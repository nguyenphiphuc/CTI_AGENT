import sys
import os

if sys.stdout.encoding != 'utf-8':
    try:
        sys.stdout.reconfigure(encoding='utf-8')
    except Exception:
        pass
if sys.stderr.encoding != 'utf-8':
    try:
        sys.stderr.reconfigure(encoding='utf-8')
    except Exception:
        pass

import time
import json
import uuid
import asyncio
import threading
from datetime import datetime
from typing import Optional, List, Dict, Any
import requests
from fastapi import FastAPI, HTTPException, Request, BackgroundTasks, Query
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, StreamingResponse, Response, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager
from urllib.parse import urlparse
from pydantic import BaseModel, Field
import logging

logger = logging.getLogger("cti.web")

# Define robust absolute paths
BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
STATIC_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), 'static'))
DB_PATH = os.path.join(BASE_DIR, 'cti_framework.db')

if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from adapters.ollama_adapter import OllamaAdapter
from core.agent import AgentEngine
from schemas.io_schemas import AgentConfig
from storage.sqlite_manager import StorageManager
from tools.cti_tools import cti_registry
from schemas.mitre_data import MITRE_ATTACK_DB
from validators import validate_defense_rule
from integrations.wazuh_client import WazuhClient

wazuh_client = WazuhClient()

active_subscribers: List[asyncio.Queue] = []
main_loop: Optional[asyncio.AbstractEventLoop] = None


# --- Chỉ cho phép truy cập từ LOCALHOST (chống DNS rebinding + CSRF drive-by) ---
LOCAL_HOSTS = {"localhost", "127.0.0.1", "::1", "[::1]", "testserver"}

def _host_is_local(host_header: str) -> bool:
    """Đối chiếu Host header với danh sách host cục bộ (bỏ port và dấu ngoặc IPv6)."""
    raw = (host_header or "").strip().lower()
    if raw.startswith("["):                      # [::1]:9090
        return raw in LOCAL_HOSTS or raw.split("]")[0] + "]" in LOCAL_HOSTS
    hostname = raw.split(":")[0]
    return hostname in LOCAL_HOSTS or raw in LOCAL_HOSTS

@asynccontextmanager
async def lifespan(app: FastAPI):
    global main_loop
    main_loop = asyncio.get_running_loop()
    # Dọn các run bị kẹt 'running' từ lần khởi động trước (không có tiến trình nào chạy nữa)
    try:
        cleaned = storage.fail_stale_runs()
        if cleaned:
            logger.warning("Đã đánh dấu %d run kẹt trạng thái 'running' thành 'failed' khi khởi động.", cleaned)
    except Exception:
        logger.exception("Không dọn được stale runs khi khởi động")
    yield

app = FastAPI(title="SOC Operations Dashboard - CTI AI Agent Framework", version="2.0.0", lifespan=lifespan)

@app.middleware("http")
async def local_only_guard(request: Request, call_next):
    # 1) Chặn DNS rebinding: mọi request phải trỏ đúng localhost/127.0.0.1
    if not _host_is_local(request.headers.get("host")):
        return JSONResponse(
            {"detail": f"Chỉ chấp nhận truy cập cục bộ (localhost/127.0.0.1), nhận được Host: '{request.headers.get('host')}'."},
            status_code=403,
        )
    # 2) Chặn CSRF drive-by: request từ trình duyệt PHẢI có Origin cùng nguồn local
    if request.method in ("POST", "PUT", "PATCH", "DELETE"):
        origin = request.headers.get("origin")
        if origin:
            origin_host = (urlparse(origin).hostname or "").lower()
            if origin_host not in LOCAL_HOSTS and not _host_is_local(origin_host):
                return JSONResponse(
                    {"detail": f"Origin không hợp lệ: '{origin}'. API này chỉ phục vụ dashboard local."},
                    status_code=403,
                )
    return await call_next(request)

# CORS giới hạn ở nguồn LOCAL thay vì "*" (không cho trang web bên ngoài gọi API)
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:9090", "http://127.0.0.1:9090",
        "http://localhost:8000", "http://127.0.0.1:8000",
    ],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Global Storage and Event Bus
storage = StorageManager(DB_PATH)

def broadcast_agent_event(event: Dict[str, Any]):
    """Thread-safe event broadcast to all SSE subscribers."""
    global active_subscribers, main_loop
    if not active_subscribers or not main_loop:
        return
    for q in list(active_subscribers):
        try:
            main_loop.call_soon_threadsafe(q.put_nowait, event)
        except Exception:
            pass

# --- Request Models ---
class AnalyzeRequest(BaseModel):
    text: str

class StartAgentRequest(BaseModel):
    task_type: str = Field("custom", description="'custom' or 'scrape_rss'")
    rss_source: Optional[str] = Field("https://feeds.feedburner.com/TheHackersNews", description="Selected RSS URL")
    custom_text: Optional[str] = Field(None, description="Custom threat intelligence report or inquiry")
    model_name: str = Field("qwen2.5:7b", description="Model name to use")
    max_steps: int = Field(8, description="Maximum agent reasoning steps")
    cti_profile: Optional[str] = Field("all", description="'web', 'network', 'endpoint', 'all'")
    artifact_focus: Optional[str] = Field("all", description="'cve', 'ipv4', 'hash', 'all'")

class UpdateIocStatusRequest(BaseModel):
    status: str = Field(..., description="observed, candidate, verified, benign, unknown")

class RuleApprovalRequest(BaseModel):
    analyst_name: Optional[str] = Field("SOC Analyst", description="Name/ID of analyst approving the rule")

class RuleRejectionRequest(BaseModel):
    reason: Optional[str] = Field("Insufficient evidence or high false positive risk", description="Rejection reason")

# --- Helper: Agent Execution Worker ---
def run_agent_in_background(run_id: str, task: str, model_name: str = "qwen2.5:7b", max_steps: int = 8,
                            cti_profile: str = "all", artifact_focus: str = "all"):
    from core.profiles import get_profile
    profile_info = get_profile(cti_profile)
    profile_guidance = profile_info.get("guidance", "")

    adapter = OllamaAdapter(model_name=model_name, base_url="http://localhost:11434")
    config = AgentConfig(
        model_name=model_name,
        max_steps=max_steps,
        temperature=0.1,
        timeout=300,
        cti_profile=cti_profile,
        artifact_focus=artifact_focus
    )
    agent = AgentEngine(adapter=adapter, registry=cti_registry, storage=storage, config=config)

    system_prompt = f"""Bạn là một chuyên gia Tình báo Mối đe dọa (CTI Agent) tự động thuộc trung tâm điều hành an ninh mạng SOC.
LĨNH VỰC MỤC TIÊU: [{profile_info.get('label', 'Universal')}].
{profile_guidance}

Quy trình thực thi TIÊU CHUẨN SOC & xAI TRUST (CHỈ XỬ LÝ 01 BÀI VIẾT DUY NHẤT):
1. NẾU cào tin RSS, hãy gọi `fetch_cti_data` với profile="{cti_profile}" và artifact_focus="{artifact_focus}".
2. TIÊU CHUẨN ĐẠO ĐỨC & xAI: TUYỆT ĐỐI KHÔNG sinh IoC giả. Chỉ trích xuất những gì CÓ THẬT trong bài.
3. Kiểm tra thông tin thu thập được:
   - Dùng `extract_iocs` để lấy các chỉ số thực tế.
   - Dùng `map_mitre_attack` kèm câu trích dẫn bằng chứng cụ thể (`evidence_quote`).
   - Dùng `generate_sigma_rule` (loại 'behavior' cho hành vi hoặc 'ipv4' cho IP).
   - [HIỆN ĐẠI]: Dùng `generate_agent_skill` để tự động lập trình một Python Skill thực thi cho Hunter Agent (ví dụ: rà soát webshell cho Web Security, hoặc kiểm toán kết nối socket cho Network Security).
4. Dùng `save_cti_result` để nạp các IoC (kèm TTL vòng đời) và Rules vào cơ sở dữ liệu vĩnh viễn.
5. Sau khi lưu xong, BẮT BUỘC DỪNG GỌI MỌI TOOL và tổng hợp bằng tiếng Việt thành Báo cáo CTI hoàn chỉnh theo chuẩn SOC để kết thúc.
"""
    try:
        agent.run(task=task, system_prompt=system_prompt, run_id=run_id, event_callback=broadcast_agent_event)
    except Exception as e:
        storage.log_event(
            run_id=run_id,
            event_type="run_failed",
            status="error",
            summary=f"Tiến trình nền gặp lỗi ngoại lệ: {str(e)}",
            error_code="UNHANDLED_EXCEPTION"
        )
        storage.finish_run(run_id, "failed", f"Lỗi hệ thống: {str(e)}")

# =====================================================================
# API ROUTES
# =====================================================================

# --- 1. SOC Overview Command Center ---
@app.get("/api/dashboard/overview")
def get_dashboard_overview():
    try:
        overview = storage.get_dashboard_overview()
        
        # Check Ollama status & latency
        t0 = time.perf_counter()
        ollama_ok = False
        ollama_latency = 0
        try:
            r = requests.get("http://localhost:11434/api/tags", timeout=3)
            ollama_ok = r.status_code == 200
            ollama_latency = int((time.perf_counter() - t0) * 1000)
        except Exception:
            ollama_ok = False

        overview["system_health"] = {
            "backend_status": "online",
            "database_status": "connected",
            "ollama_connected": ollama_ok,
            "ollama_latency_ms": ollama_latency,
            "active_model": "qwen2.5:7b",
            "active_sse_clients": len(active_subscribers)
        }
        return overview
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# --- 2. Live Agent Monitor & SSE Stream ---
@app.get("/api/agent/events/stream")
async def event_stream(request: Request):
    q = asyncio.Queue()
    active_subscribers.append(q)
    
    async def sse_generator():
        try:
            # Welcome handshake event
            init_payload = json.dumps({"type": "connected", "message": "Connected to CTI SOC Telemetry Stream", "timestamp": time.time()})
            yield f"event: connected\ndata: {init_payload}\n\n"
            while True:
                if await request.is_disconnected():
                    break
                try:
                    event = await asyncio.wait_for(q.get(), timeout=12.0)
                    yield f"event: agent_event\ndata: {json.dumps(event, ensure_ascii=False)}\n\n"
                except asyncio.TimeoutError:
                    # Heartbeat comment to keep HTTP connection alive
                    yield ": heartbeat\n\n"
        finally:
            if q in active_subscribers:
                active_subscribers.remove(q)

    return StreamingResponse(sse_generator(), media_type="text/event-stream")

@app.get("/api/agent/runs")
def list_agent_runs(status: Optional[str] = Query(None), limit: int = Query(50), offset: int = Query(0)):
    return {"runs": storage.get_agent_runs(status=status, limit=limit, offset=offset)}

@app.get("/api/agent/runs/{run_id}")
def get_agent_run_detail(run_id: str):
    detail = storage.get_agent_run_detail(run_id)
    if not detail:
        raise HTTPException(status_code=404, detail=f"Agent Run {run_id} not found")
    return detail

@app.get("/api/agent/runs/{run_id}/events")
def get_run_events(run_id: str):
    events = storage.get_events(run_id=run_id, limit=200)
    return {"run_id": run_id, "events": events}

@app.get("/api/dashboard/activity")
def get_recent_activity(limit: int = Query(50), event_type: Optional[str] = Query(None)):
    events = storage.get_events(event_type=event_type, limit=limit)
    return {"events": events}

@app.post("/api/agent/start")
def start_agent_task(req: StartAgentRequest, background_tasks: BackgroundTasks):
    run_id = str(uuid.uuid4())
    
    if req.task_type == "scrape_rss":
        rss_url = req.rss_source or "https://feeds.feedburner.com/TheHackersNews"
        task_desc = f"Hãy cào tin tức an ninh mạng mới nhất từ nguồn RSS ({rss_url}), trích xuất IoC, map MITRE ATT&CK và sinh các rule phòng vệ Sigma/YARA."
    elif req.custom_text and req.custom_text.strip():
        task_desc = req.custom_text.strip()
    else:
        raise HTTPException(status_code=400, detail="Vui lòng cung cấp nội dung văn bản phân tích hoặc chọn cào tin RSS.")

    # Run in background thread
    threading.Thread(
        target=run_agent_in_background,
        args=(run_id, task_desc, req.model_name, req.max_steps, req.cti_profile or "all", req.artifact_focus or "all"),
        daemon=True
    ).start()

    return {
        "status": "queued",
        "run_id": run_id,
        "task": task_desc,
        "model_name": req.model_name,
        "message": "Tác vụ Agent đã được kích hoạt thành công trong tiến trình nền."
    }

# Backward compatible analyze endpoint
@app.post("/api/analyze")
def analyze_cti(req: AnalyzeRequest):
    adapter = OllamaAdapter(model_name="qwen2.5:7b", base_url="http://localhost:11434")
    if not adapter.check_health():
        raise HTTPException(status_code=503, detail="Ollama is not reachable")

    config = AgentConfig(model_name="qwen2.5:7b", max_steps=8, temperature=0.1, timeout=300)
    agent = AgentEngine(adapter=adapter, registry=cti_registry, storage=storage, config=config)
    
    system_prompt = """Bạn là một chuyên gia Tình báo Mối đe dọa (CTI Agent) tự động.
Nhiệm vụ của bạn:
1. NẾU người dùng yêu cầu tự động lấy tin, hãy dùng `fetch_cti_data` để cào tin tức mới nhất trước.
2. Sử dụng công cụ `extract_iocs` để tìm IP và Hash từ văn bản do người dùng cung cấp hoặc từ tin tức vừa cào được.
3. Nếu tìm thấy hành vi đặc trưng, sử dụng `map_mitre_attack` để map với MITRE ATT&CK. Đảm bảo trích dẫn bằng chứng.
4. Dùng `generate_sigma_rule` để sinh quy tắc Sigma phòng vệ cho các IP. 
5. Dùng `generate_yara_rule` để sinh quy tắc YARA nhận diện các Hash mã độc.
6. BẮT BUỘC dùng `save_cti_result` để nạp các IoC và Rules vào cơ sở dữ liệu.
7. Cuối cùng, tổng hợp lại bằng tiếng Việt thành một báo cáo tình báo mạch lạc (gồm đầy đủ Code Sigma/YARA).
"""
    run_id = str(uuid.uuid4())
    result = agent.run(task=req.text, system_prompt=system_prompt, run_id=run_id, event_callback=broadcast_agent_event)
    return {"result": result, "run_id": run_id}

# --- 3. CTI Intelligence Explorer ---
@app.get("/api/cti/reports")
def list_cti_reports(search: Optional[str] = Query(None), limit: int = Query(50), offset: int = Query(0)):
    reports = storage.get_cti_reports(search=search, limit=limit, offset=offset)
    return {"reports": reports, "total": len(reports)}

@app.get("/api/cti/reports/{report_id}")
def get_cti_report(report_id: int):
    report = storage.get_cti_report_detail(report_id)
    if not report:
        raise HTTPException(status_code=404, detail=f"CTI Report #{report_id} not found")
    return report

# --- 4. IOC Management ---
@app.get("/api/iocs")
def list_iocs(
    ioc_type: Optional[str] = Query(None),
    status: Optional[str] = Query(None),
    search: Optional[str] = Query(None),
    is_expired: Optional[int] = Query(None, description="0 = active only, 1 = expired only"),
    limit: int = Query(50),
    offset: int = Query(0)
):
    iocs = storage.get_iocs(ioc_type=ioc_type, status=status, search=search, is_expired=is_expired, limit=limit, offset=offset)
    return {"iocs": iocs, "count": len(iocs)}

@app.post("/api/iocs/expire-cleanup")
def run_ioc_ttl_cleanup():
    expired_count = storage.check_and_expire_iocs()
    return {
        "status": "success",
        "expired_count": expired_count,
        "message": f"Đã quét và cập nhật trạng thái hết hạn cho {expired_count} chỉ số IoC quá hạn TTL."
    }

@app.patch("/api/iocs/{ioc_id}")
def update_ioc_status(ioc_id: int, req: UpdateIocStatusRequest):
    allowed_statuses = ["observed", "candidate", "verified", "benign", "unknown"]
    if req.status not in allowed_statuses:
        raise HTTPException(status_code=400, detail=f"Trạng thái không hợp lệ. Cho phép: {allowed_statuses}")
    success = storage.update_ioc_status(ioc_id, req.status)
    if not success:
        raise HTTPException(status_code=404, detail="Không tìm thấy IOC cần cập nhật")
    return {"status": "success", "message": f"Đã cập nhật trạng thái IOC #{ioc_id} thành '{req.status}'"}

@app.get("/api/iocs/export")
def export_iocs(format: str = Query("json", pattern="^(json|csv)$")):
    iocs = storage.get_iocs(limit=1000)
    if format == "json":
        return JSONResponse(content=iocs, headers={"Content-Disposition": "attachment; filename=extracted_iocs.json"})
    else:
        # CSV Export
        import csv
        import io
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(["id", "run_id", "ioc_type", "ioc_value", "status", "confidence", "context", "timestamp"])
        for ioc in iocs:
            writer.writerow([
                ioc.get("id"), ioc.get("run_id"), ioc.get("ioc_type"),
                ioc.get("ioc_value"), ioc.get("status"), ioc.get("confidence"),
                (ioc.get("context") or "").replace("\n", " "), ioc.get("timestamp")
            ])
        output.seek(0)
        return Response(content=output.getvalue(), media_type="text/csv", headers={"Content-Disposition": "attachment; filename=extracted_iocs.csv"})

@app.get("/api/database")
def get_raw_database():
    iocs = storage.get_iocs(limit=300)
    rules = storage.get_defense_rules(limit=300)
    return {"iocs": iocs, "rules": rules}

# --- 5. MITRE ATT&CK Explorer ---
@app.get("/api/mitre/mappings")
def list_mitre_mappings(tactic: Optional[str] = Query(None), search: Optional[str] = Query(None), limit: int = Query(100)):
    mappings = storage.get_mitre_mappings(tactic=tactic, search=search, limit=limit)
    return {"mappings": mappings, "count": len(mappings)}

@app.get("/api/mitre/matrix")
def get_mitre_matrix_cache():
    return {"techniques": MITRE_ATTACK_DB}

# --- 6. Defensive Rules Center ---
@app.get("/api/rules")
def list_defense_rules(
    rule_type: Optional[str] = Query(None),
    syntax_status: Optional[str] = Query(None),
    approval_status: Optional[str] = Query(None),
    search: Optional[str] = Query(None),
    limit: int = Query(50),
    offset: int = Query(0)
):
    rules = storage.get_defense_rules(
        rule_type=rule_type,
        syntax_status=syntax_status,
        approval_status=approval_status,
        search=search,
        limit=limit,
        offset=offset
    )
    return {"rules": rules, "count": len(rules)}

@app.post("/api/rules/{rule_id}/validate")
def revalidate_rule(rule_id: int):
    rule = storage.get_rule_by_id(rule_id)
    if not rule:
        raise HTTPException(status_code=404, detail="Rule không tồn tại")
    status, error_msg = validate_defense_rule(rule["rule_type"], rule["rule_content"])
    storage.update_rule_validation(rule_id, status, error_msg or "")
    return {"rule_id": rule_id, "syntax_status": status, "validation_error": error_msg}

@app.post("/api/rules/{rule_id}/approve")
def approve_rule(rule_id: int, req: RuleApprovalRequest):
    rule = storage.get_rule_by_id(rule_id)
    if not rule:
        raise HTTPException(status_code=404, detail="Rule không tồn tại")
    if rule["syntax_status"] != "valid":
        # Validate now
        status, error_msg = validate_defense_rule(rule["rule_type"], rule["rule_content"])
        storage.update_rule_validation(rule_id, status, error_msg or "")
        if status != "valid":
            raise HTTPException(status_code=400, detail=f"Không thể phê duyệt rule bị lỗi cú pháp: {error_msg}")
    storage.update_rule_approval(rule_id, "approved", approved_by=req.analyst_name or "SOC Analyst")
    return {"status": "success", "message": f"Rule #{rule_id} đã được phê duyệt bởi {req.analyst_name}"}

@app.post("/api/rules/{rule_id}/reject")
def reject_rule(rule_id: int, req: RuleRejectionRequest):
    rule = storage.get_rule_by_id(rule_id)
    if not rule:
        raise HTTPException(status_code=404, detail="Rule không tồn tại")
    storage.update_rule_approval(rule_id, "rejected", approved_by=f"Rejected: {req.reason}")
    return {"status": "success", "message": f"Rule #{rule_id} đã bị từ chối."}

@app.get("/api/rules/{rule_id}/download")
def download_rule(rule_id: int):
    rule = storage.get_rule_by_id(rule_id)
    if not rule:
        raise HTTPException(status_code=404, detail="Rule không tồn tại")
    ext = "yml" if rule["rule_type"] == "sigma" else "yar"
    clean_name = rule["rule_name"].replace(" ", "_").replace("/", "_")
    filename = f"{clean_name}.{ext}"
    return Response(
        content=rule["rule_content"],
        media_type="text/plain; charset=utf-8",
        headers={"Content-Disposition": f"attachment; filename={filename}"}
    )

# --- 7. Tool Execution Center ---
@app.get("/api/tools")
def list_registered_tools():
    all_tools = cti_registry.get_all_tools()
    metrics = storage.get_tool_metrics()
    metrics_map = {m["tool_name"]: m for m in metrics}
    
    tools_list = []
    for name, tool in all_tools.items():
        m = metrics_map.get(name, {})
        tools_list.append({
            "name": tool.name,
            "description": tool.description,
            "enabled": tool.enabled,
            "schema": tool.schema,
            "total_calls": m.get("total_calls", 0),
            "success_calls": m.get("success_calls", 0),
            "failed_calls": m.get("failed_calls", 0),
            "avg_duration_ms": round(m.get("avg_duration_ms", 0) or 0, 1),
            "last_called": m.get("last_called", None)
        })
    return {"tools": tools_list}

@app.post("/api/tools/{tool_name}/toggle")
def toggle_tool(tool_name: str):
    tool = cti_registry.get_tool(tool_name)
    if not tool:
        raise HTTPException(status_code=404, detail=f"Tool '{tool_name}' không tìm thấy trong Registry")
    new_state = not tool.enabled
    cti_registry.set_tool_enabled(tool_name, new_state)
    return {"tool_name": tool_name, "enabled": new_state, "message": f"Tool '{tool_name}' hiện {'bật' if new_state else 'tắt'}."}

# --- 8. System Health & Configuration ---
@app.get("/api/system/health")
def get_system_health():
    t0 = time.perf_counter()
    ollama_ok = False
    ollama_latency = 0
    models_available = []
    try:
        r = requests.get("http://localhost:11434/api/tags", timeout=3)
        ollama_ok = r.status_code == 200
        ollama_latency = int((time.perf_counter() - t0) * 1000)
        if ollama_ok:
            data = r.json()
            models_available = [m["name"] for m in data.get("models", [])]
    except Exception:
        ollama_ok = False

    return {
        "status": "healthy" if ollama_ok else "degraded",
        "timestamp": datetime.now().isoformat() if "datetime" in globals() else time.time(),
        "backend": {
            "framework": "FastAPI + Uvicorn",
            "python_version": sys.version.split()[0],
            "os": os.name
        },
        "database": {
            "type": "SQLite3 Local",
            "path": "cti_framework.db",
            "connected": True
        },
        "model_runtime": {
            "provider": "Ollama Local Daemon",
            "endpoint": "http://localhost:11434",
            "connected": ollama_ok,
            "latency_ms": ollama_latency,
            "active_model": "qwen2.5:7b",
            "models_installed": models_available
        },
        "tool_registry": {
            "total_tools": len(cti_registry.get_all_tools()),
            "enabled_tools": sum(1 for t in cti_registry.get_all_tools().values() if t.enabled)
        },
        "active_sse_subscribers": len(active_subscribers)
    }

# ==================== WAZUH SIEM INTEGRATION ====================

class WazuhSyncRequest(BaseModel):
    statuses: Optional[List[str]] = Field(default=["verified", "observed", "candidate"])

class WazuhTestAlertRequest(BaseModel):
    test_ip: Optional[str] = "198.51.100.1"
    custom_log: Optional[str] = None

@app.get("/api/wazuh/status")
def get_wazuh_status():
    """Lấy trạng thái kết nối và số lượng Agent của Wazuh Manager."""
    return wazuh_client.get_status()

@app.post("/api/wazuh/sync")
def sync_to_wazuh(req: Optional[WazuhSyncRequest] = None):
    """
    Đồng bộ IOCs từ CTI Database sang Wazuh CDB List có kiểm soát nghiêm ngặt bởi xAI Security Gate:
    Chỉ đồng bộ các IoC:
    1. Đã được phê duyệt thủ công (approval_status == 'approved') HOẶC
    2. Đạt chuẩn (trust_status == 'verified' VÀ maliciousness_status == 'maliciousness_confirmed'
       VÀ source_match_status IN ('exact_match', 'normalized_match'))
    Chặn toàn bộ IoC thô (observed/unverified), ví dụ/nội bộ (RFC 5737/1918), hoặc bị từ chối.
    """
    import sqlite3
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    
    total_unverified = cursor.execute("""
        SELECT COUNT(*) FROM extracted_iocs 
        WHERE (approval_status != 'approved' OR approval_status IS NULL)
          AND (trust_status != 'verified' OR maliciousness_status != 'maliciousness_confirmed')
    """).fetchone()[0]

    # Query only vetted, verified, or approved IOCs
    query = """
        SELECT ioc_type, ioc_value, confidence, status, trust_score, trust_status, approval_status, maliciousness_status
        FROM extracted_iocs 
        WHERE is_expired = 0 
          AND (
            approval_status = 'approved'
            OR (trust_status = 'verified' AND maliciousness_status = 'maliciousness_confirmed' AND source_match_status IN ('exact_match', 'normalized_match'))
          )
        ORDER BY timestamp DESC
    """
    rows = cursor.execute(query).fetchall()
    iocs = [dict(r) for r in rows]

    if not iocs:
        return {
            "status": "warning",
            "message": f"[xAI SECURITY GATE] Chặn an toàn: Không có IoC nào đủ điều kiện kiểm chứng (Verified Malicious) hoặc được Phê duyệt để đẩy sang Wazuh SIEM. Đã chặn {total_unverified} IoC thô/chưa xác minh.",
            "synced_count": 0,
            "blocked_unverified_count": total_unverified,
            "details": "Vui lòng kiểm tra và phê duyệt IoC trên Dashboard trước khi đồng bộ."
        }
    
    sync_result = wazuh_client.sync_iocs(iocs)
    sync_result["blocked_unverified_count"] = total_unverified
    sync_result["vetted_synced_count"] = len(iocs)
    if sync_result.get("status") == "success":
        reload_res = wazuh_client.reload_manager()
        sync_result["manager_reload"] = reload_res
        
    return sync_result

@app.post("/api/wazuh/test-alert")
def test_wazuh_alert(req: WazuhTestAlertRequest):
    """
    Kiểm thử trực tiếp phản hồi của Wazuh SIEM với IP hoặc mẫu log.
    Sử dụng wazuh-logtest trong container để giả lập sự kiện.
    """
    test_ip = req.test_ip or "198.51.100.1"
    log_line = req.custom_log or f"Dec 10 01:02:02 host sshd[1234]: Failed none for root from {test_ip} port 1066 ssh2"
    result = wazuh_client.test_log(log_line)
    return {
        "tested_ip": test_ip,
        "log_line": log_line,
        "result": result
    }

# =====================================================================
# PILLAR 1: CTI PROFILES API
# =====================================================================
@app.get("/api/profiles")
def list_cti_profiles():
    from core.profiles import get_all_profiles
    return get_all_profiles()

# =====================================================================
# PILLAR 2: xAI & TRUST ENGINE API
# =====================================================================
class XAIVerifyRequest(BaseModel):
    raw_text: str = Field(..., description="Văn bản báo cáo CTI gốc cần đối soát")
    candidate_iocs: Optional[List[Dict[str, Any]]] = Field(None, description="Danh sách IoC/CVE cần kiểm tra (loại và giá trị)")
    mitre_mappings: Optional[List[Dict[str, Any]]] = Field(None, description="Danh sách kỹ thuật MITRE và bằng chứng trích dẫn")

@app.post("/api/xai/verify")
def verify_with_xai(req: XAIVerifyRequest):
    """
    xAI Audit API On-Demand:
    Đối soát bất kỳ đoạn văn bản thô nào với danh sách IoCs/CVEs.
    Trả về vị trí ký tự offset [start..end], câu trích dẫn nguyên văn và Điểm Tin Cậy (Trust Score).
    """
    from core.trust_engine import XAITrustEngine
    import re
    
    iocs = req.candidate_iocs
    if iocs is None:
        ip_pattern = r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
        cve_pattern = r'\bCVE-\d{4}-\d{4,7}\b'
        ips = list(set(re.findall(ip_pattern, req.raw_text)))
        cves = list(set(re.findall(cve_pattern, req.raw_text, re.IGNORECASE)))
        iocs = [{"type": "ipv4", "value": ip} for ip in ips] + [{"type": "cve", "value": c.upper()} for c in cves]

    audit_result = XAITrustEngine.audit_cti_analysis(
        raw_text=req.raw_text,
        extracted_iocs=iocs,
        mitre_mappings=req.mitre_mappings or []
    )
    return audit_result

@app.get("/api/xai/run/{run_id}")
def get_run_xai_audit(run_id: str):
    verifications = storage.get_xai_verifications(run_id)
    return {
        "run_id": run_id,
        "total_verifications": len(verifications),
        "verifications": verifications
    }

class IOCApproveRequest(BaseModel):
    verification_id: int
    approval_status: str = Field(..., pattern="^(approved|rejected|pending_review)$")
    reviewer: Optional[str] = "SOC Analyst"
    reason: Optional[str] = ""

class SkillApproveRequest(BaseModel):
    skill_name: str
    approval_status: str = Field(..., pattern="^(approved|rejected|pending_review)$")
    reviewer: Optional[str] = "SOC Analyst"
    reason: Optional[str] = ""

@app.post("/api/xai/ioc/approve")
def approve_ioc_verification(req: IOCApproveRequest):
    """Phê duyệt hoặc từ chối một IoC sau khi chuyên gia rà soát bằng chứng xAI."""
    success = storage.update_ioc_verification_approval(
        verification_id=req.verification_id,
        approval_status=req.approval_status,
        reviewer=req.reviewer or "SOC Analyst",
        reason=req.reason or ""
    )
    return {"status": "success", "message": f"Đã cập nhật trạng thái phê duyệt IoC #{req.verification_id} thành '{req.approval_status}'."}

@app.post("/api/xai/skill/approve")
def approve_skill_verification(req: SkillApproveRequest):
    """Phê duyệt hoặc từ chối một Kỹ năng Python trước khi cho phép Hunter Agent thực thi."""
    success = storage.update_skill_approval(
        skill_name=req.skill_name,
        approval_status=req.approval_status,
        reviewer=req.reviewer or "SOC Analyst",
        reason=req.reason or ""
    )
    return {"status": "success", "message": f"Đã cập nhật trạng thái phê duyệt Skill '{req.skill_name}' thành '{req.approval_status}'."}

@app.post("/api/xai/skills/approve-all")
def approve_all_skills():
    """Phê duyệt toàn bộ các kỹ năng đang chờ duyệt để Hunter Agent sẵn sàng tác chiến."""
    skills = storage.get_all_skills()
    approved_count = 0
    for sk in skills:
        storage.update_skill_approval(
            skill_name=sk["skill_name"],
            approval_status="approved",
            reviewer="SOC Analyst",
            reason="Phê duyệt hàng loạt bởi chuyên viên SOC."
        )
        approved_count += 1
    return {"status": "success", "message": f"Đã phê duyệt thành công toàn bộ {approved_count} Kỹ năng cho Hunter Agent!"}

@app.get("/api/xai/iocs")
def list_ioc_verifications(
    report_id: Optional[int] = Query(None),
    run_id: Optional[str] = Query(None),
    trust_status: Optional[str] = Query(None),
    approval_status: Optional[str] = Query(None),
    limit: int = Query(100),
    offset: int = Query(0)
):
    """Liệt kê toàn bộ các bản ghi kiểm chứng IoC kèm trích dẫn nguyên văn và bằng chứng."""
    items = storage.get_ioc_verifications(
        report_id=report_id,
        run_id=run_id,
        trust_status=trust_status,
        approval_status=approval_status,
        limit=limit,
        offset=offset
    )
    return {"count": len(items), "verifications": items}

@app.get("/api/xai/claims")
def list_claim_verifications(
    report_id: Optional[int] = Query(None),
    run_id: Optional[str] = Query(None),
    claim_type: Optional[str] = Query(None)
):
    """Liệt kê các kiểm chứng nhận định kỹ thuật (MITRE ATT&CK, CVE, Threat Actor)."""
    items = storage.get_claim_verifications(report_id=report_id, run_id=run_id, claim_type=claim_type)
    return {"count": len(items), "claims": items}

@app.get("/api/xai/approvals")
def list_approval_audit_trail(
    entity_type: Optional[str] = Query(None),
    entity_id: Optional[int] = Query(None)
):
    """Nhật ký kiểm toán quyết định phê duyệt/từ chối của chuyên viên SOC."""
    items = storage.get_approval_records(entity_type=entity_type, entity_id=entity_id)
    return {"count": len(items), "approvals": items}

# =====================================================================
# PILLAR 3: DYNAMIC AGENT SKILLS & ACTIVE HUNTER AGENT API
# =====================================================================
class HunterExecuteRequest(BaseModel):
    skill_name: str
    target_params: Optional[Dict[str, Any]] = None

class HunterDomainHuntRequest(BaseModel):
    domain: str = Field("web", description="'web', 'network', 'endpoint'")
    target_path: Optional[str] = None

@app.get("/api/skills")
def list_agent_skills(domain: Optional[str] = None):
    return storage.get_all_skills(domain=domain)

@app.get("/api/skills/{skill_name}")
def get_agent_skill(skill_name: str):
    clean_name = skill_name.replace(".py", "")
    sk = storage.get_skill(clean_name)
    if not sk:
        raise HTTPException(status_code=404, detail="Skill not found")
    data = dict(sk)
    
    # Read skill file from disk if code in DB is empty
    skills_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "skills", "generated")
    file_path = os.path.join(skills_dir, f"{clean_name}.py")
    code = data.get("skill_code")
    if (not code or not str(code).strip()) and os.path.exists(file_path):
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                code = f.read()
        except Exception:
            pass
    data["skill_code"] = code or ""
    data["code"] = code or ""
    data["file_path"] = f"skills/generated/{clean_name}.py"
    return data

@app.post("/api/hunter/execute")
def execute_hunter_skill(req: HunterExecuteRequest):
    from core.hunter_agent import HunterAgent
    hunter = HunterAgent()
    return hunter.execute_skill(req.skill_name, req.target_params)

@app.post("/api/hunter/hunt-domain")
def run_domain_hunt(req: HunterDomainHuntRequest):
    from core.hunter_agent import HunterAgent
    hunter = HunterAgent()
    return hunter.run_automated_hunt(domain=req.domain, target_path=req.target_path)

# Mount static files using absolute path
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")

@app.get("/")
def read_index():
    return FileResponse(os.path.join(STATIC_DIR, "index.html"))

if __name__ == "__main__":
    import uvicorn
    print("\n👉 SOC Dashboard đang mở tại: http://localhost:9090 (hoặc http://127.0.0.1:9090)\n")
    uvicorn.run(app, host="127.0.0.1", port=9090)
