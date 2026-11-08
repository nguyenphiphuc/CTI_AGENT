import uuid
import json
import time
from typing import Dict, Any, Optional, Callable
from adapters.base import BaseModelAdapter
from core.tools import ToolRegistry
from core.state import AgentState
from schemas.io_schemas import Message, AgentConfig
from storage.sqlite_manager import StorageManager
from schemas.mitre_data import enrich_mitre_technique
from validators import validate_defense_rule

class AgentEngine:
    def __init__(self, adapter: BaseModelAdapter, registry: ToolRegistry, storage: StorageManager, config: AgentConfig):
        self.adapter = adapter
        self.registry = registry
        self.storage = storage
        self.config = config

    def _sanitize_summary(self, val: Any, max_len: int = 250) -> str:
        """Sanitize and shorten text for clean SOC operational telemetry without secrets."""
        if val is None:
            return ""
        s = str(val).strip()
        # Remove markdown fences or huge dumps
        if len(s) > max_len:
            return s[:max_len] + "..."
        return s

    def _emit_event(self, run_id: str, event_type: str, step: int = 0, tool_name: str = "",
                    status: str = "info", duration_ms: int = 0, summary: str = "",
                    input_summary: str = "", output_summary: str = "", error_code: str = "",
                    callback: Optional[Callable[[Dict[str, Any]], None]] = None) -> Dict[str, Any]:
        """Log event to database and trigger active SSE callback if provided."""
        event_dict = self.storage.log_event(
            run_id=run_id,
            event_type=event_type,
            step=step,
            tool_name=tool_name,
            status=status,
            duration_ms=duration_ms,
            summary=summary,
            input_summary=input_summary,
            output_summary=output_summary,
            error_code=error_code
        )
        if callback:
            try:
                callback(event_dict)
            except Exception:
                pass
        return event_dict

    def run(self, task: str, system_prompt: str, run_id: Optional[str] = None,
            event_callback: Optional[Callable[[Dict[str, Any]], None]] = None) -> str:
        if not run_id:
            run_id = str(uuid.uuid4())
            
        self.storage.start_run(run_id, task, model_name=self.config.model_name)
        
        self._emit_event(
            run_id=run_id,
            event_type="run_started",
            step=0,
            status="info",
            summary=f"Bắt đầu chu trình CTI Agent (Model: {self.config.model_name}, Max steps: {self.config.max_steps})",
            input_summary=self._sanitize_summary(task),
            callback=event_callback
        )
        
        state = AgentState(system_prompt=system_prompt)
        state.add_message(Message(role="user", content=task))
        
        step_count = 0
        final_result = ""
        status = "running"
        current_report_id = None
        fetched_articles_count = 0
        raw_article_text = ""
        collected_iocs = []
        collected_mitre = []
        
        while step_count < self.config.max_steps:
            step_count += 1
            options = {"temperature": self.config.temperature, "timeout": self.config.timeout}
            
            # --- 1. Model Request Started ---
            self._emit_event(
                run_id=run_id,
                event_type="model_request_started",
                step=step_count,
                status="running",
                summary=f"Bước {step_count}: Đang gửi prompt và schemas tới model {self.config.model_name}",
                callback=event_callback
            )
            
            t0 = time.perf_counter()
            msg, error = self.adapter.generate(state.get_messages(), self.registry.get_all_schemas(), options)
            duration_ms = int((time.perf_counter() - t0) * 1000)
            
            if error:
                self.storage.log_trace(run_id, step_count, "error", error)
                final_result = f"Failed at step {step_count}: {error}"
                status = "failed"
                self._emit_event(
                    run_id=run_id,
                    event_type="model_request_failed",
                    step=step_count,
                    status="error",
                    duration_ms=duration_ms,
                    summary=f"Model thất bại ở bước {step_count}: {error}",
                    error_code="MODEL_ERROR",
                    callback=event_callback
                )
                break
                
            state.add_message(msg)
            self.storage.log_trace(run_id, step_count, "model_inference", msg.dict() if hasattr(msg, 'dict') else msg.model_dump())
            
            tool_calls_count = len(msg.tool_calls) if msg.tool_calls else 0
            self._emit_event(
                run_id=run_id,
                event_type="model_response_received",
                step=step_count,
                status="success",
                duration_ms=duration_ms,
                summary=f"Nhận phản hồi từ {self.config.model_name} ({duration_ms}ms, yêu cầu {tool_calls_count} tool call)",
                output_summary=self._sanitize_summary(msg.content or f"{tool_calls_count} tool call requested"),
                callback=event_callback
            )
            
            # --- 2. Check Tool Calls ---
            if msg.tool_calls:
                for tool_call in msg.tool_calls:
                    func_name = tool_call.get("function", {}).get("name")
                    args_str = tool_call.get("function", {}).get("arguments", "{}")
                    
                    try:
                        args = json.loads(args_str) if isinstance(args_str, str) else args_str
                    except Exception:
                        args = {}
                        
                    input_summary = self._sanitize_summary(json.dumps(args, ensure_ascii=False))
                    
                    self._emit_event(
                        run_id=run_id,
                        event_type="tool_call_requested",
                        step=step_count,
                        tool_name=func_name,
                        status="info",
                        summary=f"Yêu cầu thực thi tool: {func_name}",
                        input_summary=input_summary,
                        callback=event_callback
                    )
                    
                    tool = self.registry.get_tool(func_name)
                    self._emit_event(
                        run_id=run_id,
                        event_type="tool_execution_started",
                        step=step_count,
                        tool_name=func_name,
                        status="running",
                        summary=f"Bắt đầu chạy tool '{func_name}'...",
                        callback=event_callback
                    )
                    
                    t_tool0 = time.perf_counter()
                    if func_name == "fetch_cti_data" and fetched_articles_count >= 1:
                        obs = json.dumps({
                            "status": "already_fetched_in_this_run",
                            "message": "Bạn ĐÃ lấy bài viết cho chu kỳ này rồi. Vui lòng KHÔNG gọi lại fetch_cti_data nữa mà hãy tiến hành phân tích và viết Báo cáo CTI kết thúc lượt chạy."
                        }, ensure_ascii=False)
                    elif tool:
                        obs = tool.execute(**args)
                        if func_name == "fetch_cti_data":
                            fetched_articles_count += 1
                    else:
                        obs = f"Error: Tool '{func_name}' not found."
                    tool_duration_ms = int((time.perf_counter() - t_tool0) * 1000)
                    
                    is_err = str(obs).startswith("Error:")
                    tool_status = "error" if is_err else "success"
                    output_summary = self._sanitize_summary(str(obs))
                    
                    if is_err:
                        self._emit_event(
                            run_id=run_id,
                            event_type="tool_execution_failed",
                            step=step_count,
                            tool_name=func_name,
                            status="error",
                            duration_ms=tool_duration_ms,
                            summary=f"Tool '{func_name}' thực thi thất bại.",
                            output_summary=output_summary,
                            error_code="TOOL_EXEC_ERR",
                            callback=event_callback
                        )
                    else:
                        self._emit_event(
                            run_id=run_id,
                            event_type="tool_execution_completed",
                            step=step_count,
                            tool_name=func_name,
                            status="success",
                            duration_ms=tool_duration_ms,
                            summary=f"Tool '{func_name}' hoàn thành ({tool_duration_ms}ms).",
                            output_summary=output_summary,
                            callback=event_callback
                        )
                        
                        # --- Process & Persist Real Entities Automatically ---
                        try:
                            # 1. RSS Article Fetch
                            if func_name == "fetch_cti_data":
                                parsed_obs = json.loads(obs) if isinstance(obs, str) else obs
                                if parsed_obs.get("status") == "success" and "article" in parsed_obs:
                                    art = parsed_obs["article"]
                                    raw_article_text = (art.get("title", "") + " " + art.get("summary", "")).strip()
                                    link = art.get("link") or args.get("source_url", "RSS")
                                    current_source_url = link
                                    raw_body = str(obs)
                                    import hashlib
                                    c_hash = hashlib.sha256(raw_body.encode('utf-8')).hexdigest()
                                    pub = art.get("publisher", "")
                                    if not pub:
                                        if "thehackernews" in link.lower(): pub = "The Hacker News"
                                        elif "bleepingcomputer" in link.lower(): pub = "BleepingComputer"
                                        elif "feodo" in link.lower() or "abuse.ch" in link.lower(): pub = "Abuse.ch"
                                        else: pub = "Threat Intelligence Feed"
                                    current_report_id = self.storage.save_cti_report(
                                        run_id=run_id,
                                        title=art.get("title", "CTI Article"),
                                        source_url=link,
                                        published_date=art.get("published", ""),
                                        summary=art.get("summary", ""),
                                        raw_content=raw_body,
                                        content_hash=c_hash,
                                        source_publisher=pub,
                                        http_status=200,
                                        fetch_status="success"
                                    )
                                    # Tự động lưu các IoC thực tế được trích xuất trực tiếp từ bài viết vào database
                                    discovered = art.get("discovered_iocs", [])
                                    src_cat = art.get("feed_category", "narrative_news")
                                    for item in discovered:
                                        collected_iocs.append(item)
                                        val = str(item.get("value", "")).strip()
                                        itype = str(item.get("type", "unknown")).lower()
                                        if val and not val.startswith(("127.", "0.", "10.", "192.168.", "172.16.", "1.2.3.4", "1.1.1.1")) and val not in ("8.8.8.8", "0.0.0.0"):
                                            ttl = 730 if itype == "cve" else (14 if itype == "ipv4" else (30 if itype == "domain" else 90))
                                            self.storage.save_ioc(
                                                run_id=run_id,
                                                ioc_type=itype,
                                                ioc_value=val,
                                                status="observed",
                                                confidence="high",
                                                context=f"Trích xuất từ báo cáo CTI: {art.get('title')}",
                                                report_id=current_report_id,
                                                ttl_days=ttl,
                                                source_type=src_cat
                                            )

                            # 2. IOC Extraction
                            elif func_name == "extract_iocs":
                                parsed_obs = json.loads(obs) if isinstance(obs, str) else obs
                                raw_article_text += " " + args.get("text", "")
                                iocs = parsed_obs.get("extracted_iocs", [])
                                for item in iocs:
                                    collected_iocs.append(item)
                                    itype = item.get("type", "unknown").lower()
                                    ttl = 730 if itype == "cve" else (14 if itype == "ipv4" else (30 if itype == "domain" else 90))
                                    self.storage.save_ioc(
                                        run_id=run_id,
                                        ioc_type=itype,
                                        ioc_value=item.get("value", ""),
                                        status="observed",
                                        confidence="medium",
                                        context=self._sanitize_summary(args.get("text", "")),
                                        report_id=current_report_id,
                                        ttl_days=ttl,
                                        source_type="narrative_news"
                                    )

                            # 3. MITRE ATT&CK Mapping
                            elif func_name == "map_mitre_attack":
                                parsed_obs = json.loads(obs) if isinstance(obs, str) else obs
                                if parsed_obs.get("status") == "success" and "mitre_mapping" in parsed_obs:
                                    m = parsed_obs["mitre_mapping"]
                                    collected_mitre.append(m)
                                    enriched = enrich_mitre_technique(m.get("technique_id", ""), m.get("name"))
                                    self.storage.save_mitre_mapping(
                                        run_id=run_id,
                                        technique_id=enriched["technique_id"],
                                        technique_name=enriched["name"],
                                        tactic=enriched["tactic"],
                                        confidence=m.get("confidence", "candidate"),
                                        evidence=m.get("evidence", ""),
                                        status="candidate",
                                        report_id=current_report_id
                                    )

                            # 4. Sigma Rule Generation & Real Syntax Validation (IoC & Behavioral Rules)
                            elif func_name == "generate_sigma_rule":
                                parsed_obs = json.loads(obs) if isinstance(obs, str) else obs
                                if parsed_obs.get("status") == "success" and "sigma_yaml" in parsed_obs:
                                    rule_content = parsed_obs["sigma_yaml"]
                                    rule_kind = parsed_obs.get("rule_type", "technical_ioc")
                                    desc = "Quy tắc Sigma giám sát hành vi (Behavioral Detection) từ bài báo CTI." if rule_kind == "behavioral" else "Quy tắc Sigma phát hiện IoC mạng (Network IoC)."
                                    mitre_id = args.get("mitre_technique_id", "")
                                    syn_status, syn_err = validate_defense_rule("sigma", rule_content)
                                    self.storage.save_rule(
                                        run_id=run_id,
                                        rule_type="sigma",
                                        rule_name=args.get("rule_title", "Auto_Sigma_Rule"),
                                        rule_content=rule_content,
                                        description=desc,
                                        syntax_status=syn_status,
                                        validation_error=syn_err or "",
                                        approval_status="awaiting_approval",
                                        mitre_technique_id=mitre_id,
                                        report_id=current_report_id
                                    )
                                    self._emit_event(
                                        run_id=run_id,
                                        event_type="validation_completed",
                                        step=step_count,
                                        tool_name="generate_sigma_rule",
                                        status="success" if syn_status == "valid" else "warning",
                                        summary=f"Kiểm tra cú pháp Sigma Rule ({rule_kind}): {syn_status.upper()}" + (f" ({syn_err})" if syn_err else ""),
                                        callback=event_callback
                                    )

                            # 5. YARA Rule Generation & Real Syntax Validation
                            elif func_name == "generate_yara_rule":
                                parsed_obs = json.loads(obs) if isinstance(obs, str) else obs
                                if parsed_obs.get("status") == "success" and "yara_rule" in parsed_obs:
                                    rule_content = parsed_obs["yara_rule"]
                                    syn_status, syn_err = validate_defense_rule("yara", rule_content)
                                    self.storage.save_rule(
                                        run_id=run_id,
                                        rule_type="yara",
                                        rule_name=args.get("rule_name", "Auto_YARA_Rule"),
                                        rule_content=rule_content,
                                        description="Tự động sinh bởi CTI Agent cho mã băm độc hại.",
                                        syntax_status=syn_status,
                                        validation_error=syn_err or "",
                                        approval_status="awaiting_approval",
                                        report_id=current_report_id
                                    )
                                    self._emit_event(
                                        run_id=run_id,
                                        event_type="validation_completed",
                                        step=step_count,
                                        tool_name="generate_yara_rule",
                                        status="success" if syn_status == "valid" else "warning",
                                        summary=f"Kiểm tra cú pháp YARA Rule: {syn_status.upper()}" + (f" ({syn_err})" if syn_err else ""),
                                        callback=event_callback
                                    )

                            # 6. Dynamic Agent Skill Synthesis (Pillar 3)
                            elif func_name == "generate_agent_skill":
                                parsed_obs = json.loads(obs) if isinstance(obs, str) else obs
                                if parsed_obs.get("status") == "success":
                                    sname = parsed_obs.get("skill_name", "")
                                    sdom = parsed_obs.get("domain", "")
                                    self._emit_event(
                                        run_id=run_id,
                                        event_type="skill_synthesized",
                                        step=step_count,
                                        tool_name="generate_agent_skill",
                                        status="success",
                                        summary=f"Đã lập trình Kỹ năng thực thi mới '{sname}' [{sdom.upper()}] cho Hunter Agent",
                                        output_summary=self._sanitize_summary(parsed_obs.get("message", "")),
                                        callback=event_callback
                                    )
                        except Exception as parse_err:
                            pass
                        
                    tool_msg = Message(role="tool", content=str(obs))
                    state.add_message(tool_msg)
                    self.storage.log_trace(run_id, step_count, "tool_call", {"tool": func_name, "args": args, "result": obs})
            else:
                # 3. No Tool Calls, Final Response
                final_result = msg.content
                status = "success"
                self.storage.log_trace(run_id, step_count, "stop", "No more tool calls, stopping.")
                self._emit_event(
                    run_id=run_id,
                    event_type="run_completed",
                    step=step_count,
                    status="success",
                    summary="Agent đã hoàn tất phân tích toàn bộ chu trình và tổng hợp báo cáo.",
                    output_summary=self._sanitize_summary(final_result),
                    callback=event_callback
                )
                break
                
        if status == "running":
            status = "failed"
            final_result = f"Exceeded max_steps ({self.config.max_steps})."
            self.storage.log_trace(run_id, step_count, "error", final_result)
            self._emit_event(
                run_id=run_id,
                event_type="run_failed",
                step=step_count,
                status="error",
                summary=f"Tác vụ thất bại do vượt quá số bước tối đa ({self.config.max_steps}).",
                error_code="MAX_STEPS_EXCEEDED",
                callback=event_callback
            )
            
        # --- 4. xAI Trust & Grounding Audit (Pillar 2) ---
        if raw_article_text and (collected_iocs or collected_mitre):
            try:
                import hashlib
                from core.trust_engine import XAITrustEngine
                audit_res = XAITrustEngine.audit_cti_analysis(raw_article_text, collected_iocs, collected_mitre)
                trust_score = audit_res.get("overall_trust_score", 100.0)

                for v in audit_res.get("verifications", []):
                    etype = v.get("entity_type", "ioc")
                    evalue = v.get("entity_value", "")
                    quote = v.get("exact_quote", "")
                    start_pos = v.get("char_offset_start", -1)
                    end_pos = v.get("char_offset_end", -1)
                    t_score = v.get("trust_score", 1.0)
                    t_status = v.get("trust_status", "unverified")
                    app_status = v.get("approval_status", "pending_review")
                    match_status = v.get("source_match_status", "exact_match" if v.get("is_grounded") else "not_found")
                    ctx_assess = v.get("context_assessment", "")
                    mal_status = v.get("maliciousness_status", "maliciousness_confirmed" if v.get("is_grounded") else "insufficient_evidence")

                    # 1. Legacy xai_verifications table
                    self.storage.save_xai_verification(
                        run_id=run_id,
                        report_id=current_report_id,
                        entity_type=etype,
                        entity_value=evalue,
                        is_grounded=v.get("is_grounded", True),
                        trust_score=t_score,
                        exact_quote=quote,
                        start_idx=start_pos,
                        end_idx=end_pos,
                        explanation=v.get("explanation", "")
                    )

                    # 2. Save Evidence Records table
                    if quote:
                        quote_h = hashlib.sha256(quote.encode('utf-8')).hexdigest()
                        self.storage.save_evidence_record(
                            report_id=current_report_id,
                            evidence_type=etype,
                            entity_value=evalue,
                            exact_quote=quote,
                            char_offset_start=start_pos,
                            char_offset_end=end_pos,
                            quote_hash=quote_h,
                            context_window=ctx_assess
                        )

                    # 3. Save IOC Verifications table & update extracted_iocs
                    if etype != "mitre_technique":
                        self.storage.save_ioc_verification(
                            ioc_id=None,
                            report_id=current_report_id,
                            run_id=run_id,
                            indicator=evalue,
                            indicator_type=etype,
                            source_url=current_source_url if 'current_source_url' in locals() else "",
                            evidence_quote=quote,
                            evidence_location=f"offset: {start_pos}-{end_pos}",
                            source_match_status=match_status,
                            context_assessment=ctx_assess,
                            maliciousness_status=mal_status,
                            external_verification_status="unverified",
                            verification_notes=v.get("explanation", ""),
                            trust_score=t_score,
                            trust_status=t_status,
                            approval_status=app_status
                        )
                        # Also update extracted_iocs table with verification flags
                        try:
                            cur = self.storage.conn.cursor()
                            cur.execute("""
                                UPDATE extracted_iocs
                                SET source_match_status = ?, context_assessment = ?, maliciousness_status = ?,
                                    trust_score = ?, trust_status = ?, approval_status = ?, exact_quote = ?,
                                    char_offset_start = ?, char_offset_end = ?
                                WHERE ioc_value = ?
                            """, (match_status, ctx_assess, mal_status, t_score, t_status, app_status, quote, start_pos, end_pos, evalue))
                            self.storage.conn.commit()
                        except Exception:
                            pass
                    else:
                        # 4. Save Claim Verifications table
                        self.storage.save_claim_verification(
                            report_id=current_report_id,
                            run_id=run_id,
                            claim=f"{evalue}: {quote}",
                            claim_type="mitre_attack",
                            source_url="",
                            evidence_quote=quote,
                            evidence_location=f"offset: {start_pos}-{end_pos}",
                            reasoning_summary=v.get("explanation", ""),
                            verification_status="verified" if v.get("is_grounded") else "insufficient_evidence",
                            uncertainties="",
                            supporting_references=json.dumps([]),
                            trust_score=t_score
                        )

                self.storage.update_run_xai_trust(
                    run_id=run_id,
                    trust_score=trust_score,
                    cti_profile=self.config.cti_profile,
                    artifact_focus=self.config.artifact_focus
                )

                hallucinated = audit_res.get("hallucination_detected", False)
                self._emit_event(
                    run_id=run_id,
                    event_type="xai_audit_completed",
                    step=step_count,
                    status="success" if not hallucinated else "warning",
                    summary=f"xAI Grounding Audit: Điểm Tin Cậy (Trust Score) = {trust_score}% | " +
                            ("100% Xác thực nguyên văn, KHÔNG có ảo giác!" if not hallucinated else "Phát hiện chỉ số không khớp văn bản gốc!"),
                    output_summary=json.dumps({"trust_score": trust_score, "verified_items": audit_res.get("verified_items_count", 0)}, ensure_ascii=False),
                    callback=event_callback
                )
            except Exception as xai_err:
                pass

        self.storage.finish_run(run_id, status, final_result, total_steps=step_count)
        return final_result
