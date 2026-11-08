import time
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

from datetime import datetime

sys.path.append(os.path.abspath(os.path.dirname(__file__)))
from adapters.ollama_adapter import OllamaAdapter
from core.agent import AgentEngine
from schemas.io_schemas import AgentConfig
from storage.sqlite_manager import StorageManager
from tools.cti_tools import cti_registry
from core.profiles import get_profile, PROFILES

# Danh sách các nguồn tình báo an ninh mạng mặc định (Universal 360 CTI)
RSS_SOURCES = PROFILES["all"]["rss_sources"]


def run_source_analysis(source: dict, adapter: OllamaAdapter, storage: StorageManager, config: AgentConfig,
                        profile_id: str = "all", artifact_focus: str = "all") -> dict:
    source_name = source["name"]
    source_url = source["url"]
    source_cat = source.get("category", "narrative_news")
    profile_info = get_profile(profile_id)

    print(f"\n  ├─► Đang quét nguồn: [{source_name}]")
    print(f"  │   Phân loại: [{source_cat.upper()}] | Profile: [{profile_id.upper()}] | Focus: [{artifact_focus.upper()}]")

    agent = AgentEngine(adapter=adapter, registry=cti_registry, storage=storage, config=config)
    
    system_prompt = f"""Bạn là CTI Analyst Agent chuyên nghiệp phụ trách trung tâm điều hành an ninh mạng SOC.
LĨNH VỰC MỤC TIÊU: [{profile_info.get('label', 'Universal')}].
{profile_info.get('guidance', '')}

TIÊU CHUẨN ĐẠO ĐỨC & xAI TRUST: Chỉ sử dụng 100% dữ liệu kỹ thuật CÓ THẬT từ báo cáo. TUYỆT ĐỐI KHÔNG BỊA ĐẶT hay tự sinh ra địa chỉ IP/File Hash giả.
QUY TẮC PHẠM VI: Mỗi chu kỳ quét CHỈ xử lý đúng 01 bài báo duy nhất. Sau khi gọi `save_cti_result`, BẮT BUỘC DỪNG GỌI MỌI CÔNG CỤ (tuyệt đối KHÔNG gọi lại fetch_cti_data) và xuất ngay Báo cáo CTI hoàn chỉnh.

CHIẾN LƯỢC XỬ LÝ CHUYÊN BIỆT:
1. Gọi `fetch_cti_data` với source_url="{source_url}", profile="{profile_id}", artifact_focus="{artifact_focus}".
2. Nếu kết quả trả về `status` là `already_scraped`, HÃY DỪNG LẠI và thông báo: "Nguồn tin chưa có bài mới hoặc dữ liệu đã được phân tích trước đó."
3. Kiểm tra thông tin `article`:
   - Phân tích hành vi và kỹ thuật: Gọi `map_mitre_attack` với kỹ thuật tương ứng và câu trích dẫn bằng chứng cụ thể (`evidence_quote`).
   - Nếu bài báo có `external_references` và thiếu IoC, có thể gọi `fetch_external_reference` để pivot cào tìm IoC gốc.
   - [ĐẦU RA DUY NHẤT - SINH KỸ NĂNG AGENT]:
     BẮT BUỘC gọi `generate_agent_skill` để tự động lập trình một Python Skill thực thi kế thừa từ BaseAgentSkill cho Hunter Agent (rà soát Web, kiểm toán Socket mạng, hoặc quét tệp độc hại)!
4. Gọi `save_cti_result` để nạp các IoC (kèm TTL tự động) vào Database.
5. Sau khi lưu xong, KHÔNG GỌI THÊM TOOL NÀO NỮA. Hãy xuất ngay Báo cáo CTI tiêu chuẩn SOC gồm:
   - Tên mối đe dọa & Phân loại bài viết
   - Tóm tắt chiến dịch / xu hướng
   - Chỉ số thỏa hiệp (IoCs) & Điểm tin cậy (xAI Grounding)
   - Bản đồ kỹ thuật MITRE ATT&CK kèm bằng chứng
   - Kỹ năng Hunter Agent vừa tạo
   - Khuyến nghị phòng thủ SOC.
"""

    task = f"Bắt đầu kiểm tra nguồn {source_name} theo Profile [{profile_id}]. Hãy lấy dữ liệu, phân tích chuẩn xác và tự động lập trình Python Skill tương ứng cho Hunter Agent."
    result = agent.run(task=task, system_prompt=system_prompt)
    is_duplicate = "chưa có bài mới" in result or "đã được phân tích trước đó" in result
    status_label = "ĐÃ CÓ SẴN (BỎ QUA)" if is_duplicate else "PHÂN TÍCH THÀNH CÔNG"
    print(f"  └─► Kết quả [{source_name}]: {status_label}")
    return {"source": source_name, "status": status_label, "is_new": not is_duplicate, "output": result}


def run_full_sweep(sweep_number: int = 1, profile_id: str = "all", artifact_focus: str = "all", max_steps: int = 8):
    try:
        sys.stdout.reconfigure(encoding='utf-8')
    except Exception:
        pass

    start_time = datetime.now()
    profile_data = get_profile(profile_id)
    sources = profile_data["rss_sources"]

    print(f"\n{'='*75}")
    print(f"[{start_time.strftime('%Y-%m-%d %H:%M:%S')}] KHỞI ĐỘNG ĐỢT QUÉT TOÀN DIỆN CTI (BATCH SWEEP #{sweep_number})")
    print(f"👉 Chế độ Profile: [{profile_data['label'].upper()}]")
    print(f"👉 Hạt nhân Lọc (Artifact Focus): [{artifact_focus.upper()}]")
    print(f"👉 Tổng số nguồn: {len(sources)} nguồn chuyên biệt")
    print(f"{'='*75}")

    adapter = OllamaAdapter(model_name="qwen2.5:7b", base_url="http://localhost:11434")
    if not adapter.check_health():
        print("❌ Lỗi: Ollama không khả dụng. Bỏ qua đợt quét này.")
        return

    db_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "cti_framework.db")
    storage = StorageManager(db_path)
    
    # 1. Tự động cập nhật trạng thái hết hạn cho các IoC quá thời gian TTL
    expired_count = storage.check_and_expire_iocs()
    if expired_count > 0:
        print(f"🛡️ [Data Lifecycle Engine]: Đã gắn nhãn hết hạn (expired) cho {expired_count} IoC quá hạn TTL.")

    config = AgentConfig(
        model_name="qwen2.5:7b",
        max_steps=max_steps,
        temperature=0.1,
        timeout=300,
        cti_profile=profile_id,
        artifact_focus=artifact_focus
    )

    # 2. Quét tuần tự toàn bộ nguồn trong Profile
    new_articles_count = 0
    for idx, src in enumerate(sources, start=1):
        print(f"\n[Tiến trình {idx}/{len(sources)}]:")
        try:
            res = run_source_analysis(src, adapter, storage, config, profile_id=profile_id, artifact_focus=artifact_focus)
            if res.get("is_new"):
                new_articles_count += 1
        except Exception as se:
            print(f"  └─► ⚠️ Lỗi khi quét nguồn [{src['name']}]: {se}")

    duration = (datetime.now() - start_time).total_seconds()
    print(f"\n{'='*75}")
    print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] HOÀN TẤT ĐỢT QUÉT #{sweep_number} (Thời gian thực thi: {duration:.1f}s)")
    print(f"👉 Tổng kết: Đã quét {len(sources)} nguồn | Số bài mới phân tích: {new_articles_count}")
    print(f"👉 Đang vào chế độ nghỉ 10 phút (600 giây) trước khi bắt đầu đợt quét tiếp theo...")
    print(f"{'='*75}\n")


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="CTI Agent Autonomous Service with Targeted Profiles & xAI Trust Engine")
    parser.add_argument("--profile", type=str, default="all", choices=["all", "web", "network", "endpoint"], help="Chuyên biệt hóa lĩnh vực: web, network, endpoint, all")
    parser.add_argument("--focus", type=str, default="all", choices=["all", "cve", "ipv4", "hash"], help="Lọc hạt nhân theo loại chỉ số: cve, ipv4, hash, all")
    parser.add_argument("--interval", type=int, default=600, help="Thời gian nghỉ giữa các đợt quét (giây, mặc định: 600s = 10 phút)")
    parser.add_argument("--max-steps", type=int, default=8, help="Số bước suy luận tối đa của Agent (mặc định: 8)")
    args = parser.parse_args()

    sys.stdout.reconfigure(encoding='utf-8')
    sel_profile = get_profile(args.profile)
    print("============================================================================")
    print("  CTI Agent Background Service đã khởi động.")
    print(f"  👉 Profile Mục Tiêu: [{sel_profile['label']}]")
    print(f"  👉 Artifact Focus:   [{args.focus.upper()}]")
    print(f"  👉 Số nguồn quét:    {len(sel_profile['rss_sources'])} nguồn chuyên biệt.")
    print(f"  👉 Bước suy luận tối đa: {args.max_steps}")
    print(f"  👉 Chu kỳ nghỉ:      {args.interval} giây ({args.interval // 60} phút).")
    print("============================================================================")
    
    sweep_count = 1
    try:
        run_full_sweep(sweep_count, profile_id=args.profile, artifact_focus=args.focus, max_steps=args.max_steps)
    except Exception as e:
        print(f"Lỗi ở đợt quét đầu tiên: {e}")
        
    while True:
        time.sleep(args.interval)
        sweep_count += 1
        try:
            run_full_sweep(sweep_count, profile_id=args.profile, artifact_focus=args.focus, max_steps=args.max_steps)
        except Exception as e:
            print(f"Lỗi ở đợt quét #{sweep_count}: {e}")
