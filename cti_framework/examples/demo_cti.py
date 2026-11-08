import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from adapters.ollama_adapter import OllamaAdapter
from core.agent import AgentEngine
from schemas.io_schemas import AgentConfig
from storage.sqlite_manager import StorageManager
from tools.cti_tools import cti_registry

def run_cti_analysis():
    sys.stdout.reconfigure(encoding='utf-8')
    adapter = OllamaAdapter(model_name="qwen2.5:7b", base_url="http://localhost:11434")
    
    if not adapter.check_health():
        print("Lỗi: Ollama không khả dụng.")
        sys.exit(1)
        
    storage = StorageManager("cti_framework.db")
    config = AgentConfig(model_name="qwen2.5:7b", max_steps=8, temperature=0.1, timeout=300)
    
    agent = AgentEngine(adapter=adapter, registry=cti_registry, storage=storage, config=config)
    
    system_prompt = """Bạn là một chuyên gia Tình báo Mối đe dọa (CTI Agent) tự động.
Nhiệm vụ của bạn:
1. Sử dụng công cụ `extract_iocs` để tìm IP và Hash từ văn bản do người dùng cung cấp.
2. Nếu tìm thấy hành vi đặc trưng (như tải file, thực thi lệnh), sử dụng `map_mitre_attack` để map với MITRE ATT&CK. Đảm bảo trích dẫn bằng chứng rõ ràng.
3. Dùng `generate_sigma_rule` để sinh quy tắc phòng vệ cho các IP độc hại tìm được. Nhớ đặt has_evidence=true nếu chắc chắn.
4. Cuối cùng, tổng hợp lại bằng tiếng Việt thành một báo cáo tình báo mạch lạc, bao gồm IoC, kỹ thuật MITRE, và Rule Sigma (nếu có).

Quy tắc tối thượng: Không bịa đặt IoC. Không gán MITRE nếu không có bằng chứng. Nếu không đủ dữ liệu, hãy trả lời rõ là không đủ dữ liệu."""

    cti_report_text = """
    Vào ngày 10/10, hệ thống phát hiện một chiến dịch tấn công nhắm vào máy chủ web.
    Kẻ tấn công đã sử dụng địa chỉ IP 198.51.100.45 để gửi payload lên server thông qua lỗ hổng tải tệp tin. 
    Sau khi xâm nhập thành công, chúng tải xuống một công cụ từ 203.0.113.99 để thiết lập kết nối C2.
    Phần mềm độc hại bị bỏ lại trên máy tính có mã băm SHA256 là 3f9547ea8bf9de6c68dc0420790100742f5bfbc8ea15a993740e58d929b20b22.
    """
    
    print(f"Task Input:\n{cti_report_text}")
    print("="*60)
    print("Agent đang phân tích (có thể mất 1-2 phút tùy tốc độ máy)...")
    result = agent.run(task=cti_report_text, system_prompt=system_prompt)
    print("="*60)
    print("BÁO CÁO CTI CUỐI CÙNG:")
    print(result)

if __name__ == "__main__":
    run_cti_analysis()
