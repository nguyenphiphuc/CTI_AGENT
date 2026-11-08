# CTI AGENT: TỰ ĐỘNG HÓA QUY TRÌNH TÌNH BÁO AN NINH MẠNG VÀ SINH KỸ NĂNG PHÒNG THỦ CHỦ ĐỘNG

Dự án Đồ Án Chuyên Ngành: Tự động hóa quy trình Cyber Threat Intelligence (CTI) và sinh quy tắc phòng thủ ứng dụng Machine Learning.

## THÀNH VIÊN NHÓM THỰC HIỆN

- Nguyễn Phi Phúc, mã số sinh viên 2387701131, trưởng nhóm
- Trần Minh Khang, mã số sinh viên 2387700027, thành viên
- Nguyễn Nhật Lâm, mã số sinh viên 2387700036, thành viên

---

## 1. GIỚI THIỆU TỔNG QUAN

Hệ thống tích hợp hai tác tử an ninh hoạt động độc lập trên hạ tầng cục bộ không phụ thuộc dịch vụ đám mây:

- Tác tử phân tích CTI Analyst Agent: Vận hành theo vòng lặp suy luận ReAct trên mô hình ngôn ngữ lớn Qwen 2.5 kích thước 7 tỷ tham số qua Ollama. Tác tử tự động thu thập tin tức bảo mật từ các nguồn cấp RSS, trích xuất Chỉ số thỏa hiệp (IoC), ánh xạ kỹ thuật tấn công theo ma trận MITRE ATT&CK và lập trình mã nguồn kỹ năng Python cho tác tử phòng thủ.
- Tác tử rà soát Hunter Agent: Thực thi các kỹ năng an ninh kế thừa từ lớp cơ sở BaseAgentSkill. Tác tử chủ động rà quét webshell, phát hiện backdoor thực thi lệnh từ xa RCE và kiểm toán kết nối socket mạng cục bộ.
- Module giải thích nguồn tin xAI Grounding: Thực hiện đối chiếu vị trí chuỗi ký tự và câu trích dẫn trong văn bản gốc, gán nhãn điểm tin cậy nhằm loại bỏ nguy cơ mô hình tự sinh dữ liệu giả.

---

## 2. CẤU TRÚC THƯ MỤC DỰ ÁN

```text
CTI_AGENT/
├── BAO_CAO_TIEN_DO_10_TUAN/       # 10 tệp báo cáo tiến độ tuần định dạng Word (.docx)
├── cti_framework/
│   ├── adapters/                  # Kết nối mô hình ngôn ngữ lớn qua Ollama
│   ├── core/                      # Động cơ ReAct Agent, quản lý trạng thái và xAI Grounding
│   ├── hunter/                    # Tác tử Hunter Agent thực thi kỹ năng an ninh
│   ├── sandbox/                   # Môi trường kiểm thử webshell và backdoor cục bộ
│   ├── schemas/                   # Khai báo lược đồ dữ liệu Pydantic
│   ├── skills/                    # Kho lưu trữ các kỹ năng Python thực thi (BaseAgentSkill)
│   ├── storage/                   # Quản lý cơ sở dữ liệu SQLite cục bộ
│   ├── tests/                     # Bộ kiểm thử tự động e2e cho xAI Verifier
│   ├── tools/                     # Bộ công cụ gọi hàm (Tool Calling) cho Agent
│   ├── validators/                # Kiểm tra cú pháp AST và kiểm định an toàn mã
│   ├── web/                       # Giao diện SOC Dashboard trên nền tảng FastAPI
│   └── cron_agent.py              # Tiến trình daemon chạy nền tự động hóa
├── BAO_CAO_DU_AN_ARGON.md         # Báo cáo kiến trúc chi tiết của đồ án
├── BAO_CAO_TIEN_DO_10_TUAN.md     # Bản tổng hợp tiến độ 10 tuần
├── requirements.txt               # Danh mục thư viện phụ thuộc Python
└── README.md                      # Tài liệu hướng dẫn sử dụng hệ thống
```

---

## 3. HƯỚNG DẪN CÀI ĐẶT VÀ VẬN HÀNH

### Yêu cầu môi trường

- Hệ điều hành: Windows 10/11 hoặc Ubuntu Linux
- Python: Phiên bản 3.10 trở lên
- Ollama: Đã tải mô hình ngôn ngữ cục bộ `ollama run qwen2.5:7b`

### Các bước khởi chạy

1. Cài đặt các gói thư viện Python:
```bash
pip install -r requirements.txt
```

2. Chạy bộ kiểm thử tự động xác nhận module xAI Verifier:
```bash
python -m unittest cti_framework/tests/test_xai_verifier_e2e.py
```

3. Khởi chạy tiến trình phân tích tự động chạy nền:
```bash
python cti_framework/cron_agent.py --max-steps 8
```

4. Khởi chạy giao diện điều khiển SOC Dashboard:
```bash
uvicorn cti_framework.web.app:app --host 127.0.0.1 --port 9090 --reload
```
Truy cập giao diện tại địa chỉ: `http://127.0.0.1:9090`
