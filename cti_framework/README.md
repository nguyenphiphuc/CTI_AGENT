# CTI SOC Operations Dashboard & Autonomous AI Agent Framework

> **Trung tâm Giám sát Điều hành An ninh Mạng (SOC Operations Dashboard)** tích hợp trực tiếp với **Framework AI Agent Tình báo Mối đe dọa (CTI) Tự động**. Hệ thống hoạt động 100% cục bộ (Local), sử dụng mô hình ngôn ngữ lớn `qwen2.5:7b` qua Ollama và cơ chế gọi công cụ (Tool Calling / ReAct loop) tự xây dựng không phụ thuộc vào LangChain/LangGraph/CrewAI.

---

## 1. Kiến trúc Hệ thống & Luồng Dữ liệu (Data Flow)

```
[ Nguồn CTI RSS / Báo cáo ]
          │
          ▼
┌────────────────────────────────────────────────────────┐
│             CTI Agent Engine (Core ReAct)              │
│  - OllamaAdapter (qwen2.5:7b)                          │
│  - ToolRegistry (fetch_cti, extract_iocs, mitre, ...)  │
│  - Real-time Event Telemetry Instrumentation           │
└────────────────────────────────────────────────────────┘
          │ (Events & Entities)
          ▼
┌────────────────────────────────────────────────────────┐
│             StorageManager (SQLite3 Local)             │
│  - agent_runs & agent_events (Telemetry timeline)      │
│  - cti_reports & extracted_iocs (Threat entities)      │
│  - mitre_mappings & defense_rules (Sigma & YARA)       │
└────────────────────────────────────────────────────────┘
          │ (Async SSE Stream & REST API)
          ▼
┌────────────────────────────────────────────────────────┐
│                 FastAPI Backend Service                │
│  - Port 9090 (REST Endpoints & /api/agent/events/stream)│
└────────────────────────────────────────────────────────┘
          │
          ▼
┌────────────────────────────────────────────────────────┐
│           SOC Operations Dashboard Frontend            │
│  - 8 Phân hệ SOC chuyên nghiệp (Dark Theme, Chart.js) │
│  - Server-Sent Events (SSE) Live Telemetry Timeline   │
└────────────────────────────────────────────────────────┘
```

---

## 2. Các Phân hệ trên SOC Dashboard

1. **SOC Command Center (Overview)**: 
   - 10 thẻ KPI thống kê dữ liệu thực từ CSDL: Báo cáo thu thập, IOC trích xuất, Số tác vụ chạy, Tỉ lệ thành công/lỗi, Kỹ thuật MITRE, Luật phòng thủ đã kiểm tra cú pháp và đang chờ duyệt.
   - Biểu đồ đường Timeline lịch sử chạy tác vụ Agent.
   - Biểu đồ tròn Doughnut phân bố Artifacts (IOCs vs Rules).
   - Bảng Live Operational Event Feed (luồng sự kiện thời gian thực).
   - Bảng Recent Agent Runs.

2. **Live Agent Operations Monitor**:
   - Giám sát Agent theo thời gian thực (Real-time Telemetry) thông qua **Server-Sent Events (SSE)**.
   - Ghi nhận chi tiết từng vòng đời: `run_started`, `model_request_started`, `model_response_received`, `tool_call_requested`, `tool_execution_started`, `tool_execution_completed`, `validation_completed`, `run_completed`.
   - Xem độ trễ (latency ms) của từng công cụ, input/output đã làm sạch, và báo cáo markdown hoàn chỉnh.

3. **CTI Knowledge Explorer**:
   - Quản lý các bài báo/tin tức tình báo đã cào và phân tích.
   - Modal chi tiết 6 tab: Tóm tắt (Summary), Bằng chứng (Evidence), IOCs trích xuất, Kỹ thuật MITRE, Quy tắc phòng thủ sinh ra, Lịch sử Agent Run.

4. **IOC Management & Verification**:
   - Kho lưu trữ địa chỉ IP và mã băm SHA256.
   - Phân biệt rõ trạng thái: `observed` (quan sát thấy), `candidate` (nghi vấn), `verified` (xác minh độc hại), `benign` (an toàn/trắng).
   - Cho phép SOC Analyst cập nhật trạng thái trực tiếp.
   - Xuất dữ liệu dưới dạng CSV hoặc JSON.

5. **MITRE ATT&CK Matrix Navigator**:
   - Bảng mapping các hành vi tấn công vào mã Kỹ thuật (Technique ID) kèm trích dẫn câu văn làm bằng chứng (Evidence quote).
   - Tích hợp từ điển tham chiếu MITRE Enterprise ATT&CK ngoại tuyến (Offline cache).

6. **Defensive Rules Center (Detection Engineering)**:
   - Quản lý mã luật **Sigma (YAML)** và **YARA**.
   - **Tích hợp Bộ kiểm tra Cú pháp Thật (Real Syntax Validators)**:
     - `Sigma Validator`: Kiểm tra định dạng YAML, trường bắt buộc (`title`, `logsource`, `detection`, `condition`).
     - `YARA Validator`: Kiểm tra cấu trúc rule, cân bằng dấu ngoặc, định dạng biến `$hash`, phần `condition:`.
   - **Quy trình Phê duyệt (Approval Workflow)**:
     - `Chờ phê duyệt (Awaiting Approval)` ➔ `Đã phê duyệt (Approved)` hoặc `Từ chối (Rejected)`.
     - Tải file luật trực tiếp (.yml hoặc .yar) hoặc sao chép mã nguồn.

7. **Tool Registry & Execution Center**:
   - Quản lý danh mục 6 công cụ của Agent: `fetch_cti_data`, `extract_iocs`, `map_mitre_attack`, `generate_sigma_rule`, `generate_yara_rule`, `save_cti_result`.
   - Hiển thị tổng số lần gọi, tỉ lệ thành công, độ trễ trung bình.
   - Công tắc Bật/Tắt (Enable/Disable) công cụ an toàn từ giao diện.

8. **System Health & Configuration**:
   - Giám sát trạng thái Backend (FastAPI), Database (SQLite), Local Model (Ollama `qwen2.5:7b`), và số lượng kết nối SSE đang mở.
   - Bảng cấu hình an toàn (Timeout, Temperature, SSRF Defense).

---

## 3. Hướng dẫn Khởi chạy (Local Setup)

### Bước 1: Khởi động Ollama Model Server
Đảm bảo Ollama đang chạy trên máy cục bộ với model `qwen2.5:7b`:
```bash
ollama run qwen2.5:7b
```
Kiểm tra kết nối tại: `http://localhost:11434/api/tags` (Trả về HTTP 200).

### Bước 2: Khởi chạy SOC Dashboard & Backend Server
Mở Terminal tại thư mục `d:\AGENT LOCAL\cti_framework`:
```bash
python web/app.py
```
*Server sẽ khởi động tại địa chỉ:* **`http://localhost:9090`**

### Bước 3: Truy cập Dashboard
Mở trình duyệt web bất kỳ và truy cập:
👉 **[http://localhost:9090/](http://localhost:9090/)**

---

## 4. Kịch bản Demo trước Giảng viên / Hội đồng

1. **Khởi chạy tác vụ phân tích tự động**:
   - Nhấn nút **"Run CTI Agent"** (hoặc nút **"Cào Tin RSS Mới Nhất"**).
   - Hệ thống tự động chuyển sang trang **Live Agent Monitor**.
   - Trình bày cho giảng viên thấy luồng sự kiện (SSE Timeline) cập nhật từng bước theo thời gian thực: Agent gửi yêu cầu tới mô hình Qwen, kích hoạt công cụ `fetch_cti_data`, sau đó gọi `extract_iocs`, `map_mitre_attack`, và tự động chạy validator cú pháp.
2. **Kiểm tra và Xác minh IOC**:
   - Vào mục **IOC Management**, chỉ cho giảng viên thấy các IP/Hash đã được phân tách và lưu trữ. Thao tác đổi trạng thái từ `observed` sang `verified`.
3. **Kiểm tra và Phê duyệt Luật Phòng thủ**:
   - Vào mục **Defensive Rules**, chọn một luật Sigma hoặc YARA vừa sinh.
   - Bấm **"Kiểm tra & Duyệt"**: Cho xem nội dung mã nguồn chuẩn, kết quả kiểm tra cú pháp tự động (`VALID SYNTAX`), và bấm **"Phê duyệt (Approve)"**.
4. **Kiểm tra Sức khỏe Hệ thống**:
   - Vào mục **System Health**: Xem độ trễ phản hồi của Ollama và số lượng kết nối WebSocket/SSE đang duy trì.

---

## 5. An toàn & Bảo mật (Security Constraints)

- **Phòng chống SSRF (Server-Side Request Forgery)**: Công cụ `fetch_cti_data` tự động chặn mọi yêu cầu truy vấn đến địa chỉ `localhost`, `127.0.0.1`, `0.0.0.0` và các dải IP nội bộ RFC 1918 (`10.x.x.x`, `192.168.x.x`, `172.16.x.x`).
- **An toàn Phòng vệ (Safety Policy)**: Dashboard hoàn toàn không tự động chặn mạng trên card mạng thật hoặc đẩy rule trực tiếp ra firewall của hệ thống máy chủ, tuân thủ đúng vai trò Giám sát & Hỗ trợ Phê duyệt của SOC Analyst.
- **Không sử dụng số liệu giả (No Dummy Data)**: Toàn bộ số liệu trên KPI, biểu đồ, bảng biểu và timeline đều được tính toán từ cơ sở dữ liệu SQLite và trạng thái tiến trình thực tế.

---

## 6. Cổng an toàn của Kỹ năng tự sinh (Skill Security Gate)

Toàn bộ mã Python do Agent 1 lập trình phải đi qua **3 lớp kiểm soát** trước khi được Hunter Agent thực thi:

1. **Cổng chính sách tĩnh (AST Policy Gate)** — `validators/skill_security.py`
   - Deny-by-default: chỉ import được allowlist module (os, re, hashlib, socket, ...).
   - Chặn `eval/exec/compile/__import__`, mọi API nguy hiểm của `os` (`system`, `popen`, `remove`, `chmod`, `environ` ...).
   - Chặn mở file ở chế độ ghi (`w/a/x/+`) — skill chỉ được QUÉT/ĐỌC.
   - Chặn thao tác socket chủ động (`connect/send/bind/listen`) — skill giám sát, không tấn công.
   - Chặn truy cập thuộc tính dunder (`__globals__`, `__subclasses__` ...) và `sys.modules`.
   - **Mã vi phạm bị từ chối TRƯỚC KHI ghi file xuống đĩa** (status `security_rejected`, có ghi audit trong `skill_verification_runs`).
2. **Hộp cát cô lập 5 giây** — subprocess chạy `python -I -B` (isolated mode), env tối thiểu, cwd thư mục tạm, timeout 5s.
3. **Cổng phê duyệt người + tái kiểm tra tại điểm thực thi**
   - Skill tải từ đĩa chỉ được đăng ký ở trạng thái `pending_review` (không còn tự duyệt ngầm).
   - Sinh lại mã cùng tên skill → **reset `approval_status` về `pending_review`** (chống "rửa phê duyệt").
   - Ngay cả khi đã `approved`, Hunter vẫn **tái quét AST** trước khi nạp mã; vi phạm là `BLOCKED`.

**Chỉ API cục bộ được phép**: mọi request có `Host` khác `localhost/127.0.0.1` bị 403 (chống DNS rebinding); request `POST` mang `Origin` từ trang web khác bị 403 (chống CSRF drive-by); CORS giới hạn nguồn local.

## 7. Chạy kiểm thử

```bash
cd cti_framework
py -3.13 -m unittest discover -s tests -v
```

- `tests/test_xai_verifier_e2e.py` — 12 ca xAI/gating nền tảng.
- `tests/test_security_hardening.py` — 13 ca bảo mật (AST gate, không tự duyệt, reset phê duyệt, local-only API, dọn run kẹt).

Tổng: **25 test, đều PASS**.
