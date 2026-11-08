# BÁO CÁO TIẾN ĐỘ 10 TUẦN ĐỒ ÁN CHUYÊN NGÀNH

## THÔNG TIN CHUNG

- Đề tài: Tự động hóa quy trình CTI và sinh quy tắc phòng thủ ứng dụng Machine Learning
- Giảng viên hướng dẫn: Bộ môn An toàn Thông tin
- Nhóm sinh viên thực hiện:
  - Nguyễn Phi Phúc, mã số sinh viên 2387701131, trưởng nhóm
  - Trần Minh Khang, mã số sinh viên 2387700027, thành viên
  - Nguyễn Nhật Lâm, mã số sinh viên 2387700036, thành viên
- Giai đoạn báo cáo: Tuần 3, hoàn thành các nội dung từ Tuần 1 đến Tuần 3 và xây dựng kế hoạch chi tiết từ Tuần 4 đến Tuần 10.

---

## NỘI DUNG BÁO CÁO CHI TIẾT THEO TỪNG TUẦN

### Tuần 1: Khảo sát tài liệu, xác định yêu cầu bài toán và thiết lập kiến trúc tổng thể

- Mục tiêu: Nghiên cứu các tiêu chuẩn Cyber Threat Intelligence (CTI), xác định phạm vi đề tài và thiết lập môi trường kỹ thuật.
- Phân công nhiệm vụ:
  - Nguyễn Phi Phúc: Khảo sát các khung tác tử ReAct và mô hình ngôn ngữ mã nguồn mở. Lựa chọn mô hình Qwen 2.5 kích thước 7 tỷ tham số chạy cục bộ qua Ollama để đảm bảo tính riêng tư cho dữ liệu tình báo mạng.
  - Trần Minh Khang: Thu thập và tổng hợp tài liệu về dữ liệu tình báo mạng, cấu trúc dữ liệu STIX 2.1 và ma trận kỹ thuật tấn công MITRE ATT&CK. Phân tích các nguồn cấp dữ liệu tình báo từ The Hacker News, BleepingComputer và Microsoft Security Blog.
  - Nguyễn Nhật Lâm: Khởi tạo kho lưu trữ mã nguồn Git, thiết lập cấu trúc thư mục dự án theo mô hình module hóa. Cấu hình môi trường Python 3.10 và kiểm tra kết nối dịch vụ cơ sở dữ liệu SQLite ở chế độ ghi trước WAL.
- Kết quả đạt được: Hoàn thành tài liệu đặc tả yêu cầu kỹ thuật và sơ đồ kiến trúc phân tầng của hệ thống.

---

### Tuần 2: Xây dựng module thu thập tin tình báo tự động và thiết kế cơ sở dữ liệu

- Mục tiêu: Hiện thực hóa quy trình cào dữ liệu từ các nguồn RSS và xây dựng lược đồ cơ sở dữ liệu quan hệ.
- Phân công nhiệm vụ:
  - Nguyễn Phi Phúc: Thiết kế bộ điều phối tác vụ nền, xây dựng cơ chế quản lý trạng thái phiên làm việc và chuẩn hóa lược đồ dữ liệu đầu vào đầu ra của các tác tử.
  - Trần Minh Khang: Viết mã nguồn module cào tin tự động từ các nguồn cấp dữ liệu bảo mật, bóc tách nội dung HTML thô và lọc trùng bài viết dựa trên mã băm SHA256.
  - Nguyễn Nhật Lâm: Hiện thực hóa module lưu trữ dữ liệu với SQLite, thiết kế các bảng lưu trữ báo cáo tình báo, bảng chỉ số xâm phạm, bảng kỹ thuật tấn công và bảng lưu vết sự kiện thực thi của hệ thống.
- Kết quả đạt được: Module thu thập hoạt động ổn định, nạp thành công 25 bài báo thử nghiệm vào cơ sở dữ liệu, thời gian phân tích trung bình mỗi bài dưới 3 giây.

---

### Tuần 3: Hiện thực hóa Agent phân tích CTI và module kiểm định nguồn tin xAI

- Mục tiêu: Tích hợp mô hình ngôn ngữ lớn để tự động phân tích bài viết, ánh xạ kỹ thuật tấn công và kiểm tra nguồn gốc dữ liệu.
- Phân công nhiệm vụ:
  - Nguyễn Phi Phúc: Hiện thực hóa động cơ suy luận ReAct cho CTI Analyst Agent. Xây dựng cơ chế gọi công cụ động, xử lý vòng lặp suy luận và nâng ngưỡng số bước suy luận tối đa lên 8 bước để phục vụ các bài báo kỹ thuật phức tạp.
  - Trần Minh Khang: Xây dựng công cụ trích xuất Chỉ số thỏa hiệp (IoC) gồm địa chỉ IP, tên miền, mã CVE và mã băm tệp tin. Hiện thực hóa công cụ ánh xạ kỹ thuật MITRE ATT&CK kèm trích dẫn câu văn làm bằng chứng.
  - Nguyễn Nhật Lâm: Xây dựng công cụ kiểm định độ tin cậy xAI Grounding. Module thực hiện đối chiếu vị trí chuỗi ký tự của các chỉ số kỹ thuật và kỹ thuật tấn công với văn bản gốc, gán điểm tin cậy nhằm loại bỏ triệt để hiện tượng mô hình tự sinh dữ liệu giả.
- Kết quả đạt được: Hoàn thành chu trình phân tích tự động từ bài báo thô đến dữ liệu có cấu trúc. Bộ kiểm thử kiểm định xAI đạt kết quả 12 trên 12 ca kiểm thử thành công, độ tin cậy trích xuất dữ liệu thực tế đạt trên 95%.

---

### Tuần 4: Nghiên cứu và hiện thực hóa cơ chế sinh kỹ năng phòng thủ tự động cho Hunter Agent

- Mục tiêu: Chuyển đổi kết quả phân tích CTI thành mã nguồn Python thực thi được thay cho các quy tắc phát hiện truyền thống.
- Kế hoạch công việc:
  - Nguyễn Phi Phúc: Thiết kế lớp kỹ năng cơ sở BaseAgentSkill và chuẩn hóa giao diện lập trình hướng đối tượng cho các kỹ năng rà soát an ninh.
  - Trần Minh Khang: Xây dựng công cụ sinh mã nguồn Python tự động từ thông tin kỹ thuật đã phân tích, tập trung vào các hành vi mạng và dấu hiệu webshell.
  - Nguyễn Nhật Lâm: Xây dựng cơ chế kiểm tra an toàn mã nguồn trước khi chạy bằng phân tích cú pháp AST, loại bỏ các lệnh nguy hiểm và kiểm thử thử nghiệm mã trong sandbox thời gian thực.
- Chỉ tiêu dự kiến: Hệ thống tự động sinh mã kỹ năng kiểm tra webshell và socket mạng hợp lệ, vượt qua 100% khâu kiểm tra cú pháp AST.

---

### Tuần 5: Xây dựng tác tử rà soát an ninh Hunter Agent và môi trường Sandbox thử nghiệm

- Mục tiêu: Hiện thực hóa tác tử phòng thủ chủ động có khả năng thực thi các kỹ năng Python đã sinh ra.
- Kế hoạch công việc:
  - Nguyễn Phi Phúc: Hiện thực hóa động cơ thực thi của Hunter Agent, xây dựng cơ chế điều phối và nạp động các tệp kỹ năng từ kho lưu trữ.
  - Trần Minh Khang: Chuẩn bị môi trường thử nghiệm chứa các mẫu mã độc thực tế gồm webshell mã hóa Base64 và tệp tin mở cổng hậu thực thi lệnh từ xa.
  - Nguyễn Nhật Lâm: Hiện thực hóa các module quét tệp tin trên hệ thống và module kiểm tra kết nối mạng đang hoạt động trên thiết bị mục tiêu.
- Chỉ tiêu dự kiến: Hunter Agent phát hiện chính xác 2 mẫu backdoor thử nghiệm trong môi trường sandbox với thời gian rà soát dưới 500 mili giây.

---

### Tuần 6: Phát triển giao diện điều khiển trung tâm SOC Dashboard

- Mục tiêu: Xây dựng giao diện web trực quan phục vụ giám sát và điều khiển toàn bộ quy trình.
- Kế hoạch công việc:
  - Nguyễn Phi Phúc: Xây dựng các điểm cuối API trên nền tảng FastAPI, cấu hình truyền phát dữ liệu thời gian thực bằng kỹ thuật Server-Sent Events (SSE).
  - Trần Minh Khang: Thiết kế các bảng biểu hiển thị báo cáo tình báo, danh sách chỉ số kỹ thuật kèm nhãn điểm tin cậy xAI và bản đồ nhiệt kỹ thuật tấn công.
  - Nguyễn Nhật Lâm: Xây dựng giao diện danh mục công cụ, bảng điều khiển trạng thái các tác tử và khu vực theo dõi nhật ký thực thi thời gian thực của Hunter Agent.
- Chỉ tiêu dự kiến: Giao diện web tải dữ liệu dưới 1 giây, phản ánh đầy đủ tiến trình suy luận và kết quả thực thi của cả hai tác tử.

---

### Tuần 7: Tích hợp toàn diện hệ thống và xây dựng tiến trình chạy tự động theo lịch trình

- Mục tiêu: Kết nối chu trình từ khâu thu thập tin tức đến khâu thực thi rà soát phòng thủ tự động.
- Kế hoạch công việc:
  - Nguyễn Phi Phúc: Xây dựng tiến trình daemon chạy ngầm theo chu kỳ, tự động quét nguồn cấp tin và kích hoạt chuỗi phân tích khi phát hiện bài báo mới.
  - Trần Minh Khang: Tối ưu hóa chu trình suy luận của mô hình ngôn ngữ, giảm thiểu số lượng token tiêu thụ và chuẩn hóa câu nhắc hệ thống.
  - Nguyễn Nhật Lâm: Hoàn thiện cơ chế tự động bàn giao kỹ năng từ tác tử phân tích sang tác tử rà soát, lưu vết toàn bộ chuỗi hành động vào cơ sở dữ liệu.
- Chỉ tiêu dự kiến: Hệ thống vận hành liên tục 24 giờ không xảy ra sự cố rò rỉ bộ nhớ hoặc xung đột khóa cơ sở dữ liệu.

---

### Tuần 8: Thử nghiệm thực nghiệm và đánh giá chất lượng hệ thống

- Mục tiêu: Đánh giá độ chính xác của mô hình học máy và hiệu quả của các kỹ năng phòng thủ được sinh tự động.
- Kế hoạch công việc:
  - Nguyễn Phi Phúc: Thực hiện đo lường thời gian suy luận, mức độ sử dụng bộ nhớ RAM và năng lực tính toán của card đồ họa trên thiết bị cục bộ.
  - Trần Minh Khang: Xây dựng tập dữ liệu kiểm thử gồm 50 bài báo bảo mật từ nhiều nguồn khác nhau, đánh giá độ chính xác trích xuất chỉ số kỹ thuật và tỷ lệ nhận diện sai.
  - Nguyễn Nhật Lâm: Đánh giá tỷ lệ phát hiện mã độc thành công và tỷ lệ báo động giả của Hunter Agent trên môi trường thử nghiệm giả lập.
- Chỉ tiêu dự kiến: Tỷ lệ trích xuất đúng chỉ số đạt trên 90%, tỷ lệ báo động sai của kỹ năng phòng thủ dưới 5%.

---

### Tuần 9: Viết tài liệu kỹ thuật, hướng dẫn cài đặt và tối ưu hóa hệ thống

- Mục tiêu: Đóng gói mã nguồn và hoàn thiện tài liệu phục vụ chuyển giao.
- Kế hoạch công việc:
  - Nguyễn Phi Phúc: Soạn thảo tài liệu kiến trúc hệ thống, tài liệu giải thích chi tiết cơ chế suy luận tác tử và mô hình giải thích được.
  - Trần Minh Khang: Soạn thảo hướng dẫn sử dụng API, tài liệu chuẩn hóa dữ liệu đầu vào và các tiêu chí an toàn thông tin của hệ thống.
  - Nguyễn Nhật Lâm: Viết kịch bản tự động hóa cài đặt môi trường, hoàn thiện tệp tài liệu hướng dẫn vận hành cho người dùng và quản trị viên.
  - Chỉ tiêu dự kiến: Bộ tài liệu kỹ thuật hoàn chỉnh gồm hơn 40 trang kèm sơ đồ luồng dữ liệu và hướng dẫn chạy mã nguồn với 1 câu lệnh.

---

### Tuần 10: Tổng kết đồ án, nghiệm thu sản phẩm và chuẩn bị bảo vệ

- Mục tiêu: Hoàn thiện báo cáo toàn văn đồ án chuyên ngành và chuẩn bị phương tiện thuyết trình.
- Kế hoạch công việc:
  - Nguyễn Phi Phúc: Tổng hợp kết quả thực nghiệm, viết chương kết luận của báo cáo và hoàn thiện slide thuyết trình đồ án.
  - Trần Minh Khang: Rà soát toàn bộ số liệu kỹ thuật trong báo cáo, chuẩn bị kịch bản thực nghiệm trực tiếp các tình huống tấn công và phòng thủ tự động.
  - Nguyễn Nhật Lâm: Kiểm tra tính toàn vẹn của mã nguồn, đóng gói bản sao lưu cơ sở dữ liệu và chuẩn bị video minh họa hoạt động của hệ thống.
- Chỉ tiêu dự kiến: Hoàn thành toàn văn báo cáo đồ án chuyên ngành và sẵn sàng bảo vệ trước hội đồng chuyên môn.

---

## TỔNG KẾT TIẾN ĐỘ THỰC TẾ ĐẾN TUẦN 3 VÀ KẾ HOẠCH BÀN GIAO

- Kết quả thực tế đạt được: Nhóm đã hoàn thành 100% mục tiêu của 3 tuần đầu tiên. Hệ thống đã xây dựng xong khung tác tử CTI Analyst Agent với ReAct loop chạy trên mô hình cục bộ Qwen 2.5, module kiểm định nguồn tin xAI Grounding đạt 12 trên 12 ca kiểm thử, và cơ sở dữ liệu SQLite lưu trữ ổn định hơn 25 báo cáo thực tế.
- Việc chưa thực hiện: Chưa tích hợp hoàn chỉnh Hunter Agent với môi trường sandbox thực tế trên hệ điều hành, chưa đóng gói giao diện web điều khiển SOC Dashboard bằng FastAPI, và chưa thực hiện đo đạc hiệu năng với tập dữ liệu 50 bài báo mẫu. Các nội dung này sẽ được triển khai lần lượt từ Tuần 4 đến Tuần 8 theo đúng lịch trình đã cam kết.
