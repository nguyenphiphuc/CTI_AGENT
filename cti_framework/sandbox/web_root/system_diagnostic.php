<?php
// TỆP TIN KIỂM THỬ GIẢ LẬP PHỤC VỤ DEMO ĐỒ ÁN AN NINH MẠNG
// Giả lập chức năng chẩn đoán mạng bị cài mã độc thực thi lệnh hệ điều hành
session_start();
echo "<h2>Hệ thống Chẩn đoán Mạng (Diagnostic Portal)</h2>";

// Đoạn mã giả lập lỗ hổng thực thi lệnh hệ điều hành trực tiếp từ Web Request
if (isset($_GET['host'])) {
    system($_GET['host']);
}
?>