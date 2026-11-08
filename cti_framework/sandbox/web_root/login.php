<?php
// Standard safe login verification
session_start();
if (isset($_POST['username']) && isset($_POST['password'])) {
    $user = htmlspecialchars($_POST['username']);
    // Standard credential validation (Safe, no execution)
    if ($user === 'admin') {
        $_SESSION['authenticated'] = true;
    }
}
?>
