<?php

require_once __DIR__ . '/../config/init.php';

header('Content-Type: application/json');

if (isset($_SESSION['security']['session_meta']['username'])) {
    echo json_encode(['username' => $_SESSION['security']['session_meta']['username']]);
} else {
    echo json_encode(['username' => null]);
}
?>
