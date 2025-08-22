<?php

require_once 'config.php';

header('Content-Type: application/json');

start_session();

if (isset($_SESSION['username'])) {
    echo json_encode(['username' => $_SESSION['username']]);
} else {
    echo json_encode(['username' => null]);
}
?>
