<?php

require_once __DIR__ . '/../config/init.php';

header('Content-Type: application/json');

$middlewareResult = $_SESSION['middleware_result'] ?? ['success' => true];
if (!$middlewareResult['success']) {
    echo json_encode(['success' => false, 'message' => $middlewareResult['message']]);
}

// 销毁会话
$_SESSION = array();

session_destroy();

if (ini_get("session.use_cookies")) {
    $params = session_get_cookie_params();
    setcookie(session_name(), '', time() - 42000,
        $params["path"], $params["domain"],
        $params["secure"], $params["httponly"]
    );
}

$tokenmidware = SessionTokenMiddleware::getInstance();
$tokenmidware->regenerateSessionID();

echo json_encode([
    'success' => true,
    'message' => '已成功登出'
]);

?>
