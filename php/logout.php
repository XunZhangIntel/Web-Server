<?php

require_once 'csrf.php';

header('Content-Type: application/json');

start_session();

// 获取CSRF令牌
$headers = getallheaders();
$csrfToken = $headers['X-CSRF-Token'] ?? '';

// 验证CSRF令牌
if (!validate_csrf_token($csrfToken)) {
    http_response_code(403);
    echo json_encode(['success' => false, 'message' => '无效的CSRF令牌']);
    exit;
}

// 销毁会话
$_SESSION = array();

if (ini_get("session.use_cookies")) {
    $params = session_get_cookie_params();
    setcookie(session_name(), '', time() - 42000,
        $params["path"], $params["domain"],
        $params["secure"], $params["httponly"]
    );
}

session_destroy();

echo json_encode([
    'success' => true,
    'message' => '已成功登出'
]);

?>
