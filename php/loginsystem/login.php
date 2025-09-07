<?php
require_once __DIR__ . '/../config/init.php';

header('Content-Type: application/json');

$middlewareResult = $_SESSION['middleware_result'] ?? ['success' => true];
if (!$middlewareResult['success']) {
    echo json_encode(['success' => false, 'message' => $middlewareResult['message']]);
    exit;
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $data = json_decode(file_get_contents('php://input'), true);

    if (json_last_error() !== JSON_ERROR_NONE) {
        http_response_code(400);
	    echo json_encode(['success' => false, 'message' => '无效的 JSON 数据']);
	    exit;
    } 

    $username = $data['username'] ?? '';
    $password = $data['password'] ?? '';
 
    if (empty($username) || empty($password)) {
        http_response_code(400);
        echo json_encode(['success' => false, 'message' => '用户名和密码不能为空']);
        exit;
    }

    try {
        $database = Database::getInstance(DB_CONFIG);
        $db = $database->getConnection();

        $stmt = $db->prepare("SELECT * FROM users WHERE username = ?");
        if (!$stmt->execute([$username])) {
	        throw new Exception('数据库查询失败');
	    }
        $user = $stmt->fetch();

        if (!$user) {
            echo json_encode(['success' => false, 'message' => '用户不存在']);
        } elseif (!password_verify($password, $user['password'])) {
            echo json_encode(['success' => false, 'message' => '密码错误']);
        } else {
            // Check suspicious login
            $isSuspicious = UserIPManager::check_suspicious_login($user['id']);

            $tokenmidware = SessionTokenMiddleware::getInstance();
            $tokenInfo = $tokenmidware->refreshSessionToken('login');

            header('X-CSRF-Token: ' . $tokenInfo['token']);
            header('X-CSRF-Token-ID: ' . $tokenInfo['token_id']);
            header('X-CSRF-Token-Expires: ' . $tokenInfo['expires_in']);

            // Record login history
            UserIPManager::record_login_history($user['id'], true);

            // 登录成功，设置会话
            $_SESSION['security']['session_meta']['user_id'] = $user['id'];
            $_SESSION['security']['session_meta']['username'] = $user['username'];
            $_SESSION['security']['session_meta']['login_time'] = time();

            $tokenmidware->regenerateSessionID();
            echo json_encode(['success' => true, 'message' => '登录成功', 'suspiciuos_login' => $isSuspicious]);
        }

    } catch (Exception $e) {
        http_response_code(500);
        echo json_encode(['success' => false, 'message' => '服务器错误']);
    }
}
