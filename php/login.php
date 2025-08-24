<?php

require_once 'csrf.php';
require_once 'database.php';

header('Content-Type: application/json');

// 获取真实客户端IP地址
function get_client_ip() {
    $ip_keys = [
        'HTTP_CLIENT_IP',
        'HTTP_X_FORWARDED_FOR',
        'HTTP_X_FORWARDED',
        'HTTP_X_CLUSTER_CLIENT_IP',
        'HTTP_FORWARDED_FOR',
        'HTTP_FORWARDED',
        'REMOTE_ADDR'
    ];

    foreach ($ip_keys as $key) {
        if (array_key_exists($key, $_SERVER) === true) {
            foreach (explode(',', $_SERVER[$key]) as $ip) {
                $ip = trim($ip);

                // 验证IP地址格式
                if (filter_var($ip, FILTER_VALIDATE_IP, 
                    FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE) !== false) {
                    return $ip;
                }
            }
        }
    }

    return $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';
}

// 记录登录历史
function record_login_history($user_id, $success = true) {
    $ip = get_client_ip();
    $user_agent = $_SERVER['HTTP_USER_AGENT'] ?? '';

    $stmt = $db->prepare("
        INSERT INTO login_history (user_id, login_ip, user_agent, success) 
        VALUES (?, ?, ?, ?)
    ");
    $stmt->bind_param("issi", $user_id, $ip, $user_agent, $success);
    $stmt->execute();

    // 如果登录成功，更新用户表的最后登录信息
    if ($success) {
        $stmt = $db->prepare("
            UPDATE users 
            SET last_login_ip = ?, last_login_time = NOW(), login_count = login_count + 1 
            WHERE id = ?
        ");
        $stmt->bind_param("si", $ip, $user_id);
        $stmt->execute();
    }
}

// 获取用户登录历史
function get_login_history($user_id, $limit = 10) {
    $stmt = $db->prepare("
        SELECT login_ip, login_time, user_agent, success 
        FROM login_history 
        WHERE user_id = ? 
        ORDER BY login_time DESC 
        LIMIT ?
    ");
    $stmt->bind_param("ii", $user_id, $limit);
    $stmt->execute();
    $result = $stmt->get_result();

    $history = [];
    while ($row = $result->fetch_assoc()) {
        $history[] = $row;
    }

    return $history;
}

// 检查可疑登录（新设备/新地点）
function check_suspicious_login($user_id) {
    $ip = get_client_ip();
    $user_agent = $_SERVER['HTTP_USER_AGENT'] ?? '';

    // 检查最近是否有相同IP的登录
    $stmt = $db->prepare("
        SELECT COUNT(*) as count 
        FROM login_history 
        WHERE user_id = ? AND login_ip = ? AND success = 1 
        AND login_time > DATE_SUB(NOW(), INTERVAL 30 DAY)
    ");
    $stmt->bind_param("is", $user_id, $ip);
    $stmt->execute();
    $result = $stmt->get_result();
    $row = $result->fetch_assoc();

    return $row['count'] == 0; // 如果是新IP，返回true表示可疑
}

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

$database = Database::getInstance(DB_CONFIG);
$db = $database->getConnection();

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
            $isSuspicious = check_suspicious_login($user['id']);

            // Record login history
            record_login_history($user['id'], true);

            // 登录成功，设置会话
            $_SESSION['user_id'] = $user['id'];
            $_SESSION['username'] = $user['username'];
            $_SESSION['login_ip'] = get_client_ip();
            $_SESSION['login_time'] = time();
            echo json_encode(['success' => true, 'message' => '登录成功']);
        }

    } catch (Exception $e) {
        http_response_code(500);
	echo json_encode(['success' => false, 'message' => '服务器错误']);
    }
}
