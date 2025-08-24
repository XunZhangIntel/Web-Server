<?php
require_once 'csrf.php';
require_once 'database.php';

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

$database = Database::getInstance(DB_CONFIG);
$db = $database->getConnection();

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $data = json_decode(file_get_contents('php://input'), true);
    if (json_last_error() !== JSON_ERROR_NONE) {
        http_response_code(400);
        echo json_encode(['success' => false, 'message' => '无效的 JSON 数据']);
        exit;
    }

    $username = trim($data['username']);
    $email = trim($data['email']);
    $password = $data['password'];
    $confirm_password = $data['confirm_password'];

    // 验证输入
    if (empty($username) || empty($email) || empty($password) || empty($confirm_password)) {
        echo json_encode(['success' => false, 'message' => '所有字段都必须填写']);
        exit();
    }

    if ($password !== $confirm_password) {
        echo json_encode(['success' => false, 'message' => '密码确认不匹配']);
        exit();
    }

    if (strlen($password) < 6) {
        echo json_encode(['success' => false, 'message' => '密码长度至少6位']);
        exit();
    }

    if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
        echo json_encode(['success' => false, 'message' => '无效的电子邮件格式']);
        exit;
    }
    
    try {
        // 检查用户名是否已存在
        $stmt = $db->prepare("SELECT id FROM users WHERE username = ? OR email = ?");
        $stmt->execute([$username, $email]);
        
        if ($stmt->rowCount() > 0) {
            echo json_encode(['success' => false, 'message' => '用户名或电子邮件已被使用']);
            exit;
        }
        
        // 哈希密码
        $hashed_password = password_hash($password, PASSWORD_DEFAULT);
        
        // 插入新用户
        $stmt = $db->prepare("INSERT INTO users (username, email, password) VALUES (?, ?, ?)");
        if ($stmt->execute([$username, $email, $hashed_password])) {
            $_SESSION['username'] = $username;
            echo json_encode(['success' => true, 'message' => '注册成功!']);
        } else {
            echo json_encode(['success' => false, 'message' => '注册失败，请稍后重试']);
        }
    } catch(PDOException $e) {
        echo json_encode(['success' => false, 'message' => '数据库错误: ' . $e->getMessage()]);
    }
} else {
    echo json_encode(['success' => false, 'message' => '无效的请求方法']);
}
?>
