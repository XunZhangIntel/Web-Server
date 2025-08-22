<?php
include 'config.php';

header('Content-Type: application/json');

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $username = trim($_POST['username']);
    $email = trim($_POST['email']);
    $password = trim($_POST['password']);
    
    // 验证输入
    if (empty($username) || empty($email) || empty($password)) {
        echo json_encode(['success' => false, 'message' => '所有字段都必须填写']);
        exit;
    }
    
    if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
        echo json_encode(['success' => false, 'message' => '无效的电子邮件格式']);
        exit;
    }
    
    if (strlen($password) < 6) {
        echo json_encode(['success' => false, 'message' => '密码长度至少为6个字符']);
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
        $hashedPassword = password_hash($password, PASSWORD_DEFAULT);
        
        // 插入新用户
        $stmt = $db->prepare("INSERT INTO users (username, email, password) VALUES (?, ?, ?)");
        $stmt->execute([$username, $email, $hashedPassword]);
        
        echo json_encode(['success' => true, 'message' => '注册成功，请登录']);
    } catch(PDOException $e) {
        echo json_encode(['success' => false, 'message' => '数据库错误: ' . $e->getMessage()]);
    }
} else {
    echo json_encode(['success' => false, 'message' => '无效的请求方法']);
}
?>
