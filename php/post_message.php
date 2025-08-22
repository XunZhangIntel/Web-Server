<?php
include 'config.php';

header('Content-Type: application/json');

if (!isset($_SESSION['user_id'])) {
    echo json_encode(['success' => false, 'message' => '请先登录']);
    exit;
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $content = trim($_POST['content']);
    $user_id = $_SESSION['user_id'];

    if (empty($content)) {
        echo json_encode(['success' => false, 'message' => '留言内容不能为空']);
        exit;
    }

    try {
        $stmt = $db->prepare("INSERT INTO messages (user_id, content) VALUES (?, ?)");
        $stmt->execute([$user_id, $content]);
        echo json_encode(['success' => true]);
    } catch(PDOException $e) {
        echo json_encode(['success' => false, 'message' => '提交失败: '.$e->getMessage()]);
    }
} else {
    http_response_code(405);
    echo json_encode(['success' => false, 'message' => '无效的请求方法']);
}
?>
