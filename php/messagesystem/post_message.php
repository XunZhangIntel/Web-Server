<?php
require_once __DIR__ . '/../config/init.php';

header('Content-Type: application/json');

$middlewareResult = $_SESSION['middleware_result'] ?? ['success' => true];
if (!$middlewareResult['success']) {
    echo json_encode(['success' => false, 'message' => $middlewareResult['message']]);
    exit;
}

if (!isset($_SESSION['security']['session_meta']['user_id'])) {
    echo json_encode(['success' => false, 'message' => '请先登录']);
    exit;
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $data = json_decode(file_get_contents('php://input'), true);

    if (json_last_error() !== JSON_ERROR_NONE) {
        http_response_code(400);
        echo json_encode(['success' => false, 'message' => '无效的 JSON 数据']);
        exit;
    }

    $content = trim($data['message']) ?? '';
    $user_id = $_SESSION['security']['session_meta']['user_id'];

    if (empty($content)) {
        echo json_encode(['success' => false, 'message' => '留言内容不能为空']);
        exit;
    }

    try {
        $database = Database::getInstance(DB_CONFIG);
        $db = $database->getConnection();

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
