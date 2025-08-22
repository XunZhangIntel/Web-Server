<?php
require_once 'config.php';
require_once 'database.php';

header('Content-Type: application/json');

$database = Database::getInstance(DB_CONFIG);
$db = $database->getConnection();

$stmt = $db->query("
    SELECT m.*, u.username 
    FROM messages m
    JOIN users u ON m.user_id = u.id
    ORDER BY m.created_at DESC
");
echo json_encode($stmt->fetchAll());
?>
