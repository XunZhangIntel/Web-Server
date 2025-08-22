<?php
include 'php/config.php';

ini_set('display_errors', 1);
ini_set('display_startup_errors', 1);
error_reporting(E_ALL);

try {
  $db->query("SELECT 1"); // 简单查询测试
  echo "数据库连接成功！";
} catch(PDOException $e) {
  phpinfo();
  die("连接失败: " . $e->getMessage());
}
?>
