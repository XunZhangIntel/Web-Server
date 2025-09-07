<?php
require_once __DIR__ . '/config.php';
require __DIR__ . '/../security/SessionTokenMiddleware.php';

session_start();

// 应用中间件（在所有页面都会执行）
$middlewareResult = SessionTokenMiddleware::getInstance()->handle();

$_SESSION['middleware_result'] = $middlewareResult;
