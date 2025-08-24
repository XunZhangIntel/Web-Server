<?php

// 安全配置
session_set_cookie_params([
    'lifetime' => 1800,
    'path' => '/',
    'secure' => false,    // 本地开发时可关闭
    'httponly' => true,
    'samesite' => 'Lax'
]);

define('DB_CONFIG', [
    'host'     => 'localhost',
    'name'     => 'login_system',
    'user'     => 'app_user',
    'password' => '12345687',
    'options'  => [
        PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
        PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC
    ]
]);

// 会话配置
define('SESSION_NAME', 'AUTH_SESS');
define('SESSION_LIFETIME', 3600); // 1小时

// 安全配置
define('CSRF_TOKEN_NAME', 'csrf_token');
define('CSRF_TOKEN_LIFETIME', 1800); // 30分钟

// IP相关配置
define('TRUSTED_PROXIES', []);
define('LOG_FAILED_ATTEMPTS', true);

// 错误报告 (开发时启用，生产时禁用)
error_reporting(E_ALL);
ini_set('display_errors', 1);

function start_session() {
    session_name(SESSION_NAME);
    session_set_cookie_params(SESSION_LIFETIME);
    session_start();

    // 防止会话固定攻击
    if (empty($_SESSION['initiated'])) {
        session_regenerate_id();
        $_SESSION['initiated'] = true;
    }
}

?>
