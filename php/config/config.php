<?php

define('DB_CONFIG', [
    'host'     => 'localhost',
    'name'     => 'login_system',
    'user'     => 'app_user',
    'password' => '12345678',
    'options'  => [
        PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
        PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC
    ]
]);

// 会话配置
define('SESSION_LOGIN', 'auth_login');
define('SESSION_REGISTER', 'auth_register');
define('SESSION_MESSAGE', 'auth_message');
define('SESSION_LOGOUT', 'auth_logout');
define('SESSION_GETUSER', 'auth_getuser');
define('SESSION_CSRFTOKEN', 'auth_csrftoken');
define('SESSION_LIFETIME', 1800); // 0.5小时

// 安全配置
define('CSRF_TOKEN_NAME', 'csrf_token');
define('CSRF_TOKEN_LIFETIME', 1800); // 30分钟

// IP相关配置
define('TRUSTED_PROXIES', []);
define('LOG_FAILED_ATTEMPTS', true);

// 错误报告 (开发时启用，生产时禁用)
error_reporting(E_ALL);
ini_set('display_errors', 1);

function start_session($name, $lifetime = SESSION_LIFETIME) {
    session_name($name);
    session_set_cookie_params([
        'lifetime' => $lifetime,
        'path' => '/',
        'secure' => false,    // 本地开发时可关闭
        'httponly' => true,
        'samesite' => 'Lax'
    ]);
    session_start();

    // 防止会话固定攻击
    if (empty($_SESSION['initiated'])) {
        session_regenerate_id();
        $_SESSION['initiated'] = true;
    }
}

?>
