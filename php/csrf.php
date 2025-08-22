<?php
require_once 'config.php';
header('Content-Type: application/json');

function generate_csrf_token() {
    if (empty($_SESSION[CSRF_TOKEN_NAME])) {
        $_SESSION[CSRF_TOKEN_NAME] = bin2hex(random_bytes(32));
        $_SESSION[CSRF_TOKEN_NAME . '_expire'] = time() + CSRF_TOKEN_LIFETIME;
    }

    // 检查token是否过期
    if (isset($_SESSION[CSRF_TOKEN_NAME . '_expire']) &&
        $_SESSION[CSRF_TOKEN_NAME . '_expire'] < time()) {
        unset($_SESSION[CSRF_TOKEN_NAME]);
        unset($_SESSION[CSRF_TOKEN_NAME . '_expire']);
        $_SESSION[CSRF_TOKEN_NAME] = bin2hex(random_bytes(32));
        $_SESSION[CSRF_TOKEN_NAME . '_expire'] = time() + CSRF_TOKEN_LIFETIME;
    }

    return $_SESSION[CSRF_TOKEN_NAME];
}

function validate_csrf_token($token) {
    if (!isset($_SESSION[CSRF_TOKEN_NAME])) {
        return false;
    }

    if (!isset($_SESSION[CSRF_TOKEN_NAME . '_expire']) ||
        $_SESSION[CSRF_TOKEN_NAME . '_expire'] < time()) {
        unset($_SESSION[CSRF_TOKEN_NAME]);
        unset($_SESSION[CSRF_TOKEN_NAME . '_expire']);
        return false;
    }

    return hash_equals($_SESSION[CSRF_TOKEN_NAME], $token);
}

if ($_SERVER['REQUEST_METHOD'] === 'GET') {
    
    start_session();

    $token = generate_csrf_token();

    echo json_encode([
        'success' => true,
        'token' => $token
    ]);
}

?>
