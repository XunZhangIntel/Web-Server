<?php
require_once __DIR__ . '/CSRFTokenManager.php';

class SessionTokenMiddleware {
    private static $instance = null;
    private $isInitialized = false;
    private $tokenManager;

    private function __construct() {
        // 防止直接实例化
        $this->tokenManager = new SessionTokenManager();
    }

    public static function getInstance() {
        if (self::$instance === null) {
            self::$instance = new self();
        }
        return self::$instance;
    }

    /**
     * 中间件处理
     */
    public function handle() {
        // 验证会话完整性
        if (!$this->tokenManager->validateSessionIntegrity()) {
            http_response_code(401);
            return ['success' => false, 'message' => 'Session integrity check failed'];
        }

        // 对于POST请求验证CSRF Token
        if ($_SERVER['REQUEST_METHOD'] === 'POST' || $_SERVER['REQUEST_METHOD'] === 'PUT' || $_SERVER['REQUEST_METHOD'] === 'DELETE') {
            $token = $this->getTokenFromRequest();

            if (!$this->tokenManager->validateSessionToken($token)) {
                http_response_code(403);
                return ['success' => false, 'message' => 'Invalid CSRF token'];
            }
        }

        // 检查并刷新即将过期的token
        $tokenInfo = $this->tokenManager->checkAndRefreshToken();

        // 将token信息添加到响应头中
        header('X-CSRF-Token: ' . $tokenInfo['token']);
        header('X-CSRF-Token-ID: ' . $tokenInfo['token_id']);
        header('X-CSRF-Token-Expires: ' . $tokenInfo['expires_in']);

        return ['success' => true];
    }

    public function refreshSessionToken($reason) {
        $tokenInfo = $this->tokenManager->refreshSessionToken($reason);

        header('X-CSRF-Token: ' . $tokenInfo['token']);
        header('X-CSRF-Token-ID: ' . $tokenInfo['token_id']);
        header('X-CSRF-Token-Expires: ' . $tokenInfo['expires_in']);

        return;
    }

    public function regenerateSessionID() {
        $this->tokenManager->regenerateSessionID();
    }

    /**
     * 从请求中获取Token
     */
    private function getTokenFromRequest() {
        // 优先从Header中获取
        $token = $_SERVER['HTTP_X_CSRF_TOKEN'] ?? null;

        // 如果没有，从POST数据中获取
        if ($token === null && isset($_POST['csrf_token'])) {
            $token = $_POST['csrf_token'];
        }

        return $token;
    }

    // 防止克隆和反序列化
    private function __clone() {}
    private function __wakeup() {}
}
?>
