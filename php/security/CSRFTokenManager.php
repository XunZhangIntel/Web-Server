<?php
require_once __DIR__ . '/userIPManager.php';
require_once __DIR__ . '/../database.php';

class SessionTokenManager {
    private $tokenExpiry = 3600; // Token过期时间（1小时）

    /**
     * Session-Token 映射表结构
     */
    private function initSessionStructure() {
        if (!isset($_SESSION['security'])) {
            $_SESSION['security'] = [
                'csrf_tokens' => [
                    'current_token' => null,      // 当前有效token
                    'token_history' => [],        // 历史token记录
                    'token_usage' => 0,           // token使用次数
                    'last_token_refresh' => time() // 最后刷新时间
                ],
                'session_meta' => [
                    'session_id' => session_id(),
                    'ip_address' => UserIPManager::getClientIP(),
                    'user_agent' => $_SERVER['HTTP_USER_AGENT'] ?? '',
                    'created_at' => time(),
                    'last_activity' => time(),
                    'user_id' => null,
                    'username' => null,
                    'login_time' => null
                ],
            ];
        }
    }

    /**
     * 为当前Session生成唯一Token
     */
    public function generateSessionToken() {
        if (session_status() === PHP_SESSION_NONE) {
            session_start();
        }

        $this->initSessionStructure();

        // 如果已有当前token，先将其移到历史记录
        if ($_SESSION['security']['csrf_tokens']['current_token'] !== null) {
            $this->archiveCurrentToken();
        }

        // 生成新的加密安全token
        $token = bin2hex(random_bytes(32));
        $tokenId = $this->generateTokenId();

        // 存储当前token信息
        $_SESSION['security']['csrf_tokens']['current_token'] = [
            'token_value' => $token,
            'token_id' => $tokenId,
            'created_at' => time(),
            'expires_at' => time() + $this->tokenExpiry,
            'usage_count' => 0
        ];

        $_SESSION['security']['csrf_tokens']['last_token_refresh'] = time();

        return [
            'token' => $token,
            'token_id' => $tokenId,
            'expires_in' => $this->tokenExpiry
        ];
    }

    /**
     * 生成唯一的Token ID（包含Session信息）
     */
    private function generateTokenId() {
        $sessionPrefix = substr(session_id(), 0, 8); // 使用session ID前8位作为前缀
        $timestamp = time();
        $random = bin2hex(random_bytes(4));

        return sprintf('sess_%s_%d_%s', $sessionPrefix, $timestamp, $random);
    }

    /**
     * 验证Token是否属于当前Session
     */
    public function validateSessionToken($inputToken) {
        if (session_status() === PHP_SESSION_NONE) {
            session_start();
        }

        $this->initSessionStructure();

        $currentToken = $_SESSION['security']['csrf_tokens']['current_token'];

        // 检查是否存在当前token
        if ($currentToken === null) {
            return false;
        }

        // 检查token是否过期
        if (time() > $currentToken['expires_at']) {
            $tokenInfo = $this->refreshSessionToken();
            header('X-CSRF-Token: ' . $tokenInfo['token']);
            header('X-CSRF-Token-ID: ' . $tokenInfo['token_id']);
            header('X-CSRF-Token-Expires: ' . $tokenInfo['expires_in']);
            return false;
        }

        // 使用hash_equals防止时序攻击
        if (!hash_equals($currentToken['token_value'], $inputToken)) {
            error_log('CSRF attacked test: ' . date('Y-m-d H:i:s') .
              ' IP: ' . $_SERVER['REMOTE_ADDR'] .
              ' URL: ' . $_SERVER['REQUEST_URI']);
            $tokenInfo = $this->refreshSessionToken('attacked');
            header('X-CSRF-Token: ' . $tokenInfo['token']);
            header('X-CSRF-Token-ID: ' . $tokenInfo['token_id']);
            header('X-CSRF-Token-Expires: ' . $tokenInfo['expires_in']);
            return false;
        }

        // 更新使用计数
        $_SESSION['security']['csrf_tokens']['current_token']['usage_count']++;
        $_SESSION['security']['csrf_tokens']['token_usage']++;
        $_SESSION['security']['session_meta']['last_activity'] = time();

        return true;
    }

    /**
     * 将当前token归档到历史记录
     */
    private function archiveCurrentToken($reason = 'expired') {
        $currentToken = $_SESSION['security']['csrf_tokens']['current_token'];
        if ($currentToken !== null) {
            $currentToken['archived_at'] = time();
            $currentToken['archived_reason'] = $reason;

            $_SESSION['security']['csrf_tokens']['token_history'][] = $currentToken;
            $_SESSION['security']['csrf_tokens']['current_token'] = null;
        }
    }

    /**
     * 强制刷新Token（安全敏感操作后使用）
     */
    public function refreshSessionToken($reason = 'expired') {
        $this->archiveCurrentToken($reason);
        return $this->generateSessionToken();
    }

    /**
     * 获取当前Session的Token信息
     */
    public function getCurrentTokenInfo() {
        if (session_status() === PHP_SESSION_NONE) {
            session_start();
        }

        $this->initSessionStructure();

        return $_SESSION['security']['csrf_tokens']['current_token'];
    }

    /**
     * 检查并刷新过期的Token
     */
    public function checkAndRefreshToken() {
        $currentToken = $this->getCurrentTokenInfo();

        if ($currentToken === null || time() > $currentToken['expires_at']) {
            return $this->generateSessionToken();
        }

        // Token还有至少5分钟有效期，不需要刷新
        if (time() < $currentToken['expires_at'] - 300) {
            return [
                'token' => $currentToken['token_value'],
                'token_id' => $currentToken['token_id'],
                'expires_in' => $currentToken['expires_at'] - time()
            ];
        }

        // Token即将过期，自动刷新
        return $this->refreshSessionToken();
    }

    public function regenerateSessionID() {
        if (session_status() === PHP_SESSION_NONE) {
            session_start();
        }
        session_regenerate_id(true);

        $this->initSessionStructure();
        $_SESSION['security']['session_meta']['session_id'] = session_id();
    }

    private function archiveSessionToken($token, $user_id, $invalidated_at, $reason, $context = []) {
        $database = Database::getInstance(DB_CONFIG);
        $db = $database->getConnection();

        // 对token进行哈希处理后再存储，保护用户隐私
        $tokenHash = hash('sha256', $token);

        // 将上下文信息序列化（例如转为JSON）
        $contextJson = !empty($context) ? json_encode($context) : null;

        $stmt = $db->prepare("
            INSERT INTO invalidated_tokens_audit
            (token_hash, user_id, invalidated_at, reason, context)
            VALUES (?, ?, ?, ?, ?)
        ");

        $stmt->execute([
            $tokenHash,
            $user_id,
            $invalidated_at,
            $reason,
            $contextJson
        ]);
    }

    /**
     * 销毁当前Session的所有Token
     */
    public function destroyAllTokens($reason = 'unknown', $isArchive = false) {
        if (session_status() === PHP_SESSION_NONE) {
            session_start();
        }

        if (isset($_SESSION['security']) && $isArchive) {
            $user_id = $_SESSION['security']['session_meta']['user_id'];
            $token = $_SESSION['security']['csrf_tokens']['current_token']['token_value'];

            if ($user_id && $token) {
                $invalidated_at = time();
                $context = [
                    'old_ip' => $_SESSION['security']['session_meta']['ip_address'] ?? null,
                    'new_ip' => UserIPManager::getClientIP(),
                    'old_ua' => $_SESSION['security']['session_meta']['user_agent'] ?? null,
                    'new_ua' => $_SERVER['HTTP_USER_AGENT'],
                    'old_se' => $_SESSION['security']['session_meta']['session_id'] ?? null,
                    'new_se' => session_id()
                ];
                $this->archiveSessionToken($token, $user_id, $invalidated_at, $reason, $context);
            }

        }

        $_SESSION = array();

        session_destroy();

        $this->regenerateSessionID();
    }

    /**
     * 验证IP地址（更灵活的验证）
     */
    private function validateIpAddress($storedIp) {
        $currentIp = UserIPManager::getClientIP();

        // 如果存储的IP是unknown，允许任何IP（首次设置）
        if ($storedIp === 'unknown') {
            // 更新为当前IP
            $_SESSION['security']['session_meta']['ip_address'] = $currentIp;
            return true;
        }

        // 精确匹配
        if ($storedIp === $currentIp) {
            return true;
        }

        // 允许同一网段的变化（例如从动态IP切换）
        if ($this->isSameNetwork($storedIp, $currentIp)) {
            // 更新IP地址
            $_SESSION['security']['session_meta']['ip_address'] = $currentIp;
            return true;
        }

        return false;
    }

    /**
     * 检查两个IP是否在同一网段
     */
    private function isSameNetwork($ip1, $ip2, $maskBits = 24) {
        if (!filter_var($ip1, FILTER_VALIDATE_IP) || !filter_var($ip2, FILTER_VALIDATE_IP)) {
            return false;
        }

        // 只对IPv4进行处理
        if (filter_var($ip1, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) &&
            filter_var($ip2, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {

            $mask = -1 << (32 - $maskBits);
            $ip1Long = ip2long($ip1) & $mask;
            $ip2Long = ip2long($ip2) & $mask;

            return $ip1Long === $ip2Long;
        }

        return false;
    }

    /**
     * 验证Session完整性（防止会话劫持）
     */
    public function validateSessionIntegrity() {
        if (session_status() === PHP_SESSION_NONE) {
            session_start();
        }

        $this->initSessionStructure();
        $sessionMeta = $_SESSION['security']['session_meta'];

        // 检查IP地址是否变化
        if (!$this->validateIpAddress($sessionMeta['ip_address'])) {
            $reason = 'IP address mismatch detected. Session invalidated for security.';
            $this->destroyAllTokens($reason, true);
            return false;
        }

        // 检查User-Agent是否变化
        if ($sessionMeta['user_agent'] !== $_SERVER['HTTP_USER_AGENT']) {
            $reason = 'User-Agent mismatch detected. Session invalidated for security.';
            $this->destroyAllTokens($reason, true);
            return false;
        }

        // 检查Session ID是否变化
        if ($sessionMeta['session_id'] !== session_id()) {
            $oldSessionCreationTime = $sessionMeta['created_at'];
            $sessionLifetime = ini_get('session.gc_maxlifetime');
            if ((time() - $oldSessionCreationTime) > $sessionLifetime) {
                $this->destroyAllTokens();
                $this->initSessionStructure();
                return false;
            } else {
                $reason = 'Session ID mismatch. Possible session fixation attack or timeout.';
                $this->destroyAllTokens($reason, true);
                return false;
            }
        }

        // 更新最后活动时间
        $_SESSION['security']['session_meta']['last_activity'] = time();

        return true;
    }

}
