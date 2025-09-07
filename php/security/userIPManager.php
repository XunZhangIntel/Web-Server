<?php
require_once __DIR__ . '/../database.php';

class UserIPManager {

    // Get clinet IP
    public static function getClientIP() {
        $ip = $_SERVER['REMOTE_ADDR'];

        // 检查各种可能的代理头部（按可信度排序）
        $proxy_headers = [
            'HTTP_X_FORWARDED_FOR',
            'HTTP_X_REAL_IP',
            'HTTP_X_CLIENT_IP',
            'HTTP_CLIENT_IP',
            'HTTP_X_FORWARDED',
            'HTTP_X_CLUSTER_CLIENT_IP',
            'HTTP_FORWARDED_FOR',
            'HTTP_FORWARDED'
        ];

        foreach ($proxy_headers as $header) {
            if (isset($_SERVER[$header]) && !empty($_SERVER[$header])) {
                $ip = $_SERVER[$header];
                break;
            }
        }

        // 处理多个IP的情况（如经过多个代理）
        if (strpos($ip, ',') !== false) {
            $ips = explode(',', $ip);
            $ip = trim($ips[0]); // 取第一个IP（最原始的客户端IP）
        }

        return filter_var($ip, FILTER_VALIDATE_IP) ? $ip : $_SERVER['REMOTE_ADDR'];
    }

    // Get Session IP
    public static function getSessionIP() {
        if (!isset($_SESSION['security'])) {
            return null;
        }

        return $_SESSION['security']['session_meta']['ip_address'];
    }

    // 记录登录历史
    public static function record_login_history($user_id, $success = true) {
        $ip = UserIPManager::getClientIP();
        $user_agent = $_SERVER['HTTP_USER_AGENT'] ?? '';

        $database = Database::getInstance(DB_CONFIG);
        $db = $database->getConnection();
        $stmt = $db->prepare("
            INSERT INTO login_history (user_id, login_ip, user_agent, success)
            VALUES (?, ?, ?, ?)
            ");
        $stmt->execute([$user_id, $ip, $user_agent, $success]);

        // 如果登录成功，更新用户表的最后登录信息
        if ($success) {
            $stmt = $db->prepare("
                UPDATE users
                SET last_login_ip = ?, last_login_time = NOW(), login_count = login_count + 1
                WHERE id = ?
                ");
            $stmt->execute([$ip, $user_id]);
        }
    }

    // 获取用户登录历史
    public static function get_login_history($user_id, $limit = 10) {
        $database = Database::getInstance(DB_CONFIG);
        $db = $database->getConnection();
        $stmt = $db->prepare("
            SELECT login_ip, login_time, user_agent, success
            FROM login_history
            WHERE user_id = ?
            ORDER BY login_time DESC
            LIMIT ?
        ");
        $stmt->execute([$user_id, $limit]);
        $result = $stmt->fetchAll(PDO::FETCH_ASSOC);

        return $result;
    }

    // 检查可疑登录（新设备/新地点）
    public static function check_suspicious_login($user_id) {
        $database = Database::getInstance(DB_CONFIG);
        $db = $database->getConnection();
        $ip = UserIPManager::getClientIP();
        $user_agent = $_SERVER['HTTP_USER_AGENT'] ?? '';

        // 检查最近是否有相同IP的登录
        $stmt = $db->prepare("
            SELECT COUNT(*) as count
            FROM login_history
            WHERE user_id = ? AND login_ip = ? AND success = 1
            AND login_time > DATE_SUB(NOW(), INTERVAL 30 DAY)
            ");

        $stmt->execute([$user_id, $ip]);
        $result = $stmt->fetch(PDO::FETCH_ASSOC);

        return $result['count'] == 0; // 如果是新IP，返回true表示可疑
    }

}
