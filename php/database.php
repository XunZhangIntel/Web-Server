<?php

class Database {
    private static $instance = null;
    private $pdo;

    private function __construct(array $config) {
        $dsn = "mysql:host={$config['host']};dbname={$config['name']};charset=utf8mb4";
        $this->pdo = new PDO($dsn, $config['user'], $config['password'], $config['options']);
    }

    public static function getInstance(array $config): self {
        if (self::$instance === null) {
            self::$instance = new self($config);
        }
        return self::$instance;
    }

    public function getConnection(): PDO {
        return $this->pdo;
    }

    // 防止克隆和反序列化
    private function __clone() {}
    public function __wakeup() {}
}

?>
