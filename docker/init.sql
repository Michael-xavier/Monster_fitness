SET NAMES utf8mb4;
SET time_zone = '-03:00';

CREATE TABLE IF NOT EXISTS usuarios (
    id            INT AUTO_INCREMENT PRIMARY KEY,
    nome          VARCHAR(120)  NOT NULL,
    email         VARCHAR(180)  NOT NULL UNIQUE,
    cpf           VARCHAR(14)   NOT NULL UNIQUE,
    nascimento    DATE,
    telefone      VARCHAR(20),
    senha_hash    VARCHAR(255)  NOT NULL,
    plano         ENUM('mensal','trimestral','semestral','anual','premium') NOT NULL DEFAULT 'mensal',
    objetivo      VARCHAR(30),
    nivel         VARCHAR(20),
    ativo         TINYINT(1)   NOT NULL DEFAULT 1,
    tentativas_login INT        NOT NULL DEFAULT 0,
    bloqueado_ate DATETIME,
    criado_em     DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
    atualizado_em DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX idx_email  (email),
    INDEX idx_ativo  (ativo),
    INDEX idx_bloqueado (bloqueado_ate)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS sessoes (
    id          INT AUTO_INCREMENT PRIMARY KEY,
    usuario_id  INT         NOT NULL,
    jti         VARCHAR(64) NOT NULL UNIQUE,
    criado_em   DATETIME    NOT NULL DEFAULT CURRENT_TIMESTAMP,
    expira_em   DATETIME    NOT NULL,
    revogado    TINYINT(1)  NOT NULL DEFAULT 0,
    ip_origem   VARCHAR(45),
    user_agent  VARCHAR(255),
    FOREIGN KEY (usuario_id) REFERENCES usuarios(id) ON DELETE CASCADE,
    INDEX idx_jti      (jti),
    INDEX idx_revogado (revogado),
    INDEX idx_expira   (expira_em)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS csrf_tokens (
    token       VARCHAR(64) PRIMARY KEY,
    criado_em   DATETIME    NOT NULL DEFAULT CURRENT_TIMESTAMP,
    usado       TINYINT(1)  NOT NULL DEFAULT 0,
    INDEX idx_criado (criado_em)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS audit_logs (
    id          INT AUTO_INCREMENT PRIMARY KEY,
    usuario_id  INT,
    evento      VARCHAR(100) NOT NULL,
    ip          VARCHAR(45),
    user_agent  VARCHAR(255),
    detalhes    TEXT,
    criado_em   DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_evento   (evento),
    INDEX idx_usuario  (usuario_id),
    INDEX idx_criado   (criado_em)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

GRANT SELECT, INSERT, UPDATE, DELETE ON monsterfitness.* TO 'mf_user'@'%';
FLUSH PRIVILEGES;
