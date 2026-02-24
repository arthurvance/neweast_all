CREATE TABLE IF NOT EXISTS platform_roles (
  role_id VARCHAR(64) NOT NULL,
  code VARCHAR(64) NOT NULL,
  code_normalized VARCHAR(64) NOT NULL,
  name VARCHAR(128) NOT NULL,
  status ENUM('active', 'disabled') NOT NULL DEFAULT 'active',
  scope ENUM('platform', 'tenant') NOT NULL DEFAULT 'platform',
  is_system TINYINT(1) NOT NULL DEFAULT 0,
  created_by_user_id VARCHAR(64) NULL,
  updated_by_user_id VARCHAR(64) NULL,
  created_at TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  updated_at TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3) ON UPDATE CURRENT_TIMESTAMP(3),
  PRIMARY KEY (role_id),
  UNIQUE KEY uk_platform_roles_code_normalized (code_normalized),
  KEY idx_platform_roles_scope_status (scope, status),
  KEY idx_platform_roles_system (is_system),
  CONSTRAINT fk_platform_roles_created_by_user FOREIGN KEY (created_by_user_id) REFERENCES iam_users (id),
  CONSTRAINT fk_platform_roles_updated_by_user FOREIGN KEY (updated_by_user_id) REFERENCES iam_users (id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

INSERT INTO platform_roles (
  role_id,
  code,
  code_normalized,
  name,
  status,
  scope,
  is_system,
  created_by_user_id,
  updated_by_user_id
)
VALUES (
  'sys_admin',
  'sys_admin',
  'sys_admin',
  '系统管理员',
  'active',
  'platform',
  1,
  NULL,
  NULL
)
ON DUPLICATE KEY UPDATE
  code = VALUES(code),
  code_normalized = VALUES(code_normalized),
  name = VALUES(name),
  status = VALUES(status),
  scope = VALUES(scope),
  is_system = VALUES(is_system),
  updated_at = CURRENT_TIMESTAMP(3);
