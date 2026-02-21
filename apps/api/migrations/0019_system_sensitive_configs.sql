CREATE TABLE IF NOT EXISTS system_sensitive_configs (
  config_key VARCHAR(128) NOT NULL,
  encrypted_value TEXT NOT NULL,
  version BIGINT UNSIGNED NOT NULL DEFAULT 1,
  status ENUM('active', 'disabled') NOT NULL DEFAULT 'active',
  updated_by_user_id VARCHAR(64) NOT NULL,
  updated_at TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3) ON UPDATE CURRENT_TIMESTAMP(3),
  created_by_user_id VARCHAR(64) NULL,
  created_at TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  PRIMARY KEY (config_key),
  CONSTRAINT chk_system_sensitive_configs_key
    CHECK (config_key IN ('auth.default_password')),
  CONSTRAINT fk_system_sensitive_configs_updated_by_user
    FOREIGN KEY (updated_by_user_id) REFERENCES users (id),
  CONSTRAINT fk_system_sensitive_configs_created_by_user
    FOREIGN KEY (created_by_user_id) REFERENCES users (id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

INSERT INTO platform_role_permission_grants (
  role_id,
  permission_code,
  created_by_user_id,
  updated_by_user_id
)
VALUES
  ('sys_admin', 'platform.system_config.view', NULL, NULL),
  ('sys_admin', 'platform.system_config.operate', NULL, NULL)
ON DUPLICATE KEY UPDATE
  updated_at = CURRENT_TIMESTAMP(3);
