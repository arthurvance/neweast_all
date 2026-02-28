CREATE TABLE IF NOT EXISTS system_sensitive_configs (
  `key` VARCHAR(128) NOT NULL,
  `value` TEXT NOT NULL,
  remark VARCHAR(255) NULL,
  version BIGINT UNSIGNED NOT NULL DEFAULT 1,
  status ENUM('active', 'disabled') NOT NULL DEFAULT 'active',
  updated_by_user_id VARCHAR(64) NULL,
  updated_at TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3) ON UPDATE CURRENT_TIMESTAMP(3),
  created_by_user_id VARCHAR(64) NULL,
  created_at TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  PRIMARY KEY (`key`),
  CONSTRAINT chk_system_sensitive_configs_key
    CHECK (`key` IN (
      'auth.default_password',
      'auth.access_ttl_seconds',
      'auth.refresh_ttl_seconds',
      'auth.otp_ttl_seconds',
      'auth.rate_limit_window_seconds',
      'auth.rate_limit_max_attempts'
    )),
  CONSTRAINT fk_system_sensitive_configs_updated_by_user
    FOREIGN KEY (updated_by_user_id) REFERENCES iam_users (id),
  CONSTRAINT fk_system_sensitive_configs_created_by_user
    FOREIGN KEY (created_by_user_id) REFERENCES iam_users (id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

INSERT INTO system_sensitive_configs (
  `key`,
  `value`,
  remark,
  version,
  status,
  updated_by_user_id,
  created_by_user_id
)
VALUES
(
  'auth.default_password',
  'enc:v1:6rJ33ZxXgkxCHR4E:b94w-yzmcyEsEEG35K5zmg:OW85WJOd',
  '平台初始化默认密码密文配置',
  1,
  'active',
  NULL,
  NULL
),
(
  'auth.access_ttl_seconds',
  '864000',
  '访问令牌有效期（秒）',
  1,
  'active',
  NULL,
  NULL
),
(
  'auth.refresh_ttl_seconds',
  '604800',
  '刷新令牌有效期（秒）',
  1,
  'active',
  NULL,
  NULL
),
(
  'auth.otp_ttl_seconds',
  '900',
  '短信验证码有效期（秒）',
  1,
  'active',
  NULL,
  NULL
),
(
  'auth.rate_limit_window_seconds',
  '60',
  '登录限流窗口时长（秒）',
  1,
  'active',
  NULL,
  NULL
),
(
  'auth.rate_limit_max_attempts',
  '10',
  '登录限流窗口最大尝试次数',
  1,
  'active',
  NULL,
  NULL
)
ON DUPLICATE KEY UPDATE
  `value` = VALUES(`value`),
  remark = VALUES(remark),
  status = VALUES(status),
  updated_at = CURRENT_TIMESTAMP(3);

INSERT INTO platform_role_permission_grants (
  role_id,
  permission_code,
  created_by_user_id,
  updated_by_user_id
)
VALUES
  ('sys_admin', 'platform.role_management.view', NULL, NULL),
  ('sys_admin', 'platform.role_management.operate', NULL, NULL)
ON DUPLICATE KEY UPDATE
  updated_at = CURRENT_TIMESTAMP(3);
