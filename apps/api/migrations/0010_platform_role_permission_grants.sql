CREATE TABLE IF NOT EXISTS platform_role_permission_grants (
  role_id VARCHAR(64) NOT NULL,
  permission_code VARCHAR(128) NOT NULL,
  created_by_user_id VARCHAR(64) NULL,
  updated_by_user_id VARCHAR(64) NULL,
  created_at TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  updated_at TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3) ON UPDATE CURRENT_TIMESTAMP(3),
  PRIMARY KEY (role_id, permission_code),
  KEY idx_platform_role_permission_grants_permission_code (permission_code),
  CONSTRAINT fk_platform_role_permission_grants_role_id
    FOREIGN KEY (role_id) REFERENCES platform_role_catalog (role_id)
    ON DELETE CASCADE,
  CONSTRAINT fk_platform_role_permission_grants_created_by_user
    FOREIGN KEY (created_by_user_id) REFERENCES users (id),
  CONSTRAINT fk_platform_role_permission_grants_updated_by_user
    FOREIGN KEY (updated_by_user_id) REFERENCES users (id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

INSERT INTO platform_role_permission_grants (
  role_id,
  permission_code,
  created_by_user_id,
  updated_by_user_id
)
VALUES
  ('sys_admin', 'platform.member_admin.view', NULL, NULL),
  ('sys_admin', 'platform.member_admin.operate', NULL, NULL),
  ('sys_admin', 'platform.billing.view', NULL, NULL),
  ('sys_admin', 'platform.billing.operate', NULL, NULL)
ON DUPLICATE KEY UPDATE
  updated_at = CURRENT_TIMESTAMP(3);
