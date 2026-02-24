CREATE TABLE IF NOT EXISTS platform_user_roles (
  id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  user_id VARCHAR(64) NOT NULL,
  role_id VARCHAR(64) NOT NULL,
  status VARCHAR(16) NOT NULL DEFAULT 'active',
  can_view_user_management TINYINT(1) NOT NULL DEFAULT 0,
  can_operate_user_management TINYINT(1) NOT NULL DEFAULT 0,
  can_view_tenant_management TINYINT(1) NOT NULL DEFAULT 0,
  can_operate_tenant_management TINYINT(1) NOT NULL DEFAULT 0,
  created_at TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  updated_at TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3) ON UPDATE CURRENT_TIMESTAMP(3),
  PRIMARY KEY (id),
  UNIQUE KEY uk_auth_user_platform_roles_user_role (user_id, role_id),
  KEY idx_auth_user_platform_roles_user_status (user_id, status)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
