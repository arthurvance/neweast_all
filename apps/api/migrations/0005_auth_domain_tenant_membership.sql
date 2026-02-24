CREATE TABLE IF NOT EXISTS tenant_memberships (
  id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  user_id VARCHAR(64) NOT NULL,
  tenant_id VARCHAR(64) NOT NULL,
  tenant_name VARCHAR(128) NULL,
  can_view_user_management TINYINT(1) NOT NULL DEFAULT 0,
  can_operate_user_management TINYINT(1) NOT NULL DEFAULT 0,
  can_view_role_management TINYINT(1) NOT NULL DEFAULT 0,
  can_operate_role_management TINYINT(1) NOT NULL DEFAULT 0,
  status VARCHAR(16) NOT NULL DEFAULT 'active',
  created_at TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  updated_at TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3) ON UPDATE CURRENT_TIMESTAMP(3),
  PRIMARY KEY (id),
  UNIQUE KEY uk_auth_user_tenants_user_tenant (user_id, tenant_id),
  KEY idx_auth_user_tenants_user_status (user_id, status)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
