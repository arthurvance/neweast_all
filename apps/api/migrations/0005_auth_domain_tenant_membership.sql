CREATE TABLE IF NOT EXISTS auth_user_domain_access (
  id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  user_id VARCHAR(64) NOT NULL,
  domain VARCHAR(16) NOT NULL,
  status VARCHAR(16) NOT NULL DEFAULT 'active',
  created_at TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  updated_at TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3) ON UPDATE CURRENT_TIMESTAMP(3),
  PRIMARY KEY (id),
  UNIQUE KEY uk_auth_user_domain_access_user_domain (user_id, domain),
  KEY idx_auth_user_domain_access_user_status (user_id, status)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS auth_user_tenants (
  id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  user_id VARCHAR(64) NOT NULL,
  tenant_id VARCHAR(64) NOT NULL,
  tenant_name VARCHAR(128) NULL,
  can_view_user_management TINYINT(1) NOT NULL DEFAULT 0,
  can_operate_user_management TINYINT(1) NOT NULL DEFAULT 0,
  can_view_organization_management TINYINT(1) NOT NULL DEFAULT 0,
  can_operate_organization_management TINYINT(1) NOT NULL DEFAULT 0,
  status VARCHAR(16) NOT NULL DEFAULT 'active',
  created_at TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  updated_at TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3) ON UPDATE CURRENT_TIMESTAMP(3),
  PRIMARY KEY (id),
  UNIQUE KEY uk_auth_user_tenants_user_tenant (user_id, tenant_id),
  KEY idx_auth_user_tenants_user_status (user_id, status)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

INSERT INTO auth_user_domain_access (user_id, domain, status)
SELECT u.id, 'platform', 'active'
FROM users u
ON DUPLICATE KEY UPDATE
  status = VALUES(status),
  updated_at = CURRENT_TIMESTAMP(3);

INSERT IGNORE INTO auth_user_domain_access (user_id, domain, status)
SELECT DISTINCT ut.user_id, 'tenant', 'active'
FROM auth_user_tenants ut
WHERE ut.status = 'active';
