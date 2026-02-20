CREATE TABLE IF NOT EXISTS tenant_role_permission_grants (
  role_id VARCHAR(64) NOT NULL,
  permission_code VARCHAR(128) NOT NULL,
  created_by_user_id VARCHAR(64) NULL,
  updated_by_user_id VARCHAR(64) NULL,
  created_at TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  updated_at TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3) ON UPDATE CURRENT_TIMESTAMP(3),
  PRIMARY KEY (role_id, permission_code),
  KEY idx_tenant_role_permission_grants_permission_code (permission_code),
  CONSTRAINT fk_tenant_role_permission_grants_role_id
    FOREIGN KEY (role_id) REFERENCES platform_role_catalog (role_id)
    ON DELETE CASCADE,
  CONSTRAINT fk_tenant_role_permission_grants_created_by_user
    FOREIGN KEY (created_by_user_id) REFERENCES users (id),
  CONSTRAINT fk_tenant_role_permission_grants_updated_by_user
    FOREIGN KEY (updated_by_user_id) REFERENCES users (id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
