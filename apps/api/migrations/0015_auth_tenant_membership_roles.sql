CREATE TABLE IF NOT EXISTS tenant_membership_roles (
  membership_id VARCHAR(64) NOT NULL,
  role_id VARCHAR(64) NOT NULL,
  created_by_user_id VARCHAR(64) NULL,
  updated_by_user_id VARCHAR(64) NULL,
  created_at TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  updated_at TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3) ON UPDATE CURRENT_TIMESTAMP(3),
  PRIMARY KEY (membership_id, role_id),
  KEY idx_tenant_membership_roles_role_id_membership_id (role_id, membership_id),
  CONSTRAINT fk_tenant_membership_roles_membership_id
    FOREIGN KEY (membership_id) REFERENCES tenant_memberships (membership_id)
    ON DELETE CASCADE,
  CONSTRAINT fk_tenant_membership_roles_role_id
    FOREIGN KEY (role_id) REFERENCES platform_roles (role_id)
    ON DELETE CASCADE,
  CONSTRAINT fk_tenant_membership_roles_created_by_user
    FOREIGN KEY (created_by_user_id) REFERENCES iam_users (id),
  CONSTRAINT fk_tenant_membership_roles_updated_by_user
    FOREIGN KEY (updated_by_user_id) REFERENCES iam_users (id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
