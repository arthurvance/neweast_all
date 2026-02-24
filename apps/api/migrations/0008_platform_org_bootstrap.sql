CREATE TABLE IF NOT EXISTS tenants (
  id CHAR(36) NOT NULL,
  name VARCHAR(128) NOT NULL,
  owner_user_id VARCHAR(64) NOT NULL,
  status ENUM('active', 'disabled') NOT NULL DEFAULT 'active',
  created_by_user_id VARCHAR(64) NOT NULL,
  created_at TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  updated_at TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3) ON UPDATE CURRENT_TIMESTAMP(3),
  PRIMARY KEY (id),
  UNIQUE KEY uk_tenants_name (name),
  KEY idx_tenants_owner_user_id (owner_user_id),
  KEY idx_tenants_status (status),
  CONSTRAINT fk_tenants_owner_user FOREIGN KEY (owner_user_id) REFERENCES iam_users (id),
  CONSTRAINT fk_tenants_created_by_user FOREIGN KEY (created_by_user_id) REFERENCES iam_users (id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
