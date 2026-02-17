CREATE TABLE IF NOT EXISTS orgs (
  id CHAR(36) NOT NULL,
  name VARCHAR(128) NOT NULL,
  owner_user_id VARCHAR(64) NOT NULL,
  status ENUM('active', 'disabled') NOT NULL DEFAULT 'active',
  created_by_user_id VARCHAR(64) NOT NULL,
  created_at TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  updated_at TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3) ON UPDATE CURRENT_TIMESTAMP(3),
  PRIMARY KEY (id),
  UNIQUE KEY uk_orgs_name (name),
  KEY idx_orgs_owner_user_id (owner_user_id),
  KEY idx_orgs_status (status),
  CONSTRAINT fk_orgs_owner_user FOREIGN KEY (owner_user_id) REFERENCES users (id),
  CONSTRAINT fk_orgs_created_by_user FOREIGN KEY (created_by_user_id) REFERENCES users (id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS memberships (
  id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  org_id CHAR(36) NOT NULL,
  user_id VARCHAR(64) NOT NULL,
  membership_role ENUM('owner', 'admin', 'member') NOT NULL DEFAULT 'member',
  status ENUM('active', 'disabled') NOT NULL DEFAULT 'active',
  created_at TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  updated_at TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3) ON UPDATE CURRENT_TIMESTAMP(3),
  PRIMARY KEY (id),
  UNIQUE KEY uk_memberships_org_user (org_id, user_id),
  KEY idx_memberships_user_status (user_id, status),
  KEY idx_memberships_org_role (org_id, membership_role),
  CONSTRAINT fk_memberships_org FOREIGN KEY (org_id) REFERENCES orgs (id) ON DELETE CASCADE,
  CONSTRAINT fk_memberships_user FOREIGN KEY (user_id) REFERENCES users (id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
