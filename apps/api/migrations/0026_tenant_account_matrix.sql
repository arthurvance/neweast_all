CREATE TABLE IF NOT EXISTS tenant_accounts (
  account_id VARCHAR(64) NOT NULL,
  tenant_id VARCHAR(64) NOT NULL,
  wechat_id VARCHAR(128) NOT NULL,
  nickname VARCHAR(128) NOT NULL,
  owner_membership_id VARCHAR(64) NOT NULL,
  customer_count INT UNSIGNED NOT NULL DEFAULT 0,
  group_chat_count INT UNSIGNED NOT NULL DEFAULT 0,
  status VARCHAR(16) NOT NULL DEFAULT 'enabled',
  avatar_url VARCHAR(512) NULL,
  created_by_user_id VARCHAR(64) NULL,
  updated_by_user_id VARCHAR(64) NULL,
  created_at TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  updated_at TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3) ON UPDATE CURRENT_TIMESTAMP(3),
  PRIMARY KEY (account_id),
  UNIQUE KEY uk_tenant_accounts_tenant_wechat (tenant_id, wechat_id),
  KEY idx_tenant_accounts_tenant_created_at (tenant_id, created_at),
  KEY idx_tenant_accounts_tenant_status_created_at (tenant_id, status, created_at),
  KEY idx_tenant_accounts_owner_membership_id (owner_membership_id),
  CONSTRAINT fk_tenant_accounts_owner_membership_id
    FOREIGN KEY (owner_membership_id) REFERENCES tenant_memberships (membership_id),
  CONSTRAINT fk_tenant_accounts_created_by_user
    FOREIGN KEY (created_by_user_id) REFERENCES iam_users (id),
  CONSTRAINT fk_tenant_accounts_updated_by_user
    FOREIGN KEY (updated_by_user_id) REFERENCES iam_users (id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS tenant_account_assistants (
  account_id VARCHAR(64) NOT NULL,
  assistant_membership_id VARCHAR(64) NOT NULL,
  created_by_user_id VARCHAR(64) NULL,
  updated_by_user_id VARCHAR(64) NULL,
  created_at TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  updated_at TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3) ON UPDATE CURRENT_TIMESTAMP(3),
  PRIMARY KEY (account_id, assistant_membership_id),
  KEY idx_tenant_account_assistants_membership_id_account_id (assistant_membership_id, account_id),
  CONSTRAINT fk_tenant_account_assistants_account_id
    FOREIGN KEY (account_id) REFERENCES tenant_accounts (account_id)
    ON DELETE CASCADE,
  CONSTRAINT fk_tenant_account_assistants_membership_id
    FOREIGN KEY (assistant_membership_id) REFERENCES tenant_memberships (membership_id),
  CONSTRAINT fk_tenant_account_assistants_created_by_user
    FOREIGN KEY (created_by_user_id) REFERENCES iam_users (id),
  CONSTRAINT fk_tenant_account_assistants_updated_by_user
    FOREIGN KEY (updated_by_user_id) REFERENCES iam_users (id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS tenant_account_operation_logs (
  operation_id VARCHAR(64) NOT NULL,
  account_id VARCHAR(64) NOT NULL,
  tenant_id VARCHAR(64) NOT NULL,
  operation_type VARCHAR(64) NOT NULL,
  operation_content VARCHAR(1024) NULL,
  operator_user_id VARCHAR(64) NULL,
  operator_name VARCHAR(128) NULL,
  operation_time TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  created_at TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  PRIMARY KEY (operation_id),
  KEY idx_tenant_account_operation_logs_account_time (tenant_id, account_id, operation_time),
  KEY idx_tenant_account_operation_logs_operator_user_id (operator_user_id),
  CONSTRAINT fk_tenant_account_operation_logs_account_id
    FOREIGN KEY (account_id) REFERENCES tenant_accounts (account_id)
    ON DELETE CASCADE,
  CONSTRAINT fk_tenant_account_operation_logs_operator_user
    FOREIGN KEY (operator_user_id) REFERENCES iam_users (id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
