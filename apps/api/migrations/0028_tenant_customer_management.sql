CREATE TABLE IF NOT EXISTS tenant_customers (
  customer_id VARCHAR(64) NOT NULL,
  tenant_id VARCHAR(64) NOT NULL,
  account_id VARCHAR(64) NOT NULL,
  wechat_id VARCHAR(128) NULL,
  nickname VARCHAR(128) NOT NULL,
  source VARCHAR(16) NOT NULL,
  status VARCHAR(16) NOT NULL DEFAULT 'enabled',
  created_by_user_id VARCHAR(64) NULL,
  updated_by_user_id VARCHAR(64) NULL,
  created_at TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  updated_at TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3) ON UPDATE CURRENT_TIMESTAMP(3),
  PRIMARY KEY (customer_id),
  UNIQUE KEY uk_tenant_customers_tenant_wechat (tenant_id, wechat_id),
  KEY idx_tenant_customers_tenant_account_created (tenant_id, account_id, created_at),
  KEY idx_tenant_customers_tenant_status_created (tenant_id, status, created_at),
  KEY idx_tenant_customers_tenant_source_created (tenant_id, source, created_at),
  CONSTRAINT fk_tenant_customers_account_id
    FOREIGN KEY (account_id) REFERENCES tenant_accounts (account_id)
    ON DELETE CASCADE,
  CONSTRAINT fk_tenant_customers_created_by_user
    FOREIGN KEY (created_by_user_id) REFERENCES iam_users (id),
  CONSTRAINT fk_tenant_customers_updated_by_user
    FOREIGN KEY (updated_by_user_id) REFERENCES iam_users (id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS tenant_customer_profiles (
  customer_id VARCHAR(64) NOT NULL,
  tenant_id VARCHAR(64) NOT NULL,
  real_name VARCHAR(64) NULL,
  school VARCHAR(128) NULL,
  class_name VARCHAR(128) NULL,
  relation VARCHAR(128) NULL,
  phone VARCHAR(32) NULL,
  address VARCHAR(255) NULL,
  created_at TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  updated_at TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3) ON UPDATE CURRENT_TIMESTAMP(3),
  PRIMARY KEY (customer_id),
  KEY idx_tenant_customer_profiles_tenant_real_name (tenant_id, real_name),
  KEY idx_tenant_customer_profiles_tenant_phone (tenant_id, phone),
  CONSTRAINT fk_tenant_customer_profiles_customer_id
    FOREIGN KEY (customer_id) REFERENCES tenant_customers (customer_id)
    ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS tenant_customer_operation_logs (
  operation_id VARCHAR(64) NOT NULL,
  tenant_id VARCHAR(64) NOT NULL,
  customer_id VARCHAR(64) NOT NULL,
  operation_type VARCHAR(64) NOT NULL,
  operation_content VARCHAR(2048) NULL,
  operator_user_id VARCHAR(64) NULL,
  operator_name VARCHAR(128) NULL,
  operation_time TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  created_at TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  PRIMARY KEY (operation_id),
  KEY idx_tenant_customer_logs_customer_time (tenant_id, customer_id, operation_time),
  KEY idx_tenant_customer_logs_operator_user_id (operator_user_id),
  CONSTRAINT fk_tenant_customer_operation_logs_customer_id
    FOREIGN KEY (customer_id) REFERENCES tenant_customers (customer_id)
    ON DELETE CASCADE,
  CONSTRAINT fk_tenant_customer_operation_logs_operator_user
    FOREIGN KEY (operator_user_id) REFERENCES iam_users (id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
