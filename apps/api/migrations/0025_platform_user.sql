CREATE TABLE IF NOT EXISTS platform_users (
  user_id VARCHAR(64) NOT NULL,
  name VARCHAR(64) NULL,
  department VARCHAR(128) NULL,
  status VARCHAR(16) NOT NULL DEFAULT 'active',
  created_at TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  updated_at TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3) ON UPDATE CURRENT_TIMESTAMP(3),
  PRIMARY KEY (user_id),
  KEY idx_platform_users_status (status),
  CONSTRAINT fk_platform_users_user_id
    FOREIGN KEY (user_id) REFERENCES iam_users (id)
    ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

ALTER TABLE platform_users
  MODIFY COLUMN name VARCHAR(64) NULL;

ALTER TABLE platform_users
  MODIFY COLUMN department VARCHAR(128) NULL;

SET @platform_users_has_status := (
  SELECT COUNT(*)
  FROM information_schema.columns
  WHERE table_schema = DATABASE()
    AND table_name = 'platform_users'
    AND column_name = 'status'
);

SET @platform_users_add_status_sql := IF(
  @platform_users_has_status = 0,
  'ALTER TABLE platform_users ADD COLUMN status VARCHAR(16) NOT NULL DEFAULT ''active''',
  'SELECT 1'
);

PREPARE platform_users_add_status_stmt FROM @platform_users_add_status_sql;
EXECUTE platform_users_add_status_stmt;
DEALLOCATE PREPARE platform_users_add_status_stmt;
