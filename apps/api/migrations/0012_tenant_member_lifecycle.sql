SET @auth_user_tenants_membership_id_exists = (
  SELECT COUNT(*)
  FROM information_schema.columns
  WHERE table_schema = DATABASE()
    AND table_name = 'tenant_memberships'
    AND column_name = 'membership_id'
);
SET @auth_user_tenants_membership_id_sql = IF(
  @auth_user_tenants_membership_id_exists = 0,
  'ALTER TABLE tenant_memberships ADD COLUMN membership_id VARCHAR(64) NULL AFTER id',
  'SELECT 1'
);
PREPARE auth_user_tenants_membership_id_stmt FROM @auth_user_tenants_membership_id_sql;
EXECUTE auth_user_tenants_membership_id_stmt;
DEALLOCATE PREPARE auth_user_tenants_membership_id_stmt;

SET @auth_user_tenants_joined_at_exists = (
  SELECT COUNT(*)
  FROM information_schema.columns
  WHERE table_schema = DATABASE()
    AND table_name = 'tenant_memberships'
    AND column_name = 'joined_at'
);
SET @auth_user_tenants_joined_at_sql = IF(
  @auth_user_tenants_joined_at_exists = 0,
  'ALTER TABLE tenant_memberships ADD COLUMN joined_at TIMESTAMP(3) NULL AFTER status',
  'SELECT 1'
);
PREPARE auth_user_tenants_joined_at_stmt FROM @auth_user_tenants_joined_at_sql;
EXECUTE auth_user_tenants_joined_at_stmt;
DEALLOCATE PREPARE auth_user_tenants_joined_at_stmt;

SET @auth_user_tenants_left_at_exists = (
  SELECT COUNT(*)
  FROM information_schema.columns
  WHERE table_schema = DATABASE()
    AND table_name = 'tenant_memberships'
    AND column_name = 'left_at'
);
SET @auth_user_tenants_left_at_sql = IF(
  @auth_user_tenants_left_at_exists = 0,
  'ALTER TABLE tenant_memberships ADD COLUMN left_at TIMESTAMP(3) NULL AFTER joined_at',
  'SELECT 1'
);
PREPARE auth_user_tenants_left_at_stmt FROM @auth_user_tenants_left_at_sql;
EXECUTE auth_user_tenants_left_at_stmt;
DEALLOCATE PREPARE auth_user_tenants_left_at_stmt;

UPDATE tenant_memberships
SET membership_id = LOWER(REPLACE(UUID(), '-', ''))
WHERE membership_id IS NULL OR TRIM(membership_id) = '';

UPDATE tenant_memberships
SET joined_at = COALESCE(joined_at, created_at, CURRENT_TIMESTAMP(3))
WHERE joined_at IS NULL;

SET @auth_user_tenants_membership_id_nullable = (
  SELECT is_nullable
  FROM information_schema.columns
  WHERE table_schema = DATABASE()
    AND table_name = 'tenant_memberships'
    AND column_name = 'membership_id'
  LIMIT 1
);
SET @auth_user_tenants_membership_id_not_null_sql = IF(
  @auth_user_tenants_membership_id_nullable = 'YES',
  'ALTER TABLE tenant_memberships MODIFY COLUMN membership_id VARCHAR(64) NOT NULL',
  'SELECT 1'
);
PREPARE auth_user_tenants_membership_id_not_null_stmt
  FROM @auth_user_tenants_membership_id_not_null_sql;
EXECUTE auth_user_tenants_membership_id_not_null_stmt;
DEALLOCATE PREPARE auth_user_tenants_membership_id_not_null_stmt;

SET @uk_auth_user_tenants_membership_id_exists = (
  SELECT COUNT(*)
  FROM information_schema.statistics
  WHERE table_schema = DATABASE()
    AND table_name = 'tenant_memberships'
    AND index_name = 'uk_auth_user_tenants_membership_id'
);
SET @uk_auth_user_tenants_membership_id_sql = IF(
  @uk_auth_user_tenants_membership_id_exists = 0,
  'ALTER TABLE tenant_memberships ADD UNIQUE KEY uk_auth_user_tenants_membership_id (membership_id)',
  'SELECT 1'
);
PREPARE uk_auth_user_tenants_membership_id_stmt FROM @uk_auth_user_tenants_membership_id_sql;
EXECUTE uk_auth_user_tenants_membership_id_stmt;
DEALLOCATE PREPARE uk_auth_user_tenants_membership_id_stmt;

SET @idx_auth_user_tenants_tenant_status_exists = (
  SELECT COUNT(*)
  FROM information_schema.statistics
  WHERE table_schema = DATABASE()
    AND table_name = 'tenant_memberships'
    AND index_name = 'idx_auth_user_tenants_tenant_status'
);
SET @idx_auth_user_tenants_tenant_status_sql = IF(
  @idx_auth_user_tenants_tenant_status_exists = 0,
  'ALTER TABLE tenant_memberships ADD KEY idx_auth_user_tenants_tenant_status (tenant_id, status)',
  'SELECT 1'
);
PREPARE idx_auth_user_tenants_tenant_status_stmt FROM @idx_auth_user_tenants_tenant_status_sql;
EXECUTE idx_auth_user_tenants_tenant_status_stmt;
DEALLOCATE PREPARE idx_auth_user_tenants_tenant_status_stmt;

CREATE TABLE IF NOT EXISTS auth_user_tenant_membership_history (
  id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  membership_id VARCHAR(64) NOT NULL,
  user_id VARCHAR(64) NOT NULL,
  tenant_id VARCHAR(64) NOT NULL,
  tenant_name VARCHAR(128) NULL,
  status VARCHAR(16) NOT NULL,
  can_view_user_management TINYINT(1) NOT NULL DEFAULT 0,
  can_operate_user_management TINYINT(1) NOT NULL DEFAULT 0,
  can_view_role_management TINYINT(1) NOT NULL DEFAULT 0,
  can_operate_role_management TINYINT(1) NOT NULL DEFAULT 0,
  joined_at TIMESTAMP(3) NULL,
  left_at TIMESTAMP(3) NULL,
  archived_reason VARCHAR(256) NULL,
  archived_by_user_id VARCHAR(64) NULL,
  archived_at TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  PRIMARY KEY (id),
  KEY idx_auth_user_tenant_membership_history_user_tenant (user_id, tenant_id),
  KEY idx_auth_user_tenant_membership_history_membership_id (membership_id),
  KEY idx_auth_user_tenant_membership_history_archived_at (archived_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
