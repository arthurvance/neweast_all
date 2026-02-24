DROP TABLE IF EXISTS auth_user_tenant_membership_history;

SET @uk_auth_user_tenants_membership_id_exists = (
  SELECT COUNT(*)
  FROM information_schema.statistics
  WHERE table_schema = DATABASE()
    AND table_name = 'tenant_memberships'
    AND index_name = 'uk_auth_user_tenants_membership_id'
);
SET @uk_auth_user_tenants_membership_id_drop_sql = IF(
  @uk_auth_user_tenants_membership_id_exists = 1,
  'ALTER TABLE tenant_memberships DROP INDEX uk_auth_user_tenants_membership_id',
  'SELECT 1'
);
PREPARE uk_auth_user_tenants_membership_id_drop_stmt FROM @uk_auth_user_tenants_membership_id_drop_sql;
EXECUTE uk_auth_user_tenants_membership_id_drop_stmt;
DEALLOCATE PREPARE uk_auth_user_tenants_membership_id_drop_stmt;

SET @idx_auth_user_tenants_tenant_status_exists = (
  SELECT COUNT(*)
  FROM information_schema.statistics
  WHERE table_schema = DATABASE()
    AND table_name = 'tenant_memberships'
    AND index_name = 'idx_auth_user_tenants_tenant_status'
);
SET @idx_auth_user_tenants_tenant_status_drop_sql = IF(
  @idx_auth_user_tenants_tenant_status_exists = 1,
  'ALTER TABLE tenant_memberships DROP INDEX idx_auth_user_tenants_tenant_status',
  'SELECT 1'
);
PREPARE idx_auth_user_tenants_tenant_status_drop_stmt FROM @idx_auth_user_tenants_tenant_status_drop_sql;
EXECUTE idx_auth_user_tenants_tenant_status_drop_stmt;
DEALLOCATE PREPARE idx_auth_user_tenants_tenant_status_drop_stmt;

ALTER TABLE tenant_memberships
  DROP COLUMN IF EXISTS left_at,
  DROP COLUMN IF EXISTS joined_at,
  DROP COLUMN IF EXISTS membership_id;
