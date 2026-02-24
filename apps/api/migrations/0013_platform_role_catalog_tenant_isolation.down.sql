SET @uk_platform_roles_scope_tenant_code_normalized_exists = (
  SELECT COUNT(*)
  FROM information_schema.statistics
  WHERE table_schema = DATABASE()
    AND table_name = 'platform_roles'
    AND index_name = 'uk_platform_roles_scope_tenant_code_normalized'
);
SET @uk_platform_roles_scope_tenant_code_normalized_drop_sql = IF(
  @uk_platform_roles_scope_tenant_code_normalized_exists = 1,
  'ALTER TABLE platform_roles DROP INDEX uk_platform_roles_scope_tenant_code_normalized',
  'SELECT 1'
);
PREPARE uk_platform_roles_scope_tenant_code_normalized_drop_stmt
  FROM @uk_platform_roles_scope_tenant_code_normalized_drop_sql;
EXECUTE uk_platform_roles_scope_tenant_code_normalized_drop_stmt;
DEALLOCATE PREPARE uk_platform_roles_scope_tenant_code_normalized_drop_stmt;

SET @idx_platform_roles_scope_tenant_status_exists = (
  SELECT COUNT(*)
  FROM information_schema.statistics
  WHERE table_schema = DATABASE()
    AND table_name = 'platform_roles'
    AND index_name = 'idx_platform_roles_scope_tenant_status'
);
SET @idx_platform_roles_scope_tenant_status_drop_sql = IF(
  @idx_platform_roles_scope_tenant_status_exists = 1,
  'ALTER TABLE platform_roles DROP INDEX idx_platform_roles_scope_tenant_status',
  'SELECT 1'
);
PREPARE idx_platform_roles_scope_tenant_status_drop_stmt
  FROM @idx_platform_roles_scope_tenant_status_drop_sql;
EXECUTE idx_platform_roles_scope_tenant_status_drop_stmt;
DEALLOCATE PREPARE idx_platform_roles_scope_tenant_status_drop_stmt;

DELETE FROM platform_roles
WHERE scope = 'tenant';

SET @uk_platform_roles_code_normalized_exists = (
  SELECT COUNT(*)
  FROM information_schema.statistics
  WHERE table_schema = DATABASE()
    AND table_name = 'platform_roles'
    AND index_name = 'uk_platform_roles_code_normalized'
);
SET @uk_platform_roles_code_normalized_sql = IF(
  @uk_platform_roles_code_normalized_exists = 0,
  'ALTER TABLE platform_roles ADD UNIQUE KEY uk_platform_roles_code_normalized (code_normalized)',
  'SELECT 1'
);
PREPARE uk_platform_roles_code_normalized_stmt
  FROM @uk_platform_roles_code_normalized_sql;
EXECUTE uk_platform_roles_code_normalized_stmt;
DEALLOCATE PREPARE uk_platform_roles_code_normalized_stmt;

ALTER TABLE platform_roles
  DROP COLUMN IF EXISTS tenant_id;
