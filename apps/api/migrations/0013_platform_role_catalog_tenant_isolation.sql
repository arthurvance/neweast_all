SET @platform_roles_tenant_id_exists = (
  SELECT COUNT(*)
  FROM information_schema.columns
  WHERE table_schema = DATABASE()
    AND table_name = 'platform_roles'
    AND column_name = 'tenant_id'
);
SET @platform_roles_tenant_id_sql = IF(
  @platform_roles_tenant_id_exists = 0,
  'ALTER TABLE platform_roles ADD COLUMN tenant_id VARCHAR(64) NOT NULL DEFAULT '''' AFTER scope',
  'SELECT 1'
);
PREPARE platform_roles_tenant_id_stmt FROM @platform_roles_tenant_id_sql;
EXECUTE platform_roles_tenant_id_stmt;
DEALLOCATE PREPARE platform_roles_tenant_id_stmt;

UPDATE platform_roles
SET tenant_id = ''
WHERE tenant_id IS NULL;

SET @idx_platform_roles_scope_tenant_status_exists = (
  SELECT COUNT(*)
  FROM information_schema.statistics
  WHERE table_schema = DATABASE()
    AND table_name = 'platform_roles'
    AND index_name = 'idx_platform_roles_scope_tenant_status'
);
SET @idx_platform_roles_scope_tenant_status_sql = IF(
  @idx_platform_roles_scope_tenant_status_exists = 0,
  'ALTER TABLE platform_roles ADD KEY idx_platform_roles_scope_tenant_status (scope, tenant_id, status)',
  'SELECT 1'
);
PREPARE idx_platform_roles_scope_tenant_status_stmt
  FROM @idx_platform_roles_scope_tenant_status_sql;
EXECUTE idx_platform_roles_scope_tenant_status_stmt;
DEALLOCATE PREPARE idx_platform_roles_scope_tenant_status_stmt;

SET @uk_platform_roles_code_normalized_exists = (
  SELECT COUNT(*)
  FROM information_schema.statistics
  WHERE table_schema = DATABASE()
    AND table_name = 'platform_roles'
    AND index_name = 'uk_platform_roles_code_normalized'
);
SET @uk_platform_roles_code_normalized_drop_sql = IF(
  @uk_platform_roles_code_normalized_exists = 1,
  'ALTER TABLE platform_roles DROP INDEX uk_platform_roles_code_normalized',
  'SELECT 1'
);
PREPARE uk_platform_roles_code_normalized_drop_stmt
  FROM @uk_platform_roles_code_normalized_drop_sql;
EXECUTE uk_platform_roles_code_normalized_drop_stmt;
DEALLOCATE PREPARE uk_platform_roles_code_normalized_drop_stmt;

SET @uk_platform_roles_scope_tenant_code_normalized_exists = (
  SELECT COUNT(*)
  FROM information_schema.statistics
  WHERE table_schema = DATABASE()
    AND table_name = 'platform_roles'
    AND index_name = 'uk_platform_roles_scope_tenant_code_normalized'
);
SET @uk_platform_roles_scope_tenant_code_normalized_sql = IF(
  @uk_platform_roles_scope_tenant_code_normalized_exists = 0,
  'ALTER TABLE platform_roles ADD UNIQUE KEY uk_platform_roles_scope_tenant_code_normalized (scope, tenant_id, code_normalized)',
  'SELECT 1'
);
PREPARE uk_platform_roles_scope_tenant_code_normalized_stmt
  FROM @uk_platform_roles_scope_tenant_code_normalized_sql;
EXECUTE uk_platform_roles_scope_tenant_code_normalized_stmt;
DEALLOCATE PREPARE uk_platform_roles_scope_tenant_code_normalized_stmt;
