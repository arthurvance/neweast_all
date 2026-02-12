SET @idx_auth_sessions_entry_domain_exists = (
  SELECT COUNT(1)
  FROM information_schema.statistics
  WHERE table_schema = DATABASE()
    AND table_name = 'auth_sessions'
    AND index_name = 'idx_auth_sessions_entry_domain'
);
SET @idx_auth_sessions_entry_domain_drop_sql = IF(
  @idx_auth_sessions_entry_domain_exists = 1,
  'DROP INDEX idx_auth_sessions_entry_domain ON auth_sessions',
  'SELECT 1'
);
PREPARE idx_auth_sessions_entry_domain_drop_stmt FROM @idx_auth_sessions_entry_domain_drop_sql;
EXECUTE idx_auth_sessions_entry_domain_drop_stmt;
DEALLOCATE PREPARE idx_auth_sessions_entry_domain_drop_stmt;

SET @idx_auth_sessions_active_tenant_id_exists = (
  SELECT COUNT(1)
  FROM information_schema.statistics
  WHERE table_schema = DATABASE()
    AND table_name = 'auth_sessions'
    AND index_name = 'idx_auth_sessions_active_tenant_id'
);
SET @idx_auth_sessions_active_tenant_id_drop_sql = IF(
  @idx_auth_sessions_active_tenant_id_exists = 1,
  'DROP INDEX idx_auth_sessions_active_tenant_id ON auth_sessions',
  'SELECT 1'
);
PREPARE idx_auth_sessions_active_tenant_id_drop_stmt FROM @idx_auth_sessions_active_tenant_id_drop_sql;
EXECUTE idx_auth_sessions_active_tenant_id_drop_stmt;
DEALLOCATE PREPARE idx_auth_sessions_active_tenant_id_drop_stmt;

ALTER TABLE auth_sessions
  DROP COLUMN IF EXISTS active_tenant_id,
  DROP COLUMN IF EXISTS entry_domain;
