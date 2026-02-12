SET @auth_sessions_entry_domain_exists = (
  SELECT COUNT(1)
  FROM information_schema.columns
  WHERE table_schema = DATABASE()
    AND table_name = 'auth_sessions'
    AND column_name = 'entry_domain'
);
SET @auth_sessions_entry_domain_sql = IF(
  @auth_sessions_entry_domain_exists = 0,
  'ALTER TABLE auth_sessions ADD COLUMN entry_domain VARCHAR(16) NOT NULL DEFAULT ''platform'' AFTER session_version',
  'SELECT 1'
);
PREPARE auth_sessions_entry_domain_stmt FROM @auth_sessions_entry_domain_sql;
EXECUTE auth_sessions_entry_domain_stmt;
DEALLOCATE PREPARE auth_sessions_entry_domain_stmt;

SET @auth_sessions_active_tenant_id_exists = (
  SELECT COUNT(1)
  FROM information_schema.columns
  WHERE table_schema = DATABASE()
    AND table_name = 'auth_sessions'
    AND column_name = 'active_tenant_id'
);
SET @auth_sessions_active_tenant_id_sql = IF(
  @auth_sessions_active_tenant_id_exists = 0,
  'ALTER TABLE auth_sessions ADD COLUMN active_tenant_id VARCHAR(64) NULL AFTER entry_domain',
  'SELECT 1'
);
PREPARE auth_sessions_active_tenant_id_stmt FROM @auth_sessions_active_tenant_id_sql;
EXECUTE auth_sessions_active_tenant_id_stmt;
DEALLOCATE PREPARE auth_sessions_active_tenant_id_stmt;

SET @idx_auth_sessions_entry_domain_exists = (
  SELECT COUNT(1)
  FROM information_schema.statistics
  WHERE table_schema = DATABASE()
    AND table_name = 'auth_sessions'
    AND index_name = 'idx_auth_sessions_entry_domain'
);
SET @idx_auth_sessions_entry_domain_sql = IF(
  @idx_auth_sessions_entry_domain_exists = 0,
  'CREATE INDEX idx_auth_sessions_entry_domain ON auth_sessions (entry_domain)',
  'SELECT 1'
);
PREPARE idx_auth_sessions_entry_domain_stmt FROM @idx_auth_sessions_entry_domain_sql;
EXECUTE idx_auth_sessions_entry_domain_stmt;
DEALLOCATE PREPARE idx_auth_sessions_entry_domain_stmt;

SET @idx_auth_sessions_active_tenant_id_exists = (
  SELECT COUNT(1)
  FROM information_schema.statistics
  WHERE table_schema = DATABASE()
    AND table_name = 'auth_sessions'
    AND index_name = 'idx_auth_sessions_active_tenant_id'
);
SET @idx_auth_sessions_active_tenant_id_sql = IF(
  @idx_auth_sessions_active_tenant_id_exists = 0,
  'CREATE INDEX idx_auth_sessions_active_tenant_id ON auth_sessions (active_tenant_id)',
  'SELECT 1'
);
PREPARE idx_auth_sessions_active_tenant_id_stmt FROM @idx_auth_sessions_active_tenant_id_sql;
EXECUTE idx_auth_sessions_active_tenant_id_stmt;
DEALLOCATE PREPARE idx_auth_sessions_active_tenant_id_stmt;
