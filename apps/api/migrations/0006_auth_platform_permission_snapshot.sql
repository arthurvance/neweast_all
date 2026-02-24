SET @column_exists := (
  SELECT COUNT(*)
  FROM information_schema.columns
  WHERE table_schema = DATABASE()
    AND table_name = 'auth_user_domain_access'
    AND column_name = 'can_view_user_management'
);
SET @ddl_sql := IF(
  @column_exists = 0,
  'ALTER TABLE auth_user_domain_access ADD COLUMN can_view_user_management TINYINT(1) NOT NULL DEFAULT 0',
  'SELECT 1'
);
PREPARE migration_stmt FROM @ddl_sql;
EXECUTE migration_stmt;
DEALLOCATE PREPARE migration_stmt;

SET @column_exists := (
  SELECT COUNT(*)
  FROM information_schema.columns
  WHERE table_schema = DATABASE()
    AND table_name = 'auth_user_domain_access'
    AND column_name = 'can_operate_user_management'
);
SET @ddl_sql := IF(
  @column_exists = 0,
  'ALTER TABLE auth_user_domain_access ADD COLUMN can_operate_user_management TINYINT(1) NOT NULL DEFAULT 0',
  'SELECT 1'
);
PREPARE migration_stmt FROM @ddl_sql;
EXECUTE migration_stmt;
DEALLOCATE PREPARE migration_stmt;

SET @column_exists := (
  SELECT COUNT(*)
  FROM information_schema.columns
  WHERE table_schema = DATABASE()
    AND table_name = 'auth_user_domain_access'
    AND column_name = 'can_view_organization_management'
);
SET @ddl_sql := IF(
  @column_exists = 0,
  'ALTER TABLE auth_user_domain_access ADD COLUMN can_view_organization_management TINYINT(1) NOT NULL DEFAULT 0',
  'SELECT 1'
);
PREPARE migration_stmt FROM @ddl_sql;
EXECUTE migration_stmt;
DEALLOCATE PREPARE migration_stmt;

SET @column_exists := (
  SELECT COUNT(*)
  FROM information_schema.columns
  WHERE table_schema = DATABASE()
    AND table_name = 'auth_user_domain_access'
    AND column_name = 'can_operate_organization_management'
);
SET @ddl_sql := IF(
  @column_exists = 0,
  'ALTER TABLE auth_user_domain_access ADD COLUMN can_operate_organization_management TINYINT(1) NOT NULL DEFAULT 0',
  'SELECT 1'
);
PREPARE migration_stmt FROM @ddl_sql;
EXECUTE migration_stmt;
DEALLOCATE PREPARE migration_stmt;
