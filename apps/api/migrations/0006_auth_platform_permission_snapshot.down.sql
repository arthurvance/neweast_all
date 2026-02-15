SET @column_exists := (
  SELECT COUNT(*)
  FROM information_schema.columns
  WHERE table_schema = DATABASE()
    AND table_name = 'auth_user_domain_access'
    AND column_name = 'can_operate_billing'
);
SET @ddl_sql := IF(
  @column_exists = 0,
  'SELECT 1',
  'ALTER TABLE auth_user_domain_access DROP COLUMN can_operate_billing'
);
PREPARE migration_stmt FROM @ddl_sql;
EXECUTE migration_stmt;
DEALLOCATE PREPARE migration_stmt;

SET @column_exists := (
  SELECT COUNT(*)
  FROM information_schema.columns
  WHERE table_schema = DATABASE()
    AND table_name = 'auth_user_domain_access'
    AND column_name = 'can_view_billing'
);
SET @ddl_sql := IF(
  @column_exists = 0,
  'SELECT 1',
  'ALTER TABLE auth_user_domain_access DROP COLUMN can_view_billing'
);
PREPARE migration_stmt FROM @ddl_sql;
EXECUTE migration_stmt;
DEALLOCATE PREPARE migration_stmt;

SET @column_exists := (
  SELECT COUNT(*)
  FROM information_schema.columns
  WHERE table_schema = DATABASE()
    AND table_name = 'auth_user_domain_access'
    AND column_name = 'can_operate_member_admin'
);
SET @ddl_sql := IF(
  @column_exists = 0,
  'SELECT 1',
  'ALTER TABLE auth_user_domain_access DROP COLUMN can_operate_member_admin'
);
PREPARE migration_stmt FROM @ddl_sql;
EXECUTE migration_stmt;
DEALLOCATE PREPARE migration_stmt;

SET @column_exists := (
  SELECT COUNT(*)
  FROM information_schema.columns
  WHERE table_schema = DATABASE()
    AND table_name = 'auth_user_domain_access'
    AND column_name = 'can_view_member_admin'
);
SET @ddl_sql := IF(
  @column_exists = 0,
  'SELECT 1',
  'ALTER TABLE auth_user_domain_access DROP COLUMN can_view_member_admin'
);
PREPARE migration_stmt FROM @ddl_sql;
EXECUTE migration_stmt;
DEALLOCATE PREPARE migration_stmt;
