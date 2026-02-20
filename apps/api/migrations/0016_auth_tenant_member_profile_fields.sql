SET @auth_user_tenants_display_name_exists = (
  SELECT COUNT(*)
  FROM information_schema.columns
  WHERE table_schema = DATABASE()
    AND table_name = 'auth_user_tenants'
    AND column_name = 'display_name'
);
SET @auth_user_tenants_display_name_sql = IF(
  @auth_user_tenants_display_name_exists = 0,
  'ALTER TABLE auth_user_tenants ADD COLUMN display_name VARCHAR(64) NULL AFTER tenant_name',
  'SELECT 1'
);
PREPARE auth_user_tenants_display_name_stmt FROM @auth_user_tenants_display_name_sql;
EXECUTE auth_user_tenants_display_name_stmt;
DEALLOCATE PREPARE auth_user_tenants_display_name_stmt;

SET @auth_user_tenants_department_name_exists = (
  SELECT COUNT(*)
  FROM information_schema.columns
  WHERE table_schema = DATABASE()
    AND table_name = 'auth_user_tenants'
    AND column_name = 'department_name'
);
SET @auth_user_tenants_department_name_sql = IF(
  @auth_user_tenants_department_name_exists = 0,
  'ALTER TABLE auth_user_tenants ADD COLUMN department_name VARCHAR(128) NULL AFTER display_name',
  'SELECT 1'
);
PREPARE auth_user_tenants_department_name_stmt
  FROM @auth_user_tenants_department_name_sql;
EXECUTE auth_user_tenants_department_name_stmt;
DEALLOCATE PREPARE auth_user_tenants_department_name_stmt;
