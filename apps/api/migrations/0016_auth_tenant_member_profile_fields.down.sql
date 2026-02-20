ALTER TABLE auth_user_tenants
  DROP COLUMN IF EXISTS department_name,
  DROP COLUMN IF EXISTS display_name;
