ALTER TABLE tenant_memberships
  DROP COLUMN IF EXISTS department_name,
  DROP COLUMN IF EXISTS display_name;
