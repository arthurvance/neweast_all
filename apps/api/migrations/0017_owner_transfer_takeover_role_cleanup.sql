DROP TEMPORARY TABLE IF EXISTS tmp_owner_takeover_legacy_membership_targets;
DROP TEMPORARY TABLE IF EXISTS tmp_owner_takeover_legacy_tenants;
DROP TEMPORARY TABLE IF EXISTS tmp_owner_takeover_legacy_memberships;

CREATE TEMPORARY TABLE IF NOT EXISTS tmp_owner_takeover_legacy_memberships AS
SELECT DISTINCT
  ut.membership_id,
  ut.tenant_id
FROM auth_tenant_membership_roles mr
JOIN auth_user_tenants ut ON ut.membership_id = mr.membership_id
WHERE mr.role_id = 'tenant_owner'
  AND ut.tenant_id IS NOT NULL
  AND ut.tenant_id <> '';

CREATE TEMPORARY TABLE IF NOT EXISTS tmp_owner_takeover_legacy_tenants AS
SELECT DISTINCT
  legacy.tenant_id,
  CONCAT('sys_admin__', SUBSTRING(SHA2(legacy.tenant_id, 256), 1, 24)) AS resolved_role_id
FROM tmp_owner_takeover_legacy_memberships legacy;

SET @owner_takeover_role_collision_count = (
  SELECT COUNT(*)
  FROM tmp_owner_takeover_legacy_tenants migration_tenants
  JOIN platform_role_catalog prc ON BINARY prc.role_id = BINARY migration_tenants.resolved_role_id
  WHERE NOT (
    prc.scope = 'tenant'
    AND prc.tenant_id = migration_tenants.tenant_id
    AND prc.code_normalized = 'sys_admin'
  )
);

SET @owner_takeover_role_collision_guard_sql = IF(
  @owner_takeover_role_collision_count = 0,
  'SELECT 1',
  "SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = '0017_owner_transfer_takeover_role_cleanup role_id collision detected'"
);

PREPARE owner_takeover_role_collision_guard_stmt FROM @owner_takeover_role_collision_guard_sql;
EXECUTE owner_takeover_role_collision_guard_stmt;
DEALLOCATE PREPARE owner_takeover_role_collision_guard_stmt;

SET @owner_takeover_tenant_code_collision_count = (
  SELECT COUNT(*)
  FROM tmp_owner_takeover_legacy_tenants migration_tenants
  JOIN platform_role_catalog prc
    ON prc.scope = 'tenant'
   AND prc.tenant_id = migration_tenants.tenant_id
   AND prc.code_normalized = 'sys_admin'
   AND BINARY prc.role_id <> BINARY migration_tenants.resolved_role_id
);

SET @owner_takeover_tenant_code_collision_guard_sql = IF(
  @owner_takeover_tenant_code_collision_count = 0,
  'SELECT 1',
  "SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = '0017_owner_transfer_takeover_role_cleanup tenant code collision detected'"
);

PREPARE owner_takeover_tenant_code_collision_guard_stmt FROM @owner_takeover_tenant_code_collision_guard_sql;
EXECUTE owner_takeover_tenant_code_collision_guard_stmt;
DEALLOCATE PREPARE owner_takeover_tenant_code_collision_guard_stmt;

CREATE TEMPORARY TABLE IF NOT EXISTS tmp_owner_takeover_legacy_membership_targets AS
SELECT
  legacy_memberships.membership_id,
  legacy_memberships.tenant_id,
  migration_tenants.resolved_role_id
FROM tmp_owner_takeover_legacy_memberships legacy_memberships
JOIN tmp_owner_takeover_legacy_tenants migration_tenants
  ON migration_tenants.tenant_id = legacy_memberships.tenant_id;

INSERT INTO platform_role_catalog (
  role_id,
  tenant_id,
  code,
  code_normalized,
  name,
  status,
  scope,
  is_system,
  created_by_user_id,
  updated_by_user_id
)
SELECT
  migration_tenants.resolved_role_id,
  migration_tenants.tenant_id,
  'sys_admin',
  'sys_admin',
  'sys_admin',
  'active',
  'tenant',
  1,
  NULL,
  NULL
FROM tmp_owner_takeover_legacy_tenants migration_tenants
LEFT JOIN platform_role_catalog prc ON BINARY prc.role_id = BINARY migration_tenants.resolved_role_id
WHERE prc.role_id IS NULL;

UPDATE platform_role_catalog prc
JOIN tmp_owner_takeover_legacy_tenants migration_tenants
  ON BINARY migration_tenants.resolved_role_id = BINARY prc.role_id
SET prc.status = 'active',
    prc.updated_at = CURRENT_TIMESTAMP(3)
WHERE prc.scope = 'tenant'
  AND prc.tenant_id = migration_tenants.tenant_id
  AND prc.status NOT IN ('active', 'enabled');

INSERT IGNORE INTO tenant_role_permission_grants (
  role_id,
  permission_code,
  created_by_user_id,
  updated_by_user_id
)
SELECT
  migration_tenants.resolved_role_id,
  legacy_and_required_grants.permission_code,
  NULL,
  NULL
FROM tmp_owner_takeover_legacy_tenants migration_tenants
JOIN (
  SELECT LOWER(TRIM(permission_code)) AS permission_code
  FROM tenant_role_permission_grants
  WHERE role_id = 'tenant_owner'
    AND LOWER(TRIM(permission_code)) IN (
      'tenant.user_management.view',
      'tenant.user_management.operate',
      'tenant.role_management.view',
      'tenant.role_management.operate'
    )
  UNION
  SELECT 'tenant.user_management.view'
  UNION
  SELECT 'tenant.user_management.operate'
) legacy_and_required_grants;

INSERT IGNORE INTO auth_tenant_membership_roles (
  membership_id,
  role_id,
  created_by_user_id,
  updated_by_user_id
)
SELECT
  migration_memberships.membership_id,
  migration_memberships.resolved_role_id,
  NULL,
  NULL
FROM tmp_owner_takeover_legacy_membership_targets migration_memberships;

DELETE mr
FROM auth_tenant_membership_roles mr
JOIN tmp_owner_takeover_legacy_membership_targets migration_memberships
  ON migration_memberships.membership_id = mr.membership_id
WHERE mr.role_id = 'tenant_owner'
  AND migration_memberships.resolved_role_id <> 'tenant_owner';

UPDATE auth_user_tenants ut
JOIN (
  SELECT
    migration_memberships.membership_id,
    MAX(
      CASE
        WHEN prc.status IN ('active', 'enabled')
             AND grants.permission_code = 'tenant.user_management.view'
          THEN 1
        ELSE 0
      END
    ) AS can_view_user_management,
    MAX(
      CASE
        WHEN prc.status IN ('active', 'enabled')
             AND grants.permission_code = 'tenant.user_management.operate'
          THEN 1
        ELSE 0
      END
    ) AS can_operate_user_management,
    MAX(
      CASE
        WHEN prc.status IN ('active', 'enabled')
             AND grants.permission_code = 'tenant.role_management.view'
          THEN 1
        ELSE 0
      END
    ) AS can_view_organization_management,
    MAX(
      CASE
        WHEN prc.status IN ('active', 'enabled')
             AND grants.permission_code = 'tenant.role_management.operate'
          THEN 1
        ELSE 0
      END
    ) AS can_operate_organization_management
  FROM tmp_owner_takeover_legacy_membership_targets migration_memberships
  LEFT JOIN auth_tenant_membership_roles mr
    ON mr.membership_id = migration_memberships.membership_id
  LEFT JOIN platform_role_catalog prc
    ON prc.role_id = mr.role_id
   AND prc.scope = 'tenant'
   AND prc.tenant_id = migration_memberships.tenant_id
  LEFT JOIN tenant_role_permission_grants grants
    ON grants.role_id = prc.role_id
  GROUP BY migration_memberships.membership_id
) membership_snapshot
  ON membership_snapshot.membership_id = ut.membership_id
SET ut.can_view_user_management = membership_snapshot.can_view_user_management,
    ut.can_operate_user_management = membership_snapshot.can_operate_user_management,
    ut.can_view_organization_management = membership_snapshot.can_view_organization_management,
    ut.can_operate_organization_management = membership_snapshot.can_operate_organization_management,
    ut.updated_at = CURRENT_TIMESTAMP(3);

SET @legacy_tenant_owner_binding_count = (
  SELECT COUNT(*)
  FROM auth_tenant_membership_roles
  WHERE role_id = 'tenant_owner'
);

DELETE FROM tenant_role_permission_grants
WHERE role_id = 'tenant_owner'
  AND @legacy_tenant_owner_binding_count = 0;

DELETE FROM platform_role_catalog
WHERE role_id = 'tenant_owner'
  AND scope = 'tenant'
  AND @legacy_tenant_owner_binding_count = 0;

DROP TEMPORARY TABLE IF EXISTS tmp_owner_takeover_legacy_membership_targets;
DROP TEMPORARY TABLE IF EXISTS tmp_owner_takeover_legacy_tenants;
DROP TEMPORARY TABLE IF EXISTS tmp_owner_takeover_legacy_memberships;
