DROP TEMPORARY TABLE IF EXISTS tmp_platform_role_permission_grants_final_authorization;
CREATE TEMPORARY TABLE tmp_platform_role_permission_grants_final_authorization (
  role_id VARCHAR(64) NOT NULL,
  permission_code VARCHAR(128) NOT NULL,
  created_by_user_id VARCHAR(64) NULL,
  updated_by_user_id VARCHAR(64) NULL,
  created_at TIMESTAMP(3) NOT NULL,
  updated_at TIMESTAMP(3) NOT NULL,
  PRIMARY KEY (role_id, permission_code)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

INSERT INTO tmp_platform_role_permission_grants_final_authorization (
  role_id,
  permission_code,
  created_by_user_id,
  updated_by_user_id,
  created_at,
  updated_at
)
SELECT
  grants.role_id,
  LOWER(TRIM(grants.permission_code)) AS permission_code,
  SUBSTRING_INDEX(
    GROUP_CONCAT(
      NULLIF(TRIM(grants.created_by_user_id), '')
      ORDER BY grants.created_at ASC, grants.permission_code ASC SEPARATOR ','
    ),
    ',',
    1
  ) AS created_by_user_id,
  SUBSTRING_INDEX(
    GROUP_CONCAT(
      NULLIF(TRIM(grants.updated_by_user_id), '')
      ORDER BY grants.updated_at DESC, grants.permission_code DESC SEPARATOR ','
    ),
    ',',
    1
  ) AS updated_by_user_id,
  MIN(grants.created_at) AS created_at,
  MAX(grants.updated_at) AS updated_at
FROM platform_role_permission_grants grants
JOIN platform_role_catalog catalog ON catalog.role_id = grants.role_id
WHERE catalog.scope = 'platform'
  AND COALESCE(catalog.tenant_id, '') = ''
  AND LOWER(TRIM(grants.permission_code)) IN (
    'platform.member_admin.view',
    'platform.member_admin.operate',
    'platform.billing.view',
    'platform.billing.operate',
    'platform.system_config.view',
    'platform.system_config.operate'
  )
GROUP BY grants.role_id, LOWER(TRIM(grants.permission_code));

DELETE grants
FROM platform_role_permission_grants grants
LEFT JOIN tmp_platform_role_permission_grants_final_authorization normalized
  ON normalized.role_id = grants.role_id
  AND normalized.permission_code = grants.permission_code
WHERE normalized.role_id IS NULL
  AND EXISTS (
    SELECT 1
    FROM tmp_platform_role_permission_grants_final_authorization
  );

INSERT INTO platform_role_permission_grants (
  role_id,
  permission_code,
  created_by_user_id,
  updated_by_user_id,
  created_at,
  updated_at
)
SELECT
  role_id,
  permission_code,
  created_by_user_id,
  updated_by_user_id,
  created_at,
  updated_at
FROM tmp_platform_role_permission_grants_final_authorization
ORDER BY role_id ASC, permission_code ASC
ON DUPLICATE KEY UPDATE
  created_by_user_id = VALUES(created_by_user_id),
  updated_by_user_id = VALUES(updated_by_user_id),
  created_at = VALUES(created_at),
  updated_at = VALUES(updated_at);

DROP TEMPORARY TABLE IF EXISTS tmp_tenant_role_permission_grants_final_authorization;
CREATE TEMPORARY TABLE tmp_tenant_role_permission_grants_final_authorization (
  role_id VARCHAR(64) NOT NULL,
  permission_code VARCHAR(128) NOT NULL,
  created_by_user_id VARCHAR(64) NULL,
  updated_by_user_id VARCHAR(64) NULL,
  created_at TIMESTAMP(3) NOT NULL,
  updated_at TIMESTAMP(3) NOT NULL,
  PRIMARY KEY (role_id, permission_code)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

INSERT INTO tmp_tenant_role_permission_grants_final_authorization (
  role_id,
  permission_code,
  created_by_user_id,
  updated_by_user_id,
  created_at,
  updated_at
)
SELECT
  grants.role_id,
  LOWER(TRIM(grants.permission_code)) AS permission_code,
  SUBSTRING_INDEX(
    GROUP_CONCAT(
      NULLIF(TRIM(grants.created_by_user_id), '')
      ORDER BY grants.created_at ASC, grants.permission_code ASC SEPARATOR ','
    ),
    ',',
    1
  ) AS created_by_user_id,
  SUBSTRING_INDEX(
    GROUP_CONCAT(
      NULLIF(TRIM(grants.updated_by_user_id), '')
      ORDER BY grants.updated_at DESC, grants.permission_code DESC SEPARATOR ','
    ),
    ',',
    1
  ) AS updated_by_user_id,
  MIN(grants.created_at) AS created_at,
  MAX(grants.updated_at) AS updated_at
FROM tenant_role_permission_grants grants
JOIN platform_role_catalog catalog ON catalog.role_id = grants.role_id
WHERE catalog.scope = 'tenant'
  AND COALESCE(catalog.tenant_id, '') <> ''
  AND LOWER(TRIM(grants.permission_code)) IN (
    'tenant.member_admin.view',
    'tenant.member_admin.operate',
    'tenant.billing.view',
    'tenant.billing.operate'
  )
GROUP BY grants.role_id, LOWER(TRIM(grants.permission_code));

DELETE grants
FROM tenant_role_permission_grants grants
LEFT JOIN tmp_tenant_role_permission_grants_final_authorization normalized
  ON normalized.role_id = grants.role_id
  AND normalized.permission_code = grants.permission_code
WHERE normalized.role_id IS NULL
  AND EXISTS (
    SELECT 1
    FROM tmp_tenant_role_permission_grants_final_authorization
  );

INSERT INTO tenant_role_permission_grants (
  role_id,
  permission_code,
  created_by_user_id,
  updated_by_user_id,
  created_at,
  updated_at
)
SELECT
  role_id,
  permission_code,
  created_by_user_id,
  updated_by_user_id,
  created_at,
  updated_at
FROM tmp_tenant_role_permission_grants_final_authorization
ORDER BY role_id ASC, permission_code ASC
ON DUPLICATE KEY UPDATE
  created_by_user_id = VALUES(created_by_user_id),
  updated_by_user_id = VALUES(updated_by_user_id),
  created_at = VALUES(created_at),
  updated_at = VALUES(updated_at);

DROP TEMPORARY TABLE IF EXISTS tmp_platform_role_permission_grants_final_authorization;
DROP TEMPORARY TABLE IF EXISTS tmp_tenant_role_permission_grants_final_authorization;
