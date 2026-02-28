INSERT INTO tenant_role_permission_grants (
  role_id,
  permission_code,
  created_by_user_id,
  updated_by_user_id
)
SELECT pr.role_id,
       perms.permission_code,
       NULL AS created_by_user_id,
       NULL AS updated_by_user_id
FROM platform_roles pr
JOIN (
  SELECT 'tenant.customer_management.view' AS permission_code
  UNION ALL
  SELECT 'tenant.customer_management.operate' AS permission_code
  UNION ALL
  SELECT 'tenant.customer_scope_my.view' AS permission_code
  UNION ALL
  SELECT 'tenant.customer_scope_my.operate' AS permission_code
  UNION ALL
  SELECT 'tenant.customer_scope_assist.view' AS permission_code
  UNION ALL
  SELECT 'tenant.customer_scope_assist.operate' AS permission_code
  UNION ALL
  SELECT 'tenant.customer_scope_all.view' AS permission_code
  UNION ALL
  SELECT 'tenant.customer_scope_all.operate' AS permission_code
) perms
  ON 1 = 1
LEFT JOIN tenant_role_permission_grants trg
  ON trg.role_id = pr.role_id
 AND trg.permission_code = perms.permission_code
WHERE pr.scope = 'tenant'
  AND LOWER(TRIM(pr.code)) = 'sys_admin'
  AND pr.status IN ('active', 'enabled')
  AND pr.tenant_id IS NOT NULL
  AND trg.role_id IS NULL;
