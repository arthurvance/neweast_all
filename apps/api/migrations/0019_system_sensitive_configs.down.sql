DELETE FROM platform_role_permission_grants
WHERE role_id = 'sys_admin'
  AND permission_code IN (
    'platform.role_management.view',
    'platform.role_management.operate'
  );

DROP TABLE IF EXISTS system_sensitive_configs;
