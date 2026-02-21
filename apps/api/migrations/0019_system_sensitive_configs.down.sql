DELETE FROM platform_role_permission_grants
WHERE role_id = 'sys_admin'
  AND permission_code IN (
    'platform.system_config.view',
    'platform.system_config.operate'
  );

DROP TABLE IF EXISTS system_sensitive_configs;
