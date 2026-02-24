export const readTenantPermissionState = (sessionState) => {
  const permission = sessionState?.tenant_permission_context;
  if (permission && typeof permission === 'object') {
    return {
      scope_label: String(permission.scope_label || '组织权限快照（服务端）'),
      can_view_user_management: Boolean(permission.can_view_user_management),
      can_operate_user_management: Boolean(permission.can_operate_user_management),
      can_view_role_management: Boolean(permission.can_view_role_management),
      can_operate_role_management: Boolean(permission.can_operate_role_management)
    };
  }

  if (sessionState?.entry_domain !== 'tenant') {
    return {
      scope_label: '平台入口（无组织侧权限上下文）',
      can_view_user_management: false,
      can_operate_user_management: false,
      can_view_role_management: false,
      can_operate_role_management: false
    };
  }

  return {
    scope_label: '组织权限加载中（以服务端返回为准）',
    can_view_user_management: false,
    can_operate_user_management: false,
    can_view_role_management: false,
    can_operate_role_management: false
  };
};

export const selectPermissionUiState = (permissionState) => {
  const canAccessUserManagement = Boolean(
    permissionState?.can_view_user_management
    && permissionState?.can_operate_user_management
  );
  const canAccessRoleManagement = Boolean(
    permissionState?.can_view_role_management
    && permissionState?.can_operate_role_management
  );

  return {
    menu: {
      user_management: canAccessUserManagement,
      role_management: canAccessRoleManagement
    },
    action: {
      user_management: canAccessUserManagement,
      role_management: canAccessRoleManagement
    }
  };
};
