const readPermissionFlag = (permission, snakeCase, camelCase) =>
  Boolean(permission?.[snakeCase] || permission?.[camelCase]);

export const readTenantPermissionState = (sessionState) => {
  const permission = sessionState?.tenant_permission_context;
  if (permission && typeof permission === 'object') {
    return {
      scope_label: String(permission.scope_label || '组织权限快照（服务端）'),
      can_view_user_management: readPermissionFlag(
        permission,
        'can_view_user_management',
        'canViewUserManagement'
      ),
      can_operate_user_management: readPermissionFlag(
        permission,
        'can_operate_user_management',
        'canOperateUserManagement'
      ),
      can_view_role_management: readPermissionFlag(
        permission,
        'can_view_role_management',
        'canViewRoleManagement'
      ),
      can_operate_role_management: readPermissionFlag(
        permission,
        'can_operate_role_management',
        'canOperateRoleManagement'
      ),
      can_view_account_management: readPermissionFlag(
        permission,
        'can_view_account_management',
        'canViewAccountManagement'
      ),
      can_operate_account_management: readPermissionFlag(
        permission,
        'can_operate_account_management',
        'canOperateAccountManagement'
      ),
      can_view_session_management: readPermissionFlag(
        permission,
        'can_view_session_management',
        'canViewSessionManagement'
      ),
      can_operate_session_management: readPermissionFlag(
        permission,
        'can_operate_session_management',
        'canOperateSessionManagement'
      ),
      can_view_session_scope_my: readPermissionFlag(
        permission,
        'can_view_session_scope_my',
        'canViewSessionScopeMy'
      ),
      can_operate_session_scope_my: readPermissionFlag(
        permission,
        'can_operate_session_scope_my',
        'canOperateSessionScopeMy'
      ),
      can_view_session_scope_assist: readPermissionFlag(
        permission,
        'can_view_session_scope_assist',
        'canViewSessionScopeAssist'
      ),
      can_operate_session_scope_assist: readPermissionFlag(
        permission,
        'can_operate_session_scope_assist',
        'canOperateSessionScopeAssist'
      ),
      can_view_session_scope_all: readPermissionFlag(
        permission,
        'can_view_session_scope_all',
        'canViewSessionScopeAll'
      ),
      can_operate_session_scope_all: readPermissionFlag(
        permission,
        'can_operate_session_scope_all',
        'canOperateSessionScopeAll'
      ),
      can_view_customer_management: readPermissionFlag(
        permission,
        'can_view_customer_management',
        'canViewCustomerManagement'
      ),
      can_operate_customer_management: readPermissionFlag(
        permission,
        'can_operate_customer_management',
        'canOperateCustomerManagement'
      ),
      can_view_customer_scope_my: readPermissionFlag(
        permission,
        'can_view_customer_scope_my',
        'canViewCustomerScopeMy'
      ),
      can_operate_customer_scope_my: readPermissionFlag(
        permission,
        'can_operate_customer_scope_my',
        'canOperateCustomerScopeMy'
      ),
      can_view_customer_scope_assist: readPermissionFlag(
        permission,
        'can_view_customer_scope_assist',
        'canViewCustomerScopeAssist'
      ),
      can_operate_customer_scope_assist: readPermissionFlag(
        permission,
        'can_operate_customer_scope_assist',
        'canOperateCustomerScopeAssist'
      ),
      can_view_customer_scope_all: readPermissionFlag(
        permission,
        'can_view_customer_scope_all',
        'canViewCustomerScopeAll'
      ),
      can_operate_customer_scope_all: readPermissionFlag(
        permission,
        'can_operate_customer_scope_all',
        'canOperateCustomerScopeAll'
      )
    };
  }

  if (sessionState?.entry_domain !== 'tenant') {
    return {
      scope_label: '平台入口（无组织侧权限上下文）',
      can_view_user_management: false,
      can_operate_user_management: false,
      can_view_role_management: false,
      can_operate_role_management: false,
      can_view_account_management: false,
      can_operate_account_management: false,
      can_view_session_management: false,
      can_operate_session_management: false,
      can_view_session_scope_my: false,
      can_operate_session_scope_my: false,
      can_view_session_scope_assist: false,
      can_operate_session_scope_assist: false,
      can_view_session_scope_all: false,
      can_operate_session_scope_all: false,
      can_view_customer_management: false,
      can_operate_customer_management: false,
      can_view_customer_scope_my: false,
      can_operate_customer_scope_my: false,
      can_view_customer_scope_assist: false,
      can_operate_customer_scope_assist: false,
      can_view_customer_scope_all: false,
      can_operate_customer_scope_all: false
    };
  }

  return {
    scope_label: '组织权限加载中（以服务端返回为准）',
    can_view_user_management: false,
    can_operate_user_management: false,
    can_view_role_management: false,
    can_operate_role_management: false,
    can_view_account_management: false,
    can_operate_account_management: false,
    can_view_session_management: false,
    can_operate_session_management: false,
    can_view_session_scope_my: false,
    can_operate_session_scope_my: false,
    can_view_session_scope_assist: false,
    can_operate_session_scope_assist: false,
    can_view_session_scope_all: false,
    can_operate_session_scope_all: false,
    can_view_customer_management: false,
    can_operate_customer_management: false,
    can_view_customer_scope_my: false,
    can_operate_customer_scope_my: false,
    can_view_customer_scope_assist: false,
    can_operate_customer_scope_assist: false,
    can_view_customer_scope_all: false,
    can_operate_customer_scope_all: false
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
  const canViewAccountManagement = Boolean(
    permissionState?.can_view_account_management
  );
  const canOperateAccountManagement = Boolean(
    permissionState?.can_view_account_management
    && permissionState?.can_operate_account_management
  );
  const canViewSessionManagement = Boolean(
    permissionState?.can_view_session_management
  );
  const canOperateSessionManagement = Boolean(
    canViewSessionManagement
    && permissionState?.can_operate_session_management
  );
  const hasAnyCustomerScope = Boolean(
    permissionState?.can_view_customer_scope_my
    || permissionState?.can_view_customer_scope_assist
    || permissionState?.can_view_customer_scope_all
  );
  const hasAnyCustomerScopeOperate = Boolean(
    permissionState?.can_operate_customer_scope_my
    || permissionState?.can_operate_customer_scope_assist
    || permissionState?.can_operate_customer_scope_all
  );
  const canViewCustomerManagement = hasAnyCustomerScope;
  const canOperateCustomerManagement = Boolean(
    hasAnyCustomerScope
    && (permissionState?.can_operate_customer_management || hasAnyCustomerScopeOperate)
  );

  return {
    menu: {
      user_management: canAccessUserManagement,
      role_management: canAccessRoleManagement,
      account_management: canViewAccountManagement,
      session_management: canViewSessionManagement,
      customer_management: canViewCustomerManagement
    },
    action: {
      user_management: canAccessUserManagement,
      role_management: canAccessRoleManagement,
      account_management: canOperateAccountManagement,
      session_management: canOperateSessionManagement,
      customer_management: canOperateCustomerManagement
    }
  };
};
