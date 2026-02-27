import {
  AppstoreOutlined,
  ContactsOutlined,
  IdcardOutlined,
  SafetyCertificateOutlined,
  SettingOutlined,
  TeamOutlined
} from '@ant-design/icons';
import { lazy } from 'react';
import {
  TENANT_PERMISSION_CODE_BY_GROUP_ACTION
} from '../../../../features/auth/generated-permission-catalog';

const CUSTOMER_MANAGEMENT_MENU_KEY = 'customer';
const CUSTOMER_PROFILE_MENU_KEY = 'customer/profile';
const ACCOUNT_MATRIX_MENU_KEY = 'account';
const ACCOUNT_MENU_KEY = 'account/account';
const LEGACY_ACCOUNT_MATRIX_MENU_KEY = 'account-matrix';
const LEGACY_ACCOUNT_MENU_KEY = 'account-matrix/accounts';
const SETTINGS_MENU_KEY = 'settings';
const USER_MENU_KEY = 'settings/users';
const ROLE_MENU_KEY = 'settings/roles';
const TenantCustomerProfilePage = lazy(() =>
  import('../../customer/profile/TenantCustomerProfilePage')
);
const TenantAccountManagementPage = lazy(() => import('../account/TenantAccountManagementPage'));
const TenantRoleManagementPage = lazy(() => import('../../settings/role/TenantRoleManagementPage'));
const TenantUserManagementPage = lazy(() => import('../../settings/user/TenantUserManagementPage'));

const readTenantPermissionCode = ({
  groupKey,
  actionKey,
  fallbackCode = ''
}) => {
  const code = TENANT_PERMISSION_CODE_BY_GROUP_ACTION?.[groupKey]?.[actionKey];
  if (code) {
    return code;
  }
  const normalizedFallbackCode = String(fallbackCode || '').trim();
  if (normalizedFallbackCode) {
    return normalizedFallbackCode;
  }
  if (!code) {
    throw new Error(
      `missing generated tenant permission code for ${String(groupKey)}.${String(actionKey)}`
    );
  }
  return code;
};

const USER_MANAGEMENT_VIEW_PERMISSION_CODE = readTenantPermissionCode({
  groupKey: 'user_management',
  actionKey: 'view'
});
const USER_MANAGEMENT_OPERATE_PERMISSION_CODE = readTenantPermissionCode({
  groupKey: 'user_management',
  actionKey: 'operate'
});
const ROLE_MANAGEMENT_VIEW_PERMISSION_CODE = readTenantPermissionCode({
  groupKey: 'role_management',
  actionKey: 'view'
});
const ROLE_MANAGEMENT_OPERATE_PERMISSION_CODE = readTenantPermissionCode({
  groupKey: 'role_management',
  actionKey: 'operate'
});
const ACCOUNT_MANAGEMENT_VIEW_PERMISSION_CODE = readTenantPermissionCode({
  groupKey: 'account_management',
  actionKey: 'view',
  fallbackCode: 'tenant.account_management.view'
});
const ACCOUNT_MANAGEMENT_OPERATE_PERMISSION_CODE = readTenantPermissionCode({
  groupKey: 'account_management',
  actionKey: 'operate',
  fallbackCode: 'tenant.account_management.operate'
});
const CUSTOMER_MANAGEMENT_VIEW_PERMISSION_CODE = readTenantPermissionCode({
  groupKey: 'customer_management',
  actionKey: 'view',
  fallbackCode: 'tenant.customer_management.view'
});
const CUSTOMER_MANAGEMENT_OPERATE_PERMISSION_CODE = readTenantPermissionCode({
  groupKey: 'customer_management',
  actionKey: 'operate',
  fallbackCode: 'tenant.customer_management.operate'
});

const TENANT_MENU_ORDER = Object.freeze([
  CUSTOMER_PROFILE_MENU_KEY,
  ACCOUNT_MENU_KEY,
  USER_MENU_KEY,
  ROLE_MENU_KEY
]);

export const TENANT_DEFAULT_MENU_KEY = USER_MENU_KEY;

export const TENANT_NAV_GROUP_FALLBACK = Object.freeze({
  [CUSTOMER_MANAGEMENT_MENU_KEY]: CUSTOMER_PROFILE_MENU_KEY,
  [ACCOUNT_MATRIX_MENU_KEY]: ACCOUNT_MENU_KEY,
  [LEGACY_ACCOUNT_MATRIX_MENU_KEY]: ACCOUNT_MENU_KEY,
  [SETTINGS_MENU_KEY]: USER_MENU_KEY
});

export const TENANT_MENU_PERMISSION_REGISTRY = Object.freeze({
  [CUSTOMER_MANAGEMENT_MENU_KEY]: '',
  [CUSTOMER_PROFILE_MENU_KEY]: CUSTOMER_MANAGEMENT_VIEW_PERMISSION_CODE,
  [ACCOUNT_MATRIX_MENU_KEY]: '',
  [ACCOUNT_MENU_KEY]: ACCOUNT_MANAGEMENT_VIEW_PERMISSION_CODE,
  [SETTINGS_MENU_KEY]: '',
  [USER_MENU_KEY]: USER_MANAGEMENT_VIEW_PERMISSION_CODE,
  [ROLE_MENU_KEY]: ROLE_MANAGEMENT_VIEW_PERMISSION_CODE
});

const readPermissionFlag = (permissionContext, snakeCase, camelCase) =>
  Boolean(permissionContext?.[snakeCase] || permissionContext?.[camelCase]);

const hasTenantUserManagementAccess = (permissionContext = null) => {
  if (!permissionContext || typeof permissionContext !== 'object') {
    return false;
  }
  const canView = readPermissionFlag(
    permissionContext,
    'can_view_user_management',
    'canViewUserManagement'
  );
  const canOperate = readPermissionFlag(
    permissionContext,
    'can_operate_user_management',
    'canOperateUserManagement'
  );
  return canView && canOperate;
};

const hasTenantRoleManagementAccess = (permissionContext = null) => {
  if (!permissionContext || typeof permissionContext !== 'object') {
    return false;
  }
  const canView = readPermissionFlag(
    permissionContext,
    'can_view_role_management',
    'canViewRoleManagement'
  );
  const canOperate = readPermissionFlag(
    permissionContext,
    'can_operate_role_management',
    'canOperateRoleManagement'
  );
  return canView && canOperate;
};

const hasTenantAccountManagementAccess = (permissionContext = null) => {
  if (!permissionContext || typeof permissionContext !== 'object') {
    return false;
  }
  const canView = readPermissionFlag(
    permissionContext,
    'can_view_account_management',
    'canViewAccountManagement'
  );
  return canView;
};

const hasTenantCustomerManagementAccess = (permissionContext = null) => {
  if (!permissionContext || typeof permissionContext !== 'object') {
    return false;
  }
  const canViewScopeMy = readPermissionFlag(
    permissionContext,
    'can_view_customer_scope_my',
    'canViewCustomerScopeMy'
  );
  const canViewScopeAssist = readPermissionFlag(
    permissionContext,
    'can_view_customer_scope_assist',
    'canViewCustomerScopeAssist'
  );
  const canViewScopeAll = readPermissionFlag(
    permissionContext,
    'can_view_customer_scope_all',
    'canViewCustomerScopeAll'
  );
  return canViewScopeMy || canViewScopeAssist || canViewScopeAll;
};

export const resolveTenantMenuPermissionCode = (menuKey) => {
  const normalizedKey = String(menuKey || '').trim();
  return TENANT_MENU_PERMISSION_REGISTRY[normalizedKey] || '';
};

export const hasTenantMenuAccess = ({ menuKey, permissionContext = null }) => {
  const permissionCode = resolveTenantMenuPermissionCode(menuKey);
  if (!permissionCode) {
    return true;
  }
  if (
    permissionCode === USER_MANAGEMENT_VIEW_PERMISSION_CODE
    || permissionCode === USER_MANAGEMENT_OPERATE_PERMISSION_CODE
  ) {
    return hasTenantUserManagementAccess(permissionContext);
  }
  if (
    permissionCode === ROLE_MANAGEMENT_VIEW_PERMISSION_CODE
    || permissionCode === ROLE_MANAGEMENT_OPERATE_PERMISSION_CODE
  ) {
    return hasTenantRoleManagementAccess(permissionContext);
  }
  if (
    permissionCode === ACCOUNT_MANAGEMENT_VIEW_PERMISSION_CODE
    || permissionCode === ACCOUNT_MANAGEMENT_OPERATE_PERMISSION_CODE
  ) {
    return hasTenantAccountManagementAccess(permissionContext);
  }
  if (
    permissionCode === CUSTOMER_MANAGEMENT_VIEW_PERMISSION_CODE
    || permissionCode === CUSTOMER_MANAGEMENT_OPERATE_PERMISSION_CODE
  ) {
    return hasTenantCustomerManagementAccess(permissionContext);
  }
  return false;
};

export const TENANT_NAV_ITEMS = [
  {
    key: CUSTOMER_MANAGEMENT_MENU_KEY,
    permission_code: resolveTenantMenuPermissionCode(CUSTOMER_MANAGEMENT_MENU_KEY),
    icon: <ContactsOutlined />,
    label: <span data-testid="tenant-menu-customer-management">客户管理</span>,
    children: [
      {
        key: CUSTOMER_PROFILE_MENU_KEY,
        permission_code: resolveTenantMenuPermissionCode(CUSTOMER_PROFILE_MENU_KEY),
        icon: <IdcardOutlined />,
        label: <span data-testid="tenant-tab-customer-profile">客户资料</span>
      }
    ]
  },
  {
    key: ACCOUNT_MATRIX_MENU_KEY,
    permission_code: resolveTenantMenuPermissionCode(ACCOUNT_MATRIX_MENU_KEY),
    icon: <AppstoreOutlined />,
    label: <span data-testid="tenant-menu-account-matrix">账号矩阵</span>,
    children: [
      {
        key: ACCOUNT_MENU_KEY,
        permission_code: resolveTenantMenuPermissionCode(ACCOUNT_MENU_KEY),
        icon: <IdcardOutlined />,
        label: <span data-testid="tenant-tab-accounts">账号管理</span>
      }
    ]
  },
  {
    key: SETTINGS_MENU_KEY,
    permission_code: resolveTenantMenuPermissionCode(SETTINGS_MENU_KEY),
    icon: <SettingOutlined />,
    label: <span data-testid="tenant-menu-settings">设置</span>,
    children: [
      {
        key: USER_MENU_KEY,
        permission_code: resolveTenantMenuPermissionCode(USER_MENU_KEY),
        icon: <TeamOutlined />,
        label: <span data-testid="tenant-tab-users">用户管理</span>
      },
      {
        key: ROLE_MENU_KEY,
        permission_code: resolveTenantMenuPermissionCode(ROLE_MENU_KEY),
        icon: <SafetyCertificateOutlined />,
        label: <span data-testid="tenant-tab-roles">角色管理</span>
      }
    ]
  }
];

export const TENANT_PAGE_REGISTRY = Object.freeze({
  [CUSTOMER_PROFILE_MENU_KEY]: {
    title: '客户资料',
    subTitle: '客户管理 / 客户资料',
    permission_code: resolveTenantMenuPermissionCode(CUSTOMER_PROFILE_MENU_KEY),
    breadcrumbItems: [
      { key: CUSTOMER_MANAGEMENT_MENU_KEY, title: '客户管理' },
      { key: CUSTOMER_PROFILE_MENU_KEY, title: '客户资料' }
    ],
    Component: TenantCustomerProfilePage
  },
  [ACCOUNT_MENU_KEY]: {
    title: '账号管理',
    subTitle: '账号矩阵 / 账号管理',
    permission_code: resolveTenantMenuPermissionCode(ACCOUNT_MENU_KEY),
    breadcrumbItems: [
      { key: ACCOUNT_MATRIX_MENU_KEY, title: '账号矩阵' },
      { key: ACCOUNT_MENU_KEY, title: '账号管理' }
    ],
    Component: TenantAccountManagementPage
  },
  [USER_MENU_KEY]: {
    title: '用户管理',
    subTitle: '组织设置 / 用户管理',
    permission_code: resolveTenantMenuPermissionCode(USER_MENU_KEY),
    breadcrumbItems: [
      { key: SETTINGS_MENU_KEY, title: '设置' },
      { key: USER_MENU_KEY, title: '用户管理' }
    ],
    Component: TenantUserManagementPage
  },
  [ROLE_MENU_KEY]: {
    title: '角色管理',
    subTitle: '组织设置 / 角色管理',
    permission_code: resolveTenantMenuPermissionCode(ROLE_MENU_KEY),
    breadcrumbItems: [
      { key: SETTINGS_MENU_KEY, title: '设置' },
      { key: ROLE_MENU_KEY, title: '角色管理' }
    ],
    Component: TenantRoleManagementPage
  }
});

export const resolveTenantMenuKey = (menuKey) => {
  const normalizedKey = String(menuKey || '').trim();
  if (normalizedKey === LEGACY_ACCOUNT_MATRIX_MENU_KEY || normalizedKey === LEGACY_ACCOUNT_MENU_KEY) {
    return ACCOUNT_MENU_KEY;
  }
  if (TENANT_PAGE_REGISTRY[normalizedKey]) {
    return normalizedKey;
  }
  return TENANT_DEFAULT_MENU_KEY;
};

export const resolveTenantVisiblePageKeys = (permissionContext = null) =>
  TENANT_MENU_ORDER.filter((menuKey) =>
    hasTenantMenuAccess({
      menuKey,
      permissionContext
    })
  );

export const resolveFirstTenantVisibleMenuKey = (permissionContext = null) =>
  resolveTenantVisiblePageKeys(permissionContext)[0] || '';

export const resolveTenantMenuKeyByPermission = (menuKey, permissionContext = null) => {
  const normalizedMenuKey = resolveTenantMenuKey(menuKey);
  if (
    hasTenantMenuAccess({
      menuKey: normalizedMenuKey,
      permissionContext
    })
  ) {
    return normalizedMenuKey;
  }
  return resolveFirstTenantVisibleMenuKey(permissionContext);
};

export const resolveTenantNavItemsByPermission = (permissionContext = null) =>
  TENANT_NAV_ITEMS
    .map((item) => {
      const children = Array.isArray(item?.children) ? item.children : [];
      if (children.length > 0) {
        const visibleChildren = children.filter((child) =>
          hasTenantMenuAccess({
            menuKey: child?.key,
            permissionContext
          })
        );
        if (visibleChildren.length < 1) {
          return null;
        }
        return {
          ...item,
          children: visibleChildren
        };
      }
      if (
        hasTenantMenuAccess({
          menuKey: item?.key,
          permissionContext
        })
      ) {
        return item;
      }
      return null;
    })
    .filter(Boolean);

export const resolveTenantOpenKeys = (menuKey) => {
  const normalizedKey = String(menuKey || '').trim();
  if (!normalizedKey.includes('/')) {
    return [];
  }
  return [normalizedKey.split('/')[0]];
};
