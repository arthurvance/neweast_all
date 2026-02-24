import {
  ApartmentOutlined,
  SafetyCertificateOutlined,
  SettingOutlined,
  TeamOutlined
} from '@ant-design/icons';
import { lazy } from 'react';
import {
  PLATFORM_PERMISSION_CODE_BY_GROUP_ACTION
} from '../auth/generated-permission-catalog';

const SETTINGS_MENU_KEY = 'settings';
const USER_MENU_KEY = 'settings/users';
const TENANT_MENU_KEY = 'settings/tenants';
const ROLE_MENU_KEY = 'settings/roles';
const PlatformOrgManagementPage = lazy(() => import('./pages/PlatformOrgManagementPage'));
const PlatformRoleManagementPage = lazy(() => import('./pages/PlatformRoleManagementPage'));
const PlatformUserManagementPage = lazy(() => import('./pages/PlatformUserManagementPage'));
const readPlatformPermissionCode = ({ groupKey, actionKey }) => {
  const code = PLATFORM_PERMISSION_CODE_BY_GROUP_ACTION?.[groupKey]?.[actionKey];
  if (!code) {
    throw new Error(
      `missing generated platform permission code for ${String(groupKey)}.${String(actionKey)}`
    );
  }
  return code;
};
const USER_VIEW_PERMISSION_CODE = readPlatformPermissionCode({
  groupKey: 'user_management',
  actionKey: 'view'
});
const ROLE_VIEW_PERMISSION_CODE = readPlatformPermissionCode({
  groupKey: 'role_management',
  actionKey: 'view'
});
const TENANT_VIEW_PERMISSION_CODE = readPlatformPermissionCode({
  groupKey: 'tenant_management',
  actionKey: 'view'
});
const PLATFORM_MENU_ORDER = Object.freeze([
  USER_MENU_KEY,
  ROLE_MENU_KEY,
  TENANT_MENU_KEY
]);

export const PLATFORM_DEFAULT_MENU_KEY = USER_MENU_KEY;

export const PLATFORM_NAV_GROUP_FALLBACK = Object.freeze({
  [SETTINGS_MENU_KEY]: USER_MENU_KEY
});

export const PLATFORM_MENU_PERMISSION_REGISTRY = Object.freeze({
  [SETTINGS_MENU_KEY]: '',
  [USER_MENU_KEY]: USER_VIEW_PERMISSION_CODE,
  [ROLE_MENU_KEY]: ROLE_VIEW_PERMISSION_CODE,
  [TENANT_MENU_KEY]: TENANT_VIEW_PERMISSION_CODE
});

const PLATFORM_PERMISSION_FLAG_REGISTRY = Object.freeze({
  [USER_VIEW_PERMISSION_CODE]: Object.freeze([
    'can_view_user_management',
    'canViewUserManagement',
    'can_operate_user_management',
    'canOperateUserManagement'
  ]),
  [ROLE_VIEW_PERMISSION_CODE]: Object.freeze([
    'can_view_role_management',
    'canViewRoleManagement',
    'can_operate_role_management',
    'canOperateRoleManagement'
  ]),
  [TENANT_VIEW_PERMISSION_CODE]: Object.freeze([
    'can_view_tenant_management',
    'canViewTenantManagement',
    'can_operate_tenant_management',
    'canOperateTenantManagement'
  ])
});

export const resolvePlatformMenuPermissionCode = (menuKey) => {
  const normalizedKey = String(menuKey || '').trim();
  return PLATFORM_MENU_PERMISSION_REGISTRY[normalizedKey] || '';
};

export const hasPlatformMenuAccess = ({ menuKey, permissionContext = null }) => {
  const permissionCode = resolvePlatformMenuPermissionCode(menuKey);
  if (!permissionCode) {
    return true;
  }
  if (!permissionContext || typeof permissionContext !== 'object') {
    return false;
  }
  const permissionFlagNames = PLATFORM_PERMISSION_FLAG_REGISTRY[permissionCode] || [];
  return permissionFlagNames.some((flagName) => Boolean(permissionContext?.[flagName]));
};

export const PLATFORM_NAV_ITEMS = [
  {
    key: SETTINGS_MENU_KEY,
    permission_code: resolvePlatformMenuPermissionCode(SETTINGS_MENU_KEY),
    icon: <SettingOutlined />,
    label: <span data-testid="platform-menu-settings">设置</span>,
    children: [
      {
        key: USER_MENU_KEY,
        permission_code: resolvePlatformMenuPermissionCode(USER_MENU_KEY),
        icon: <TeamOutlined />,
        label: <span data-testid="platform-tab-users">用户管理</span>
      },
      {
        key: ROLE_MENU_KEY,
        permission_code: resolvePlatformMenuPermissionCode(ROLE_MENU_KEY),
        icon: <SafetyCertificateOutlined />,
        label: <span data-testid="platform-tab-roles">角色管理</span>
      },
      {
        key: TENANT_MENU_KEY,
        permission_code: resolvePlatformMenuPermissionCode(TENANT_MENU_KEY),
        icon: <ApartmentOutlined />,
        label: <span data-testid="platform-tab-tenants">组织管理</span>
      }
    ]
  }
];

export const PLATFORM_PAGE_REGISTRY = Object.freeze({
  [USER_MENU_KEY]: {
    title: '用户管理',
    subTitle: '平台设置 / 用户管理',
    permission_code: resolvePlatformMenuPermissionCode(USER_MENU_KEY),
    breadcrumbItems: [
      { key: SETTINGS_MENU_KEY, title: '设置' },
      { key: USER_MENU_KEY, title: '用户管理' }
    ],
    Component: PlatformUserManagementPage
  },
  [TENANT_MENU_KEY]: {
    title: '组织管理',
    subTitle: '平台设置 / 组织管理',
    permission_code: resolvePlatformMenuPermissionCode(TENANT_MENU_KEY),
    breadcrumbItems: [
      { key: SETTINGS_MENU_KEY, title: '设置' },
      { key: TENANT_MENU_KEY, title: '组织管理' }
    ],
    Component: PlatformOrgManagementPage
  },
  [ROLE_MENU_KEY]: {
    title: '角色管理',
    subTitle: '平台设置 / 角色管理',
    permission_code: resolvePlatformMenuPermissionCode(ROLE_MENU_KEY),
    breadcrumbItems: [
      { key: SETTINGS_MENU_KEY, title: '设置' },
      { key: ROLE_MENU_KEY, title: '角色管理' }
    ],
    Component: PlatformRoleManagementPage
  }
});

export const resolvePlatformMenuKey = (menuKey) => {
  const normalizedKey = String(menuKey || '').trim();
  if (PLATFORM_PAGE_REGISTRY[normalizedKey]) {
    return normalizedKey;
  }
  return PLATFORM_DEFAULT_MENU_KEY;
};

export const resolvePlatformVisiblePageKeys = (permissionContext = null) =>
  PLATFORM_MENU_ORDER.filter((menuKey) =>
    hasPlatformMenuAccess({
      menuKey,
      permissionContext
    })
  );

export const resolveFirstPlatformVisibleMenuKey = (permissionContext = null) =>
  resolvePlatformVisiblePageKeys(permissionContext)[0] || '';

export const resolvePlatformMenuKeyByPermission = (menuKey, permissionContext = null) => {
  const normalizedMenuKey = resolvePlatformMenuKey(menuKey);
  if (
    hasPlatformMenuAccess({
      menuKey: normalizedMenuKey,
      permissionContext
    })
  ) {
    return normalizedMenuKey;
  }
  return resolveFirstPlatformVisibleMenuKey(permissionContext);
};

export const resolvePlatformNavItemsByPermission = (permissionContext = null) =>
  PLATFORM_NAV_ITEMS
    .map((item) => {
      const children = Array.isArray(item?.children) ? item.children : [];
      if (children.length > 0) {
        const visibleChildren = children.filter((child) =>
          hasPlatformMenuAccess({
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
        hasPlatformMenuAccess({
          menuKey: item?.key,
          permissionContext
        })
      ) {
        return item;
      }
      return null;
    })
    .filter(Boolean);

export const resolvePlatformOpenKeys = (menuKey) => {
  const normalizedKey = String(menuKey || '').trim();
  if (!normalizedKey.includes('/')) {
    return [];
  }
  return [normalizedKey.split('/')[0]];
};
