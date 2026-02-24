import {
  SafetyCertificateOutlined,
  SettingOutlined,
  TeamOutlined
} from '@ant-design/icons';
import TenantRoleManagementPage from '../tenant-settings/TenantRoleManagementPage';
import TenantUserManagementPage from '../tenant-settings/TenantUserManagementPage';

const SETTINGS_MENU_KEY = 'settings';
const USER_MENU_KEY = 'settings/users';
const ROLE_MENU_KEY = 'settings/roles';

const MEMBER_ADMIN_VIEW_PERMISSION_CODE = 'tenant.member_admin.view';
const MEMBER_ADMIN_OPERATE_PERMISSION_CODE = 'tenant.member_admin.operate';

const TENANT_MENU_ORDER = Object.freeze([
  USER_MENU_KEY,
  ROLE_MENU_KEY
]);

export const TENANT_DEFAULT_MENU_KEY = USER_MENU_KEY;

export const TENANT_NAV_GROUP_FALLBACK = Object.freeze({
  [SETTINGS_MENU_KEY]: USER_MENU_KEY
});

export const TENANT_MENU_PERMISSION_REGISTRY = Object.freeze({
  [SETTINGS_MENU_KEY]: '',
  [USER_MENU_KEY]: MEMBER_ADMIN_VIEW_PERMISSION_CODE,
  [ROLE_MENU_KEY]: MEMBER_ADMIN_VIEW_PERMISSION_CODE
});

const readPermissionFlag = (permissionContext, snakeCase, camelCase) =>
  Boolean(permissionContext?.[snakeCase] || permissionContext?.[camelCase]);

const hasTenantMemberAdminAccess = (permissionContext = null) => {
  if (!permissionContext || typeof permissionContext !== 'object') {
    return false;
  }
  const canView = readPermissionFlag(
    permissionContext,
    'can_view_member_admin',
    'canViewMemberAdmin'
  );
  const canOperate = readPermissionFlag(
    permissionContext,
    'can_operate_member_admin',
    'canOperateMemberAdmin'
  );
  return canView && canOperate;
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
    permissionCode === MEMBER_ADMIN_VIEW_PERMISSION_CODE
    || permissionCode === MEMBER_ADMIN_OPERATE_PERMISSION_CODE
  ) {
    return hasTenantMemberAdminAccess(permissionContext);
  }
  return false;
};

export const TENANT_NAV_ITEMS = [
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
