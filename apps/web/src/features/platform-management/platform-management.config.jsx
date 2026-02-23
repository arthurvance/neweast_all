import {
  ApartmentOutlined,
  SafetyCertificateOutlined,
  SettingOutlined,
  TeamOutlined
} from '@ant-design/icons';
import PlatformOrgManagementPage from '../platform-settings/PlatformOrgManagementPage';
import PlatformRoleManagementPage from '../platform-settings/PlatformRoleManagementPage';
import PlatformUserManagementPage from '../platform-settings/PlatformUserManagementPage';

const SETTINGS_MENU_KEY = 'settings';
const USER_MENU_KEY = 'settings/users';
const ORG_MENU_KEY = 'settings/orgs';
const ROLE_MENU_KEY = 'settings/roles';
const SETTINGS_VIEW_PERMISSION_CODE = 'platform.member_admin.view';

export const PLATFORM_DEFAULT_MENU_KEY = USER_MENU_KEY;

export const PLATFORM_NAV_GROUP_FALLBACK = Object.freeze({
  [SETTINGS_MENU_KEY]: USER_MENU_KEY
});

export const PLATFORM_MENU_PERMISSION_REGISTRY = Object.freeze({
  [SETTINGS_MENU_KEY]: SETTINGS_VIEW_PERMISSION_CODE,
  [USER_MENU_KEY]: SETTINGS_VIEW_PERMISSION_CODE,
  [ROLE_MENU_KEY]: SETTINGS_VIEW_PERMISSION_CODE,
  [ORG_MENU_KEY]: SETTINGS_VIEW_PERMISSION_CODE
});

export const resolvePlatformMenuPermissionCode = (menuKey) => {
  const normalizedKey = String(menuKey || '').trim();
  return PLATFORM_MENU_PERMISSION_REGISTRY[normalizedKey] || '';
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
        key: ORG_MENU_KEY,
        permission_code: resolvePlatformMenuPermissionCode(ORG_MENU_KEY),
        icon: <ApartmentOutlined />,
        label: <span data-testid="platform-tab-orgs">组织管理</span>
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
  [ORG_MENU_KEY]: {
    title: '组织管理',
    subTitle: '平台设置 / 组织管理',
    permission_code: resolvePlatformMenuPermissionCode(ORG_MENU_KEY),
    breadcrumbItems: [
      { key: SETTINGS_MENU_KEY, title: '设置' },
      { key: ORG_MENU_KEY, title: '组织管理' }
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

export const resolvePlatformOpenKeys = (menuKey) => {
  const normalizedKey = String(menuKey || '').trim();
  if (!normalizedKey.includes('/')) {
    return [];
  }
  return [normalizedKey.split('/')[0]];
};
