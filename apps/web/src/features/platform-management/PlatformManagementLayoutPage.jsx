import { useMemo, useState } from 'react';
import CustomLayout from '../../components/CustomLayout';
import CustomPage from '../../components/CustomPage';
import {
  PLATFORM_DEFAULT_MENU_KEY,
  PLATFORM_NAV_GROUP_FALLBACK,
  PLATFORM_NAV_ITEMS,
  PLATFORM_PAGE_REGISTRY,
  resolvePlatformMenuKey,
  resolvePlatformOpenKeys
} from './platform-management.config';

export default function PlatformManagementLayoutPage({ accessToken, onLogout }) {
  const [activeMenuKey, setActiveMenuKey] = useState(PLATFORM_DEFAULT_MENU_KEY);
  const resolvedMenuKey = resolvePlatformMenuKey(activeMenuKey);
  const pageMeta = PLATFORM_PAGE_REGISTRY[resolvedMenuKey] || PLATFORM_PAGE_REGISTRY[PLATFORM_DEFAULT_MENU_KEY];
  const ActivePageComponent = pageMeta.Component;

  const menuItems = useMemo(() => PLATFORM_NAV_ITEMS, []);
  const openKeys = resolvePlatformOpenKeys(resolvedMenuKey);

  return (
    <section data-testid="platform-governance-panel" style={{ minHeight: '100vh' }}>
      <CustomLayout
        title="平台管理"
        menuItems={menuItems}
        selectedKeys={[resolvedMenuKey]}
        openKeys={openKeys}
        onMenuClick={({ key }) => {
          const nextKey = String(key || '').trim();
          if (PLATFORM_PAGE_REGISTRY[nextKey]) {
            setActiveMenuKey(nextKey);
            return;
          }
          if (PLATFORM_NAV_GROUP_FALLBACK[nextKey]) {
            setActiveMenuKey(PLATFORM_NAV_GROUP_FALLBACK[nextKey]);
          }
        }}
        onUserMenuClick={({ key }) => {
          if (String(key || '').trim() === 'logout') {
            onLogout?.();
          }
        }}
        showNotification={false}
        footerRender={false}
        showBreadcrumb={false}
        contentStyle={{
          margin: 16,
          padding: 16,
          minHeight: 'calc(100vh - 88px)'
        }}
        userInfo={{ name: '平台管理员' }}
      >
        <CustomPage
          title={pageMeta.title}
          subTitle={pageMeta.subTitle}
          showBreadcrumb
          breadcrumbItems={pageMeta.breadcrumbItems}
          bodyStyle={{ display: 'grid', gap: 12 }}
        >
          <ActivePageComponent accessToken={accessToken} />
        </CustomPage>
      </CustomLayout>
    </section>
  );
}
