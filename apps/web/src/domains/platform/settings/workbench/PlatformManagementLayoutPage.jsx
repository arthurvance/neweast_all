import { Empty, Spin } from 'antd';
import { Suspense, useMemo, useState } from 'react';
import CustomLayout from '../../../../components/CustomLayout';
import CustomPage from '../../../../components/CustomPage';
import {
  PLATFORM_DEFAULT_MENU_KEY,
  PLATFORM_NAV_GROUP_FALLBACK,
  PLATFORM_PAGE_REGISTRY,
  resolveFirstPlatformVisibleMenuKey,
  resolvePlatformMenuKeyByPermission,
  resolvePlatformNavItemsByPermission,
  resolvePlatformOpenKeys
} from './platform-management.config';

export default function PlatformManagementLayoutPage({
  accessToken,
  userName,
  onLogout,
  onPlatformPermissionContextRefresh,
  platformPermissionContext = null
}) {
  const [activeMenuKey, setActiveMenuKey] = useState(PLATFORM_DEFAULT_MENU_KEY);
  const firstVisibleMenuKey = useMemo(
    () => resolveFirstPlatformVisibleMenuKey(platformPermissionContext),
    [platformPermissionContext]
  );
  const hasVisiblePage = Boolean(firstVisibleMenuKey);
  const resolvedMenuKey = resolvePlatformMenuKeyByPermission(
    activeMenuKey,
    platformPermissionContext
  );
  const pageMeta = hasVisiblePage
    ? PLATFORM_PAGE_REGISTRY[resolvedMenuKey] || PLATFORM_PAGE_REGISTRY[firstVisibleMenuKey]
    : null;
  const displayPageMeta = pageMeta || {
    title: '平台设置',
    subTitle: '平台设置',
    breadcrumbItems: []
  };
  const ActivePageComponent = pageMeta?.Component || null;

  const menuItems = useMemo(
    () => resolvePlatformNavItemsByPermission(platformPermissionContext),
    [platformPermissionContext]
  );
  const openKeys = hasVisiblePage ? resolvePlatformOpenKeys(resolvedMenuKey) : [];
  const displayUserName = String(userName || '').trim() || '-';

  return (
    <section data-testid="platform-management-panel" style={{ minHeight: '100vh' }}>
      <CustomLayout
        title="平台管理"
        menuItems={menuItems}
        selectedKeys={hasVisiblePage ? [resolvedMenuKey] : []}
        openKeys={openKeys}
        onMenuClick={({ key }) => {
          const nextKey = String(key || '').trim();
          if (!nextKey) {
            return;
          }
          if (PLATFORM_PAGE_REGISTRY[nextKey]) {
            const nextPermittedMenuKey = resolvePlatformMenuKeyByPermission(
              nextKey,
              platformPermissionContext
            );
            if (nextPermittedMenuKey) {
              setActiveMenuKey(nextPermittedMenuKey);
            }
            return;
          }
          if (PLATFORM_NAV_GROUP_FALLBACK[nextKey]) {
            const fallbackMenuKey = resolvePlatformMenuKeyByPermission(
              PLATFORM_NAV_GROUP_FALLBACK[nextKey],
              platformPermissionContext
            );
            if (fallbackMenuKey) {
              setActiveMenuKey(fallbackMenuKey);
            }
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
        userInfo={{ name: displayUserName }}
      >
        <CustomPage
          title={displayPageMeta.title}
          showBreadcrumb={hasVisiblePage}
          breadcrumbItems={displayPageMeta.breadcrumbItems}
          bodyStyle={{ display: 'grid', gap: 12 }}
        >
          {hasVisiblePage && ActivePageComponent ? (
            <Suspense
              fallback={(
                <section
                  data-testid="platform-page-loading"
                  style={{
                    minHeight: 240,
                    display: 'grid',
                    placeItems: 'center'
                  }}
                >
                  <Spin />
                </section>
              )}
            >
              <ActivePageComponent
                accessToken={accessToken}
                onPlatformPermissionContextRefresh={onPlatformPermissionContextRefresh}
              />
            </Suspense>
          ) : (
            <section
              data-testid="platform-menu-empty"
              style={{
                minHeight: 240,
                display: 'grid',
                placeItems: 'center'
              }}
            >
              <Empty description="当前账号暂无可访问菜单" />
            </section>
          )}
        </CustomPage>
      </CustomLayout>
    </section>
  );
}
