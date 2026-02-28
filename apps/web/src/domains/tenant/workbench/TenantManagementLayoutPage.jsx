import { Empty, Spin } from 'antd';
import { Suspense, useEffect, useMemo, useState } from 'react';
import CustomLayout from '../../../components/CustomLayout';
import CustomPage from '../../../components/CustomPage';
import {
  TENANT_DEFAULT_MENU_KEY,
  TENANT_NAV_GROUP_FALLBACK,
  TENANT_PAGE_REGISTRY,
  SESSION_CENTER_MENU_KEY,
  resolveFirstTenantVisibleMenuKey,
  resolveTenantMenuKeyByPermission,
  resolveTenantNavItemsByPermission,
  resolveTenantOpenKeys
} from './tenant-management.config';

const TENANT_ACTIVE_MENU_STORAGE_KEY = 'tenant-management-active-menu-key';

const readTenantActiveMenuKey = () => {
  if (typeof window === 'undefined') {
    return '';
  }
  try {
    return String(
      window.sessionStorage.getItem(TENANT_ACTIVE_MENU_STORAGE_KEY) || ''
    ).trim();
  } catch (error) {
    return '';
  }
};

const persistTenantActiveMenuKey = (menuKey) => {
  if (typeof window === 'undefined') {
    return;
  }
  const normalizedMenuKey = String(menuKey || '').trim();
  if (!normalizedMenuKey) {
    return;
  }
  try {
    window.sessionStorage.setItem(TENANT_ACTIVE_MENU_STORAGE_KEY, normalizedMenuKey);
  } catch (error) {
    // Ignore storage write failures to keep menu navigation available.
  }
};

export default function TenantManagementLayoutPage({
  accessToken,
  userName,
  onLogout,
  tenantPermissionContext = null,
  onTenantPermissionContextRefresh,
  tenantOptions = [],
  activeTenantId = '',
  onOpenTenantSwitchPage = null
}) {
  const [activeMenuKey, setActiveMenuKey] = useState(
    () => readTenantActiveMenuKey() || TENANT_DEFAULT_MENU_KEY
  );
  const firstVisibleMenuKey = useMemo(
    () => resolveFirstTenantVisibleMenuKey(tenantPermissionContext),
    [tenantPermissionContext]
  );
  const hasVisiblePage = Boolean(firstVisibleMenuKey);
  const resolvedMenuKey = resolveTenantMenuKeyByPermission(
    activeMenuKey,
    tenantPermissionContext
  );
  const pageMeta = hasVisiblePage
    ? TENANT_PAGE_REGISTRY[resolvedMenuKey] || TENANT_PAGE_REGISTRY[firstVisibleMenuKey]
    : null;
  const displayPageMeta = pageMeta || {
    title: '组织设置',
    subTitle: '组织设置',
    breadcrumbItems: []
  };

  const isSessionCenter = resolvedMenuKey === SESSION_CENTER_MENU_KEY;
  const ActivePageComponent = pageMeta?.Component || null;

  const menuItems = useMemo(
    () => resolveTenantNavItemsByPermission(tenantPermissionContext),
    [tenantPermissionContext]
  );
  useEffect(() => {
    if (!resolvedMenuKey) {
      return;
    }
    if (resolvedMenuKey !== activeMenuKey) {
      setActiveMenuKey(resolvedMenuKey);
      return;
    }
    persistTenantActiveMenuKey(resolvedMenuKey);
  }, [activeMenuKey, resolvedMenuKey]);

  const openKeys = hasVisiblePage ? resolveTenantOpenKeys(resolvedMenuKey) : [];
  const displayUserName = String(userName || '').trim() || '-';
  const layoutTitle = useMemo(() => {
    const normalizedActiveTenantId = String(activeTenantId || '').trim();
    if (!normalizedActiveTenantId) {
      return '组织管理';
    }
    const matchedTenant = (Array.isArray(tenantOptions) ? tenantOptions : []).find(
      (tenant) => String(tenant?.tenant_id || '').trim() === normalizedActiveTenantId
    );
    const normalizedTenantName = String(matchedTenant?.tenant_name || '').trim();
    return normalizedTenantName || normalizedActiveTenantId || '组织管理';
  }, [activeTenantId, tenantOptions]);
  const userMenuItems = useMemo(
    () => [
      { key: 'settings', label: '个人设置' },
      { key: 'switch-org', label: '切换组织' },
      { type: 'divider' },
      { key: 'logout', label: '退出登录' }
    ],
    []
  );

  return (
    <section data-testid="tenant-management-panel" style={{ height: '100vh', display: 'flex', flexDirection: 'column' }}>
      <CustomLayout
        title={layoutTitle}
        menuItems={menuItems}
        selectedKeys={hasVisiblePage ? [resolvedMenuKey] : []}
        openKeys={openKeys}
        fixedHeader={false}
        fixSiderbar={false}
        onMenuClick={({ key }) => {
          const nextKey = String(key || '').trim();
          if (!nextKey) {
            return;
          }
          if (TENANT_PAGE_REGISTRY[nextKey]) {
            const nextPermittedMenuKey = resolveTenantMenuKeyByPermission(
              nextKey,
              tenantPermissionContext
            );
            if (nextPermittedMenuKey) {
              setActiveMenuKey(nextPermittedMenuKey);
            }
            return;
          }
          if (TENANT_NAV_GROUP_FALLBACK[nextKey]) {
            const fallbackMenuKey = resolveTenantMenuKeyByPermission(
              TENANT_NAV_GROUP_FALLBACK[nextKey],
              tenantPermissionContext
            );
            if (fallbackMenuKey) {
              setActiveMenuKey(fallbackMenuKey);
            }
          }
        }}
        userMenuItems={userMenuItems}
        onUserMenuClick={({ key }) => {
          const normalizedKey = String(key || '').trim();
          if (normalizedKey === 'logout') {
            onLogout?.();
            return;
          }
          if (normalizedKey === 'switch-org') {
            onOpenTenantSwitchPage?.();
            return;
          }
        }}
        showNotification={false}
        footerRender={false}
        contentStyle={{
          margin: 12,
          padding: 12,
          display: 'flex',
          flexDirection: 'column',
          flex: 1,
          minHeight: 0,
          overflow: 'hidden'
        }}
        userInfo={{ name: displayUserName }}
      >
        <CustomPage
          title={null}
          showBreadcrumb={false}
          breadcrumbItems={displayPageMeta.breadcrumbItems}
          style={{ display: 'flex', flexDirection: 'column', flex: 1, minHeight: 0 }}
          bodyStyle={{ display: 'flex', flexDirection: 'column', flex: 1, minHeight: 0, overflow: 'hidden', gap: isSessionCenter ? 0 : 12 }}
        >
          {hasVisiblePage && ActivePageComponent ? (
            <Suspense
              fallback={(
                <section
                  data-testid="tenant-page-loading"
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
                tenantPermissionContext={tenantPermissionContext}
                onTenantPermissionContextRefresh={onTenantPermissionContextRefresh}
              />
            </Suspense>
          ) : (
            <section
              data-testid="tenant-menu-empty"
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
