export default function TenantDashboardFallbackPanel({
  sessionState = null,
  tenantOptions = [],
  tenantSwitchValue = '',
  isTenantSubmitting = false,
  onTenantSwitchValueChange = null,
  onTenantSwitchConfirm = null,
  permissionState = null,
  permissionUiState = null
}) {
  return (
    <section
      data-testid="dashboard-panel"
      style={{
        marginTop: 16,
        background: '#f6f8fa',
        borderRadius: 8,
        padding: 12,
        display: 'grid',
        gap: 12
      }}
    >
      <h2 style={{ margin: 0 }}>已登录工作台</h2>
      <p style={{ margin: 0 }}>会话：{sessionState?.session_id || '-'}</p>
      {sessionState?.entry_domain === 'tenant' ? (
        <>
          <p style={{ margin: 0 }}>
            当前组织：{sessionState?.active_tenant_id || '未选择'}
          </p>
          <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
            <select
              data-testid="tenant-switch"
              value={tenantSwitchValue}
              onChange={(event) => onTenantSwitchValueChange?.(event.target.value)}
              disabled={isTenantSubmitting}
              style={{
                flex: 1,
                padding: '8px 10px',
                borderRadius: 6,
                border: '1px solid #d0d7de'
              }}
            >
              {tenantOptions.map((option) => (
                <option key={option.tenant_id} value={option.tenant_id}>
                  {option.tenant_name || option.tenant_id}
                </option>
              ))}
            </select>
            <button
              data-testid="tenant-switch-confirm"
              type="button"
              onClick={onTenantSwitchConfirm}
              disabled={isTenantSubmitting || tenantOptions.length === 0}
              style={{ padding: '8px 12px', borderRadius: 6, border: '1px solid #d0d7de' }}
            >
              {isTenantSubmitting ? '切换中...' : '切换组织'}
            </button>
          </div>
          <section
            data-testid="permission-panel"
            style={{
              display: 'grid',
              gap: 8,
              background: '#fff',
              borderRadius: 6,
              border: '1px solid #e5e7eb',
              padding: 10
            }}
          >
            <p data-testid="permission-scope" style={{ margin: 0 }}>
              权限上下文：{permissionState?.scope_label}
            </p>
            <nav aria-label="tenant-permission-menu">
              <p style={{ margin: 0 }}>可见菜单</p>
              <ul style={{ margin: '4px 0 0 20px', padding: 0 }}>
                {permissionUiState?.menu?.customer_management ? (
                  <li data-testid="menu-customer_management">客户资料</li>
                ) : null}
                {permissionUiState?.menu?.user_management ? (
                  <li data-testid="menu-user-management">用户管理</li>
                ) : null}
                {permissionUiState?.menu?.role_management ? (
                  <li data-testid="menu-role_management">角色管理</li>
                ) : null}
                {permissionUiState?.menu?.account_management ? (
                  <li data-testid="menu-account_management">账号管理</li>
                ) : null}
                {!permissionUiState?.menu?.customer_management
                && !permissionUiState?.menu?.user_management
                && !permissionUiState?.menu?.role_management
                && !permissionUiState?.menu?.account_management ? (
                  <li data-testid="menu-empty">当前无可见菜单</li>
                ) : null}
              </ul>
            </nav>
            {permissionUiState?.action?.customer_management ? (
              <button
                data-testid="permission-customer_management-button"
                type="button"
                style={{ padding: '8px 12px', borderRadius: 6, border: '1px solid #d0d7de' }}
              >
                客户资料
              </button>
            ) : null}
            {permissionUiState?.action?.user_management ? (
              <button
                data-testid="permission-user-management-button"
                type="button"
                style={{ padding: '8px 12px', borderRadius: 6, border: '1px solid #d0d7de' }}
              >
                用户管理
              </button>
            ) : null}
            {permissionUiState?.action?.role_management ? (
              <button
                data-testid="permission-role_management-button"
                type="button"
                style={{ padding: '8px 12px', borderRadius: 6, border: '1px solid #d0d7de' }}
              >
                角色管理
              </button>
            ) : null}
            {permissionUiState?.action?.account_management ? (
              <button
                data-testid="permission-account_management-button"
                type="button"
                style={{ padding: '8px 12px', borderRadius: 6, border: '1px solid #d0d7de' }}
              >
                账号管理
              </button>
            ) : null}
          </section>
          <section
            data-testid="tenant-management-panel"
            style={{
              display: 'grid',
              gap: 8,
              background: '#fff',
              borderRadius: 6,
              border: '1px solid #e5e7eb',
              padding: 10
            }}
          >
            <p style={{ margin: 0 }}>当前组织无成员治理权限，治理工作台已按 fail-closed 隐藏。</p>
          </section>
        </>
      ) : null}
    </section>
  );
}
