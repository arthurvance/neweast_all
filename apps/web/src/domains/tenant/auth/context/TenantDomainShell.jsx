import TenantDashboardFallbackPanel from './TenantDashboardFallbackPanel';
import TenantManagementLayoutPage from '../../account/workbench/TenantManagementLayoutPage';
import TenantSwitchScreen from '../session/TenantSwitchScreen';
import {
  APP_SCREEN_DASHBOARD,
  APP_SCREEN_TENANT_SWITCH
} from '../../../../features/app-shell/app-screen';

export default function TenantDomainShell({
  screen,
  sessionState,
  tenantOptions,
  tenantSwitchValue,
  onTenantSwitchValueChange,
  isTenantSubmitting,
  permissionState,
  permissionUiState,
  isTenantManagementDashboardScreen,
  onLogout,
  onTenantPermissionContextRefresh,
  onTenantSwitchFromDashboard,
  onOpenTenantSwitchPage,
  onTenantSwitchFromSwitchPage
}) {
  if (screen === APP_SCREEN_DASHBOARD && sessionState?.entry_domain === 'tenant') {
    if (isTenantManagementDashboardScreen) {
      return (
        <TenantManagementLayoutPage
          accessToken={sessionState?.access_token}
          userName={sessionState?.user_name}
          tenantPermissionContext={sessionState?.tenant_permission_context || null}
          onLogout={onLogout}
          onTenantPermissionContextRefresh={onTenantPermissionContextRefresh}
          tenantOptions={tenantOptions}
          activeTenantId={tenantSwitchValue || sessionState?.active_tenant_id || ''}
          onTenantSwitch={onTenantSwitchFromDashboard}
          onOpenTenantSwitchPage={onOpenTenantSwitchPage}
        />
      );
    }

    return (
      <TenantDashboardFallbackPanel
        sessionState={sessionState}
        tenantOptions={tenantOptions}
        tenantSwitchValue={tenantSwitchValue}
        isTenantSubmitting={isTenantSubmitting}
        onTenantSwitchValueChange={onTenantSwitchValueChange}
        onTenantSwitchConfirm={onTenantSwitchFromDashboard}
        permissionState={permissionState}
        permissionUiState={permissionUiState}
      />
    );
  }

  if (screen === APP_SCREEN_TENANT_SWITCH) {
    return (
      <TenantSwitchScreen
        tenantOptions={tenantOptions}
        activeTenantId={tenantSwitchValue || sessionState?.active_tenant_id || ''}
        onSelect={onTenantSwitchFromSwitchPage}
      />
    );
  }

  return null;
}
