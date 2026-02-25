import TenantDomainShell from './auth/context/TenantDomainShell';

export default function TenantApp({
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
  return (
    <TenantDomainShell
      screen={screen}
      sessionState={sessionState}
      tenantOptions={tenantOptions}
      tenantSwitchValue={tenantSwitchValue}
      onTenantSwitchValueChange={onTenantSwitchValueChange}
      isTenantSubmitting={isTenantSubmitting}
      permissionState={permissionState}
      permissionUiState={permissionUiState}
      isTenantManagementDashboardScreen={isTenantManagementDashboardScreen}
      onLogout={onLogout}
      onTenantPermissionContextRefresh={onTenantPermissionContextRefresh}
      onTenantSwitchFromDashboard={onTenantSwitchFromDashboard}
      onOpenTenantSwitchPage={onOpenTenantSwitchPage}
      onTenantSwitchFromSwitchPage={onTenantSwitchFromSwitchPage}
    />
  );
}
