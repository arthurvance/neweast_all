import TenantDomainShell from './TenantDomainShell';

export default function TenantApp({
  screen,
  sessionState,
  tenantOptions,
  tenantSelectionValue,
  onTenantSelectionChange,
  onTenantSelectConfirm,
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
      tenantSelectionValue={tenantSelectionValue}
      onTenantSelectionChange={onTenantSelectionChange}
      onTenantSelectConfirm={onTenantSelectConfirm}
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
