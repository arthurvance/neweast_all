import PlatformManagementLayoutPage from '../../settings/workbench/PlatformManagementLayoutPage';
import { APP_SCREEN_DASHBOARD } from '../../../../features/app-shell/app-screen';

export default function PlatformDomainShell({
  screen,
  sessionState,
  onLogout,
  onPlatformPermissionContextRefresh
}) {
  if (screen !== APP_SCREEN_DASHBOARD || sessionState?.entry_domain !== 'platform') {
    return null;
  }

  return (
    <PlatformManagementLayoutPage
      accessToken={sessionState?.access_token}
      userName={sessionState?.user_name}
      platformPermissionContext={sessionState?.platform_permission_context || null}
      onLogout={onLogout}
      onPlatformPermissionContextRefresh={onPlatformPermissionContextRefresh}
    />
  );
}
