import PlatformManagementLayoutPage from './PlatformManagementLayoutPage';
import { APP_SCREEN_DASHBOARD } from '../app-shell/app-screen';

export default function PlatformDomainShell({
  screen,
  sessionState,
  onLogout
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
    />
  );
}
