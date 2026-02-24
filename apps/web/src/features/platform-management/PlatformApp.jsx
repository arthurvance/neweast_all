import PlatformDomainShell from './PlatformDomainShell';

export default function PlatformApp({
  screen,
  sessionState,
  onLogout,
  onPlatformPermissionContextRefresh
}) {
  return (
    <PlatformDomainShell
      screen={screen}
      sessionState={sessionState}
      onLogout={onLogout}
      onPlatformPermissionContextRefresh={onPlatformPermissionContextRefresh}
    />
  );
}
