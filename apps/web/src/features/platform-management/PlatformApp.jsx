import PlatformDomainShell from './PlatformDomainShell';

export default function PlatformApp({
  screen,
  sessionState,
  onLogout
}) {
  return (
    <PlatformDomainShell
      screen={screen}
      sessionState={sessionState}
      onLogout={onLogout}
    />
  );
}
