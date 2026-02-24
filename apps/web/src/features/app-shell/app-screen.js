export const APP_SCREEN_LOGIN = 'login';
export const APP_SCREEN_DASHBOARD = 'dashboard';
export const APP_SCREEN_TENANT_SELECT = 'tenant-select';
export const APP_SCREEN_TENANT_SWITCH = 'tenant-switch';

const normalizePathname = (pathname) => {
  const raw = String(pathname || '').trim();
  if (!raw || raw === '/') {
    return '/';
  }
  return raw.endsWith('/') ? raw.slice(0, -1) : raw;
};

export const resolvePreferredScreenFromPathname = (pathname) => {
  const normalizedPathname = normalizePathname(pathname).toLowerCase();
  if (normalizedPathname === '/tenant/select') {
    return APP_SCREEN_TENANT_SELECT;
  }
  if (normalizedPathname === '/tenant/switch') {
    return APP_SCREEN_TENANT_SWITCH;
  }
  if (
    normalizedPathname === '/platform'
    || normalizedPathname === '/tenant'
    || normalizedPathname === '/dashboard'
  ) {
    return APP_SCREEN_DASHBOARD;
  }
  if (
    normalizedPathname === '/login/platform'
    || normalizedPathname === '/login/tenant'
  ) {
    return APP_SCREEN_LOGIN;
  }
  return APP_SCREEN_LOGIN;
};

export const resolveInitialScreen = ({
  restoredSession = null,
  preferredScreen = APP_SCREEN_LOGIN
} = {}) => {
  if (!restoredSession || typeof restoredSession !== 'object') {
    return APP_SCREEN_LOGIN;
  }
  const entryDomain = String(restoredSession.entry_domain || '').trim().toLowerCase();
  if (entryDomain === 'tenant' && restoredSession.tenant_selection_required) {
    return APP_SCREEN_TENANT_SELECT;
  }
  if (
    entryDomain === 'tenant'
    && (
      preferredScreen === APP_SCREEN_TENANT_SELECT
      || preferredScreen === APP_SCREEN_TENANT_SWITCH
    )
  ) {
    return preferredScreen;
  }
  return APP_SCREEN_DASHBOARD;
};

export const resolvePathForScreen = ({
  screen = APP_SCREEN_LOGIN,
  entryDomain = 'tenant',
  sessionState = null
} = {}) => {
  const normalizedScreen = String(screen || APP_SCREEN_LOGIN).trim().toLowerCase();
  const normalizedEntryDomain = String(entryDomain || 'tenant').trim().toLowerCase() === 'platform'
    ? 'platform'
    : 'tenant';

  if (normalizedScreen === APP_SCREEN_LOGIN) {
    return `/login/${normalizedEntryDomain}`;
  }
  if (normalizedScreen === APP_SCREEN_TENANT_SELECT) {
    return '/tenant/select';
  }
  if (normalizedScreen === APP_SCREEN_TENANT_SWITCH) {
    return '/tenant/switch';
  }
  if (normalizedScreen === APP_SCREEN_DASHBOARD) {
    const resolvedDomain = String(sessionState?.entry_domain || '').trim().toLowerCase();
    if (resolvedDomain === 'platform') {
      return '/platform';
    }
    if (resolvedDomain === 'tenant') {
      return '/tenant';
    }
    return '/dashboard';
  }
  return '/login/tenant';
};
