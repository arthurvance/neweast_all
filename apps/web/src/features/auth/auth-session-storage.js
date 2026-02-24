import {
  asTenantOptions,
  normalizeEntryDomain,
  normalizeUserName
} from './session-model';

const AUTH_SESSION_STORAGE_KEY = 'neweast.auth.session.v1';
const LOGIN_ENTRY_DOMAIN_PATH_PATTERN = /^\/login\/(platform|tenant)\/?$/i;

const readExplicitEntryDomainFromLocation = (locationLike) => {
  if (!locationLike || typeof locationLike !== 'object') {
    return null;
  }
  const pathname = String(locationLike.pathname || '');
  const pathMatch = pathname.match(LOGIN_ENTRY_DOMAIN_PATH_PATTERN);
  if (!pathMatch) {
    return null;
  }
  return normalizeEntryDomain(pathMatch[1]);
};

export const readEntryDomainFromLocation = (locationLike) => {
  if (!locationLike || typeof locationLike !== 'object') {
    return 'tenant';
  }

  const pathname = String(locationLike.pathname || '');
  const pathMatch = pathname.match(LOGIN_ENTRY_DOMAIN_PATH_PATTERN);
  if (pathMatch) {
    return normalizeEntryDomain(pathMatch[1]);
  }

  return 'tenant';
};

export const clearPersistedAuthSession = () => {
  if (typeof window === 'undefined') {
    return;
  }
  window.sessionStorage.removeItem(AUTH_SESSION_STORAGE_KEY);
};

export const readPersistedAuthSession = () => {
  if (typeof window === 'undefined') {
    return null;
  }
  const raw = window.sessionStorage.getItem(AUTH_SESSION_STORAGE_KEY);
  if (!raw) {
    return null;
  }
  try {
    const parsed = JSON.parse(raw);
    const snapshot = parsed && typeof parsed === 'object' ? parsed : {};
    const rawSession = snapshot.sessionState && typeof snapshot.sessionState === 'object'
      ? snapshot.sessionState
      : null;
    const accessToken = String(rawSession?.access_token || '').trim();
    if (!accessToken) {
      clearPersistedAuthSession();
      return null;
    }
    const sessionState = {
      access_token: accessToken,
      session_id: rawSession?.session_id ? String(rawSession.session_id) : null,
      entry_domain: normalizeEntryDomain(rawSession?.entry_domain),
      user_name: normalizeUserName(rawSession?.user_name),
      active_tenant_id: rawSession?.active_tenant_id ? String(rawSession.active_tenant_id).trim() : null,
      tenant_selection_required: Boolean(rawSession?.tenant_selection_required),
      platform_permission_context:
        rawSession?.platform_permission_context
          && typeof rawSession.platform_permission_context === 'object'
          ? rawSession.platform_permission_context
          : null,
      tenant_permission_context:
        rawSession?.tenant_permission_context && typeof rawSession.tenant_permission_context === 'object'
          ? rawSession.tenant_permission_context
          : null
    };
    const explicitEntryDomain = readExplicitEntryDomainFromLocation(window.location);
    if (explicitEntryDomain && explicitEntryDomain !== sessionState.entry_domain) {
      clearPersistedAuthSession();
      return null;
    }
    const tenantOptions = asTenantOptions(snapshot.tenantOptions);
    const fallbackTenantId = String(sessionState.active_tenant_id || '').trim()
      || (tenantOptions[0] ? tenantOptions[0].tenant_id : '');
    const tenantSelectionValue = String(snapshot.tenantSelectionValue || '').trim() || fallbackTenantId;
    const tenantSwitchValue = String(snapshot.tenantSwitchValue || '').trim() || fallbackTenantId;
    return {
      sessionState,
      tenantOptions,
      tenantSelectionValue,
      tenantSwitchValue
    };
  } catch (_error) {
    clearPersistedAuthSession();
    return null;
  }
};

export const persistAuthSession = ({
  sessionState,
  tenantOptions,
  tenantSelectionValue,
  tenantSwitchValue
}) => {
  if (typeof window === 'undefined') {
    return;
  }
  const accessToken = String(sessionState?.access_token || '').trim();
  if (!accessToken) {
    clearPersistedAuthSession();
    return;
  }
  const snapshot = {
    sessionState: {
      access_token: accessToken,
      session_id: sessionState?.session_id ? String(sessionState.session_id) : null,
      entry_domain: normalizeEntryDomain(sessionState?.entry_domain),
      user_name: normalizeUserName(sessionState?.user_name),
      active_tenant_id: sessionState?.active_tenant_id ? String(sessionState.active_tenant_id).trim() : null,
      tenant_selection_required: Boolean(sessionState?.tenant_selection_required),
      platform_permission_context:
        sessionState?.platform_permission_context
          && typeof sessionState.platform_permission_context === 'object'
          ? sessionState.platform_permission_context
          : null,
      tenant_permission_context:
        sessionState?.tenant_permission_context && typeof sessionState.tenant_permission_context === 'object'
          ? sessionState.tenant_permission_context
          : null
    },
    tenantOptions: asTenantOptions(tenantOptions),
    tenantSelectionValue: String(tenantSelectionValue || '').trim(),
    tenantSwitchValue: String(tenantSwitchValue || '').trim()
  };
  window.sessionStorage.setItem(AUTH_SESSION_STORAGE_KEY, JSON.stringify(snapshot));
};
