const normalizeTenantId = (value) => String(value || '').trim();
const normalizeSessionField = (value) => String(value || '').trim();
const normalizeSessionBindingValue = (value) => String(value || '').trim();
const normalizeUserName = (value) => {
  const normalized = String(value || '').trim();
  return normalized || null;
};
const asNullableObject = (value) =>
  value && typeof value === 'object' ? value : null;
const asObjectOrEmpty = (value) =>
  value && typeof value === 'object' ? value : {};

const decodeBase64UrlPayload = (value) => {
  const normalizedValue = String(value || '')
    .replace(/-/g, '+')
    .replace(/_/g, '/');
  const paddedValue = normalizedValue.padEnd(Math.ceil(normalizedValue.length / 4) * 4, '=');
  if (typeof window !== 'undefined' && typeof window.atob === 'function') {
    return window.atob(paddedValue);
  }
  if (typeof atob === 'function') {
    return atob(paddedValue);
  }
  if (typeof Buffer !== 'undefined') {
    return Buffer.from(paddedValue, 'base64').toString('utf8');
  }
  return '';
};

export const readSessionIdFromAccessToken = (accessToken) => {
  if (typeof accessToken !== 'string' || accessToken.length === 0) {
    return '';
  }
  const parts = accessToken.split('.');
  if (parts.length < 2) {
    return '';
  }
  try {
    const payload = JSON.parse(decodeBase64UrlPayload(parts[1]));
    return normalizeSessionBindingValue(payload?.sid || payload?.session_id);
  } catch (_error) {
    return '';
  }
};

export const isTenantRefreshResultBoundToCurrentSession = ({
  currentSession,
  expectedSession,
  requestAccessToken,
  requestSessionId,
  responsePayload
}) => {
  const sessionBindingContext = expectedSession && typeof expectedSession === 'object'
    ? expectedSession
    : currentSession;
  const activeAccessToken = String(
    sessionBindingContext?.access_token || currentSession?.access_token || ''
  );
  if (!activeAccessToken) {
    return false;
  }

  const activeSessionId = normalizeSessionBindingValue(
    sessionBindingContext?.session_id || currentSession?.session_id
  );
  const normalizedRequestSessionId = normalizeSessionBindingValue(requestSessionId);
  const responseSessionId = normalizeSessionBindingValue(responsePayload?.session_id);
  const candidateSessionId = responseSessionId || normalizedRequestSessionId;

  if (
    candidateSessionId
    && activeSessionId
    && candidateSessionId !== activeSessionId
  ) {
    return false;
  }

  if (!candidateSessionId && requestAccessToken !== activeAccessToken) {
    return false;
  }

  if (!activeSessionId && requestAccessToken !== activeAccessToken) {
    return false;
  }

  return true;
};

export const resolveTenantMutationPermissionContext = ({
  hasTenantPermissionContext,
  nextTenantPermissionContext
}) => (hasTenantPermissionContext ? asNullableObject(nextTenantPermissionContext) : null);

export const resolveTenantMutationUiState = ({
  nextTenantOptions,
  nextActiveTenantId,
  hasTenantOptions,
  previousTenantSelectionValue,
  previousTenantOptions
}) => {
  const normalizedHasTenantOptions = hasTenantOptions === true;
  const normalizedOptions = normalizedHasTenantOptions
    ? Array.isArray(nextTenantOptions)
      ? nextTenantOptions
      : []
    : null;
  const normalizedPreviousOptions = Array.isArray(previousTenantOptions)
    ? previousTenantOptions
    : [];
  const normalizedActiveTenantId = normalizeTenantId(nextActiveTenantId);
  const normalizedPreviousSelection = normalizeTenantId(previousTenantSelectionValue);

  if (normalizedOptions && normalizedOptions.length > 0) {
    const firstTenantId = normalizeTenantId(normalizedOptions[0].tenant_id);
    const hasActiveTenant = normalizedOptions.some(
      (option) =>
        normalizedActiveTenantId.length > 0
        && normalizeTenantId(option.tenant_id) === normalizedActiveTenantId
    );
    const hasExistingTenant = normalizedOptions.some(
      (option) =>
        normalizedPreviousSelection.length > 0
        && normalizeTenantId(option.tenant_id) === normalizedPreviousSelection
    );
    const nextSelectedTenantId = hasActiveTenant
      ? normalizedActiveTenantId
      : hasExistingTenant
      ? normalizedPreviousSelection
      : firstTenantId;
    return {
      tenantOptionsUpdate: normalizedOptions,
      tenantSelectionValue: nextSelectedTenantId,
      tenantSwitchValue: nextSelectedTenantId
    };
  }

  if (!normalizedHasTenantOptions) {
    if (normalizedPreviousOptions.length > 0) {
      const firstKnownTenantId = normalizeTenantId(normalizedPreviousOptions[0].tenant_id);
      const hasActiveTenantInKnownOptions = normalizedPreviousOptions.some(
        (option) =>
          normalizedActiveTenantId.length > 0
          && normalizeTenantId(option.tenant_id) === normalizedActiveTenantId
      );
      const hasPreviousSelectionInKnownOptions = normalizedPreviousOptions.some(
        (option) =>
          normalizedPreviousSelection.length > 0
          && normalizeTenantId(option.tenant_id) === normalizedPreviousSelection
      );
      const nextSelectedTenantId = hasActiveTenantInKnownOptions
        ? normalizedActiveTenantId
        : hasPreviousSelectionInKnownOptions
        ? normalizedPreviousSelection
        : firstKnownTenantId;
      return {
        tenantOptionsUpdate: undefined,
        tenantSelectionValue: nextSelectedTenantId,
        tenantSwitchValue: nextSelectedTenantId
      };
    }
    return {
      tenantOptionsUpdate: undefined,
      tenantSelectionValue: '',
      tenantSwitchValue: ''
    };
  }

  if (normalizedActiveTenantId) {
    return {
      tenantOptionsUpdate: [],
      tenantSelectionValue: '',
      tenantSwitchValue: ''
    };
  }

  return {
    tenantOptionsUpdate: [],
    tenantSelectionValue: '',
    tenantSwitchValue: ''
  };
};

export const resolveTenantMutationSessionState = ({
  previousSessionState,
  payload,
  nextActiveTenantId,
  nextTenantPermissionContext
}) => {
  const previous = asObjectOrEmpty(previousSessionState);
  const normalizedPayload = asObjectOrEmpty(payload);
  const nextAccessToken = normalizeSessionField(normalizedPayload.access_token);
  const nextSessionId = normalizeSessionField(normalizedPayload.session_id);
  const nextEntryDomain = normalizeSessionField(normalizedPayload.entry_domain);
  const normalizedActiveTenantId = normalizeTenantId(nextActiveTenantId);
  const hasUserNameField = Object.prototype.hasOwnProperty.call(normalizedPayload, 'user_name');

  return {
    ...previous,
    access_token: nextAccessToken || previous.access_token || null,
    session_id: nextSessionId || previous.session_id || null,
    entry_domain: nextEntryDomain || previous.entry_domain || 'tenant',
    user_name: hasUserNameField
      ? normalizeUserName(normalizedPayload.user_name)
      : normalizeUserName(previous.user_name),
    active_tenant_id: normalizedActiveTenantId || null,
    tenant_selection_required: Boolean(normalizedPayload.tenant_selection_required),
    tenant_permission_context: nextTenantPermissionContext
  };
};

export const resolveTenantRefreshUiState = ({
  tenantOptions,
  activeTenantId,
  previousTenantSelectionValue
}) =>
  resolveTenantMutationUiState({
    nextTenantOptions: tenantOptions,
    nextActiveTenantId: activeTenantId,
    hasTenantOptions: true,
    previousTenantSelectionValue
  });
