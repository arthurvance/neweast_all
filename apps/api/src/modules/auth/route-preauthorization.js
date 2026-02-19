const ROUTE_PREAUTHORIZED_FLAG = Symbol('neweast.auth.route.preauthorized');
const ROUTE_PREAUTHORIZED_PERMISSION_KEY = Symbol('neweast.auth.route.permission_code');
const ROUTE_PREAUTHORIZED_SCOPE_KEY = Symbol('neweast.auth.route.scope');

const normalizeRequiredString = (value) => {
  if (typeof value !== 'string') {
    return '';
  }
  return value.trim();
};

const resolveRoutePreauthorizedEntryDomain = (authorizationContext = null) => {
  if (!authorizationContext || typeof authorizationContext !== 'object') {
    return '';
  }
  const directEntryDomain = normalizeRequiredString(
    authorizationContext.entry_domain || authorizationContext.entryDomain
  ).toLowerCase();
  if (directEntryDomain) {
    return directEntryDomain;
  }
  const sessionContextEntryDomain = normalizeRequiredString(
    authorizationContext.session_context?.entry_domain
      || authorizationContext.session_context?.entryDomain
      || authorizationContext.sessionContext?.entry_domain
      || authorizationContext.sessionContext?.entryDomain
  ).toLowerCase();
  if (sessionContextEntryDomain) {
    return sessionContextEntryDomain;
  }
  return normalizeRequiredString(
    authorizationContext.session?.sessionContext?.entry_domain
      || authorizationContext.session?.sessionContext?.entryDomain
      || authorizationContext.session?.session_context?.entry_domain
      || authorizationContext.session?.session_context?.entryDomain
      || authorizationContext.session?.entry_domain
      || authorizationContext.session?.entryDomain
  ).toLowerCase();
};

const markRoutePreauthorizedContext = ({
  authorizationContext = null,
  permissionCode = '',
  scope = ''
} = {}) => {
  if (!authorizationContext || typeof authorizationContext !== 'object') {
    return null;
  }
  return {
    ...authorizationContext,
    [ROUTE_PREAUTHORIZED_FLAG]: true,
    [ROUTE_PREAUTHORIZED_PERMISSION_KEY]: normalizeRequiredString(permissionCode),
    [ROUTE_PREAUTHORIZED_SCOPE_KEY]: normalizeRequiredString(scope)
  };
};

const resolveRoutePreauthorizedContext = ({
  authorizationContext = null,
  expectedPermissionCode = '',
  expectedScope = '',
  expectedEntryDomain = ''
} = {}) => {
  if (!authorizationContext || typeof authorizationContext !== 'object') {
    return null;
  }
  if (authorizationContext[ROUTE_PREAUTHORIZED_FLAG] !== true) {
    return null;
  }

  const normalizedExpectedPermissionCode = normalizeRequiredString(
    expectedPermissionCode
  );
  if (
    normalizedExpectedPermissionCode
    && normalizeRequiredString(
      authorizationContext[ROUTE_PREAUTHORIZED_PERMISSION_KEY]
    ) !== normalizedExpectedPermissionCode
  ) {
    return null;
  }

  const normalizedExpectedScope = normalizeRequiredString(expectedScope)
    .toLowerCase();
  if (
    normalizedExpectedScope
    && normalizeRequiredString(
      authorizationContext[ROUTE_PREAUTHORIZED_SCOPE_KEY]
    ).toLowerCase() !== normalizedExpectedScope
  ) {
    return null;
  }

  const resolvedEntryDomain = resolveRoutePreauthorizedEntryDomain(
    authorizationContext
  );
  const normalizedExpectedEntryDomain = normalizeRequiredString(
    expectedEntryDomain
  ).toLowerCase();
  if (
    normalizedExpectedEntryDomain
    && resolvedEntryDomain !== normalizedExpectedEntryDomain
  ) {
    return null;
  }

  const userId = normalizeRequiredString(
    authorizationContext.user_id
      || authorizationContext.userId
      || authorizationContext.user?.id
      || authorizationContext.user?.user_id
      || authorizationContext.user?.userId
  );
  const sessionId = normalizeRequiredString(
    authorizationContext.session_id
      || authorizationContext.sessionId
      || authorizationContext.session?.sessionId
      || authorizationContext.session?.session_id
  );
  if (!userId || !sessionId) {
    return null;
  }

  return {
    userId,
    sessionId,
    entryDomain: resolvedEntryDomain
  };
};

module.exports = {
  markRoutePreauthorizedContext,
  resolveRoutePreauthorizedContext
};
