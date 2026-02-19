const {
  PLATFORM_ORG_CREATE_PATH,
  PLATFORM_ORG_STATUS_PATH,
  PLATFORM_ORG_OWNER_TRANSFER_PATH,
  PLATFORM_ORG_CREATE_PERMISSION_CODE,
  PLATFORM_ORG_SCOPE
} = require('./modules/platform/org.constants');
const {
  PLATFORM_ROLE_BASE_PATH,
  PLATFORM_ROLE_ITEM_PATH,
  PLATFORM_ROLE_PERMISSION_PATH,
  PLATFORM_ROLE_VIEW_PERMISSION_CODE,
  PLATFORM_ROLE_OPERATE_PERMISSION_CODE,
  PLATFORM_ROLE_SCOPE
} = require('./modules/platform/role.constants');
const {
  PLATFORM_USER_CREATE_PATH,
  PLATFORM_USER_STATUS_PATH,
  PLATFORM_USER_PERMISSION_CODE,
  PLATFORM_USER_SCOPE
} = require('./modules/platform/user.constants');
const {
  TENANT_MEMBER_LIST_PATH,
  TENANT_MEMBER_CREATE_PATH,
  TENANT_MEMBER_STATUS_PATH,
  TENANT_MEMBER_VIEW_PERMISSION_CODE,
  TENANT_MEMBER_OPERATE_PERMISSION_CODE,
  TENANT_MEMBER_SCOPE
} = require('./modules/tenant/member.constants');
const {
  TENANT_ROLE_BASE_PATH,
  TENANT_ROLE_ITEM_PATH,
  TENANT_ROLE_VIEW_PERMISSION_CODE,
  TENANT_ROLE_OPERATE_PERMISSION_CODE,
  TENANT_ROLE_SCOPE
} = require('./modules/tenant/role.constants');

const asMethod = (method) => String(method || 'GET').trim().toUpperCase();
const normalizeAccess = (access) => String(access || '').trim().toLowerCase();
const normalizeScope = (scope) => String(scope || '').trim().toLowerCase();
const normalizePermissionCode = (permissionCode) => String(permissionCode || '').trim();

const toPathnameString = (pathname) => String(pathname || '');
const normalizePathname = (pathname) => {
  if (!pathname || pathname === '/') {
    return '/';
  }
  return toPathnameString(pathname).replace(/\/+$/, '') || '/';
};
const ROUTE_PATH_PARAM_CONTROL_CHAR_PATTERN = /[\u0000-\u001F\u007F]/;
const hasConsecutiveSlashes = (pathname) =>
  toPathnameString(pathname).includes('//');
const hasTrailingSlash = (pathname) => {
  const raw = toPathnameString(pathname);
  return raw.length > 1 && raw.endsWith('/');
};
const hasNonCanonicalSlashes = (pathname) =>
  hasConsecutiveSlashes(pathname) || hasTrailingSlash(pathname);
const toPathSegments = (pathname) =>
  normalizePathname(pathname)
    .split('/')
    .filter((segment) => segment.length > 0);
const isPathParameterSegment = (segment = '') =>
  String(segment || '').startsWith(':') && String(segment || '').length > 1;
const decodeRoutePathParamSegment = (segment = '') => {
  const raw = String(segment || '');
  if (!raw) {
    return raw;
  }
  try {
    return decodeURIComponent(raw);
  } catch (_error) {
    return null;
  }
};
const isSafeDecodedRoutePathParamSegment = (decodedSegment) =>
  typeof decodedSegment === 'string'
  && decodedSegment.length > 0
  && decodedSegment.trim() === decodedSegment
  && !decodedSegment.includes('/')
  && !ROUTE_PATH_PARAM_CONTROL_CHAR_PATTERN.test(decodedSegment);
const isRoutePathMatch = (declaredPath, actualPath) => {
  if (
    hasNonCanonicalSlashes(declaredPath)
    || hasNonCanonicalSlashes(actualPath)
  ) {
    return false;
  }
  const declaredSegments = toPathSegments(declaredPath);
  const actualSegments = toPathSegments(actualPath);
  if (declaredSegments.length !== actualSegments.length) {
    return false;
  }
  for (let index = 0; index < declaredSegments.length; index += 1) {
    const declaredSegment = declaredSegments[index];
    const actualSegment = actualSegments[index];
    if (isPathParameterSegment(declaredSegment)) {
      if (actualSegment.length === 0) {
        return false;
      }
      const decodedSegment = decodeRoutePathParamSegment(actualSegment);
      if (!isSafeDecodedRoutePathParamSegment(decodedSegment)) {
        return false;
      }
      continue;
    }
    if (declaredSegment !== actualSegment) {
      return false;
    }
  }
  return true;
};
const extractRoutePathParams = (declaredPath, actualPath) => {
  if (!isRoutePathMatch(declaredPath, actualPath)) {
    return null;
  }
  const declaredSegments = toPathSegments(declaredPath);
  const actualSegments = toPathSegments(actualPath);
  const params = {};
  for (let index = 0; index < declaredSegments.length; index += 1) {
    const declaredSegment = declaredSegments[index];
    if (!isPathParameterSegment(declaredSegment)) {
      continue;
    }
    const decodedSegment = decodeRoutePathParamSegment(actualSegments[index]);
    if (!isSafeDecodedRoutePathParamSegment(decodedSegment)) {
      return null;
    }
    params[declaredSegment.slice(1)] = decodedSegment;
  }
  return params;
};

const asRouteKey = ({ method, path }) => `${asMethod(method)} ${normalizePathname(path)}`;
const toImmutableRouteDefinition = (route = {}) =>
  Object.freeze({
    method: asMethod(route.method),
    path: normalizePathname(route.path),
    access: normalizeAccess(route.access),
    permission_code: normalizePermissionCode(route.permission_code),
    scope: normalizeScope(route.scope)
  });
const createImmutableRouteDefinitions = (routeDefinitions = []) =>
  Object.freeze(routeDefinitions.map((route) => toImmutableRouteDefinition(route)));
const ROUTE_DEFINITION_SNAPSHOT_CACHE = new WeakMap();
const serializeRouteDefinition = (route = {}) =>
  JSON.stringify([
    asMethod(route.method),
    normalizePathname(route.path),
    normalizeAccess(route.access),
    normalizePermissionCode(route.permission_code),
    normalizeScope(route.scope)
  ]);
const computeRouteDefinitionsSignature = (routeDefinitions = []) =>
  `${routeDefinitions.length}:${routeDefinitions.map((route) => serializeRouteDefinition(route)).join('\n')}`;
const isImmutableRouteDefinitions = (routeDefinitions) =>
  Array.isArray(routeDefinitions)
  && Object.isFrozen(routeDefinitions)
  && routeDefinitions.every(
    (routeDefinition) =>
      routeDefinition && typeof routeDefinition === 'object' && Object.isFrozen(routeDefinition)
  );
const toRouteDefinitionsSnapshot = (routeDefinitions) => {
  if (!Array.isArray(routeDefinitions)) {
    return ROUTE_DEFINITIONS;
  }
  if (routeDefinitions === ROUTE_DEFINITIONS || isImmutableRouteDefinitions(routeDefinitions)) {
    return routeDefinitions;
  }
  const routeDefinitionsSignature = computeRouteDefinitionsSignature(routeDefinitions);
  const cachedSnapshotEntry = ROUTE_DEFINITION_SNAPSHOT_CACHE.get(routeDefinitions);
  if (
    cachedSnapshotEntry
    && cachedSnapshotEntry.signature === routeDefinitionsSignature
  ) {
    return cachedSnapshotEntry.snapshot;
  }
  const snapshot = createImmutableRouteDefinitions(routeDefinitions);
  ROUTE_DEFINITION_SNAPSHOT_CACHE.set(routeDefinitions, {
    signature: routeDefinitionsSignature,
    snapshot
  });
  return snapshot;
};
const parseRouteKey = (routeKey) => {
  const normalized = String(routeKey || '').trim();
  if (!normalized) {
    return null;
  }
  const firstSpace = normalized.indexOf(' ');
  if (firstSpace <= 0) {
    return null;
  }
  const method = normalized.slice(0, firstSpace);
  const path = normalized.slice(firstSpace + 1).trim();
  if (path.length === 0) {
    return null;
  }
  return {
    method: asMethod(method),
    path: normalizePathname(path)
  };
};
const normalizeRouteKey = (routeKey) => {
  const parsed = parseRouteKey(routeKey);
  if (!parsed) {
    return null;
  }
  return asRouteKey(parsed);
};

const VALID_ROUTE_ACCESS = new Set(['public', 'protected']);
const VALID_ROUTE_SCOPE = new Set(['public', 'session', 'tenant', 'platform']);
const VALID_HTTP_METHODS = new Set(['GET', 'POST', 'PUT', 'PATCH', 'DELETE']);

const ROUTE_DEFINITIONS = createImmutableRouteDefinitions([
  {
    method: 'GET',
    path: '/health',
    access: 'public',
    permission_code: '',
    scope: 'public'
  },
  {
    method: 'GET',
    path: '/openapi.json',
    access: 'public',
    permission_code: '',
    scope: 'public'
  },
  {
    method: 'GET',
    path: '/auth/ping',
    access: 'public',
    permission_code: '',
    scope: 'public'
  },
  {
    method: 'POST',
    path: '/auth/login',
    access: 'public',
    permission_code: '',
    scope: 'public'
  },
  {
    method: 'POST',
    path: '/auth/otp/send',
    access: 'public',
    permission_code: '',
    scope: 'public'
  },
  {
    method: 'POST',
    path: '/auth/otp/login',
    access: 'public',
    permission_code: '',
    scope: 'public'
  },
  {
    method: 'GET',
    path: '/auth/tenant/options',
    access: 'protected',
    permission_code: 'tenant.context.read',
    scope: 'tenant'
  },
  {
    method: 'POST',
    path: '/auth/tenant/select',
    access: 'protected',
    permission_code: 'tenant.context.switch',
    scope: 'tenant'
  },
  {
    method: 'POST',
    path: '/auth/tenant/switch',
    access: 'protected',
    permission_code: 'tenant.context.switch',
    scope: 'tenant'
  },
  {
    method: 'GET',
    path: '/auth/tenant/member-admin/probe',
    access: 'protected',
    permission_code: 'tenant.member_admin.operate',
    scope: 'tenant'
  },
  {
    method: 'POST',
    path: '/auth/tenant/member-admin/provision-user',
    access: 'protected',
    permission_code: 'tenant.member_admin.operate',
    scope: 'tenant'
  },
  {
    method: 'GET',
    path: TENANT_MEMBER_LIST_PATH,
    access: 'protected',
    permission_code: TENANT_MEMBER_VIEW_PERMISSION_CODE,
    scope: TENANT_MEMBER_SCOPE
  },
  {
    method: 'POST',
    path: TENANT_MEMBER_CREATE_PATH,
    access: 'protected',
    permission_code: TENANT_MEMBER_OPERATE_PERMISSION_CODE,
    scope: TENANT_MEMBER_SCOPE
  },
  {
    method: 'PATCH',
    path: TENANT_MEMBER_STATUS_PATH,
    access: 'protected',
    permission_code: TENANT_MEMBER_OPERATE_PERMISSION_CODE,
    scope: TENANT_MEMBER_SCOPE
  },
  {
    method: 'GET',
    path: TENANT_ROLE_BASE_PATH,
    access: 'protected',
    permission_code: TENANT_ROLE_VIEW_PERMISSION_CODE,
    scope: TENANT_ROLE_SCOPE
  },
  {
    method: 'POST',
    path: TENANT_ROLE_BASE_PATH,
    access: 'protected',
    permission_code: TENANT_ROLE_OPERATE_PERMISSION_CODE,
    scope: TENANT_ROLE_SCOPE
  },
  {
    method: 'PATCH',
    path: TENANT_ROLE_ITEM_PATH,
    access: 'protected',
    permission_code: TENANT_ROLE_OPERATE_PERMISSION_CODE,
    scope: TENANT_ROLE_SCOPE
  },
  {
    method: 'DELETE',
    path: TENANT_ROLE_ITEM_PATH,
    access: 'protected',
    permission_code: TENANT_ROLE_OPERATE_PERMISSION_CODE,
    scope: TENANT_ROLE_SCOPE
  },
  {
    method: 'GET',
    path: '/auth/platform/member-admin/probe',
    access: 'protected',
    permission_code: 'platform.member_admin.view',
    scope: 'platform'
  },
  {
    method: 'POST',
    path: '/auth/platform/member-admin/provision-user',
    access: 'protected',
    permission_code: 'platform.member_admin.operate',
    scope: 'platform'
  },
  {
    method: 'POST',
    path: PLATFORM_ORG_CREATE_PATH,
    access: 'protected',
    permission_code: PLATFORM_ORG_CREATE_PERMISSION_CODE,
    scope: PLATFORM_ORG_SCOPE
  },
  {
    method: 'POST',
    path: PLATFORM_ORG_STATUS_PATH,
    access: 'protected',
    permission_code: PLATFORM_ORG_CREATE_PERMISSION_CODE,
    scope: PLATFORM_ORG_SCOPE
  },
  {
    method: 'POST',
    path: PLATFORM_ORG_OWNER_TRANSFER_PATH,
    access: 'protected',
    permission_code: PLATFORM_ORG_CREATE_PERMISSION_CODE,
    scope: PLATFORM_ORG_SCOPE
  },
  {
    method: 'GET',
    path: PLATFORM_ROLE_BASE_PATH,
    access: 'protected',
    permission_code: PLATFORM_ROLE_VIEW_PERMISSION_CODE,
    scope: PLATFORM_ROLE_SCOPE
  },
  {
    method: 'POST',
    path: PLATFORM_ROLE_BASE_PATH,
    access: 'protected',
    permission_code: PLATFORM_ROLE_OPERATE_PERMISSION_CODE,
    scope: PLATFORM_ROLE_SCOPE
  },
  {
    method: 'PATCH',
    path: PLATFORM_ROLE_ITEM_PATH,
    access: 'protected',
    permission_code: PLATFORM_ROLE_OPERATE_PERMISSION_CODE,
    scope: PLATFORM_ROLE_SCOPE
  },
  {
    method: 'DELETE',
    path: PLATFORM_ROLE_ITEM_PATH,
    access: 'protected',
    permission_code: PLATFORM_ROLE_OPERATE_PERMISSION_CODE,
    scope: PLATFORM_ROLE_SCOPE
  },
  {
    method: 'GET',
    path: PLATFORM_ROLE_PERMISSION_PATH,
    access: 'protected',
    permission_code: PLATFORM_ROLE_VIEW_PERMISSION_CODE,
    scope: PLATFORM_ROLE_SCOPE
  },
  {
    method: 'PUT',
    path: PLATFORM_ROLE_PERMISSION_PATH,
    access: 'protected',
    permission_code: PLATFORM_ROLE_OPERATE_PERMISSION_CODE,
    scope: PLATFORM_ROLE_SCOPE
  },
  {
    method: 'POST',
    path: PLATFORM_USER_CREATE_PATH,
    access: 'protected',
    permission_code: PLATFORM_USER_PERMISSION_CODE,
    scope: PLATFORM_USER_SCOPE
  },
  {
    method: 'POST',
    path: PLATFORM_USER_STATUS_PATH,
    access: 'protected',
    permission_code: PLATFORM_USER_PERMISSION_CODE,
    scope: PLATFORM_USER_SCOPE
  },
  {
    method: 'POST',
    path: '/auth/refresh',
    access: 'public',
    permission_code: '',
    scope: 'public'
  },
  {
    method: 'POST',
    path: '/auth/logout',
    access: 'protected',
    permission_code: 'auth.session.logout',
    scope: 'session'
  },
  {
    method: 'POST',
    path: '/auth/change-password',
    access: 'protected',
    permission_code: 'auth.session.change_password',
    scope: 'session'
  },
  {
    method: 'POST',
    path: '/auth/platform/role-facts/replace',
    access: 'protected',
    permission_code: 'platform.member_admin.operate',
    scope: 'platform'
  },
  {
    method: 'GET',
    path: '/smoke',
    access: 'public',
    permission_code: '',
    scope: 'public'
  }
]);

const createRouteDefinitionMap = (routeDefinitions = ROUTE_DEFINITIONS) =>
  new Map(
    routeDefinitions.map((route) => {
      const immutableRoute = toImmutableRouteDefinition(route);
      return [asRouteKey(immutableRoute), immutableRoute];
    })
  );

const listDeclaredRoutePaths = (routeDefinitions = ROUTE_DEFINITIONS) =>
  new Set(routeDefinitions.map((route) => normalizePathname(route.path)));

const findRouteDefinitionInMap = (
  routeDefinitionMap,
  { method, path }
) => {
  if (hasNonCanonicalSlashes(path)) {
    return null;
  }
  const normalizedMethod = asMethod(method);
  const normalizedPath = normalizePathname(path);
  const directMatch = routeDefinitionMap.get(
    asRouteKey({ method: normalizedMethod, path: normalizedPath })
  );
  if (directMatch) {
    return directMatch;
  }
  for (const routeDefinition of routeDefinitionMap.values()) {
    if (routeDefinition.method !== normalizedMethod) {
      continue;
    }
    if (!String(routeDefinition.path || '').includes(':')) {
      continue;
    }
    if (isRoutePathMatch(routeDefinition.path, normalizedPath)) {
      return routeDefinition;
    }
  }
  return null;
};

const ROUTE_DEFINITION_MAP = createRouteDefinitionMap(ROUTE_DEFINITIONS);

const findRouteDefinition = ({ method, path }) =>
  findRouteDefinitionInMap(ROUTE_DEFINITION_MAP, { method, path });

const routeListToText = (routes) => routes.map((item) => `${item.method} ${item.path}`).join(', ');
const invalidDeclarationToText = (declarations) =>
  declarations
    .map(
      (item) =>
        `${item.method} ${item.path} (invalid ${item.field}: ${item.value || '(empty)'})`
    )
    .join(', ');
const unknownPermissionCodeToText = (declarations) =>
  declarations
    .map(
      (item) =>
        `${item.method} ${item.path} (unknown permission_code: ${item.permission_code})`
    )
    .join(', ');
const incompatiblePermissionScopeToText = (declarations) =>
  declarations
    .map(
      (item) =>
        `${item.method} ${item.path} (permission_code ${item.permission_code} incompatible with scope ${item.scope}; allowed scopes: ${item.allowed_scopes.join('|')})`
    )
    .join(', ');

const validateRoutePermissionDeclarations = (routeDefinitions = ROUTE_DEFINITIONS, options = {}) => {
  const missing = [];
  const invalid = [];
  const unknown = [];
  const incompatible = [];
  const duplicate = [];
  const undeclared = [];
  const unhandled = [];
  const declarationKeys = new Set();
  const declarationKeyCounts = new Map();
  const supportedPermissionCodes = (() => {
    if (options.supportedPermissionCodes instanceof Set) {
      return options.supportedPermissionCodes;
    }
    if (Array.isArray(options.supportedPermissionCodes)) {
      return new Set(
        options.supportedPermissionCodes
          .map((permissionCode) => normalizePermissionCode(permissionCode))
          .filter((permissionCode) => permissionCode.length > 0)
      );
    }
    return null;
  })();
  const supportedPermissionScopes = (() => {
    const normalizeAllowedScopes = (scopeValues) => {
      if (scopeValues instanceof Set) {
        return new Set(
          [...scopeValues]
            .map((scope) => normalizeScope(scope))
            .filter((scope) => VALID_ROUTE_SCOPE.has(scope))
        );
      }
      if (Array.isArray(scopeValues)) {
        return new Set(
          scopeValues
            .map((scope) => normalizeScope(scope))
            .filter((scope) => VALID_ROUTE_SCOPE.has(scope))
        );
      }
      if (typeof scopeValues === 'string') {
        const normalized = normalizeScope(scopeValues);
        return VALID_ROUTE_SCOPE.has(normalized) ? new Set([normalized]) : new Set();
      }
      return new Set();
    };

    if (options.supportedPermissionScopes instanceof Map) {
      const normalized = new Map();
      for (const [permissionCode, allowedScopes] of options.supportedPermissionScopes.entries()) {
        const normalizedPermissionCode = normalizePermissionCode(permissionCode);
        if (normalizedPermissionCode.length === 0) {
          continue;
        }
        const normalizedScopes = normalizeAllowedScopes(allowedScopes);
        if (normalizedScopes.size > 0) {
          normalized.set(normalizedPermissionCode, normalizedScopes);
        }
      }
      return normalized;
    }

    if (options.supportedPermissionScopes && typeof options.supportedPermissionScopes === 'object') {
      const normalized = new Map();
      for (const [permissionCode, allowedScopes] of Object.entries(options.supportedPermissionScopes)) {
        const normalizedPermissionCode = normalizePermissionCode(permissionCode);
        if (normalizedPermissionCode.length === 0) {
          continue;
        }
        const normalizedScopes = normalizeAllowedScopes(allowedScopes);
        if (normalizedScopes.size > 0) {
          normalized.set(normalizedPermissionCode, normalizedScopes);
        }
      }
      return normalized;
    }

    return null;
  })();

  for (const route of routeDefinitions) {
    const rawMethod = String(route?.method || '').trim();
    const rawPathInput = String(route?.path || '');
    const rawPath = rawPathInput.trim();
    const method = asMethod(route?.method);
    const path = normalizePathname(rawPath);
    const routeKey = asRouteKey({ method, path });
    const access = normalizeAccess(route?.access);
    const scope = normalizeScope(route?.scope);
    const permissionCode = normalizePermissionCode(route?.permission_code);
    if (rawMethod.length === 0) {
      invalid.push({ method, path, field: 'method', value: '(empty)' });
    } else if (!VALID_HTTP_METHODS.has(method)) {
      invalid.push({ method, path, field: 'method', value: rawMethod });
    }
    if (
      rawPath.length === 0
      || !rawPath.startsWith('/')
      || rawPathInput !== rawPath
      || /\s/.test(rawPath)
      || rawPath.includes('?')
      || rawPath.includes('#')
    ) {
      invalid.push({
        method,
        path,
        field: 'path',
        value: rawPath.length === 0 ? '(empty)' : rawPathInput
      });
    }
    declarationKeys.add(routeKey);
    const routeKeyCount = (declarationKeyCounts.get(routeKey) || 0) + 1;
    declarationKeyCounts.set(routeKey, routeKeyCount);
    if (routeKeyCount > 1) {
      duplicate.push({
        method,
        path
      });
    }

    if (!VALID_ROUTE_ACCESS.has(access)) {
      invalid.push({
        method,
        path,
        field: 'access',
        value: String(route?.access || '')
      });
    }
    if (!VALID_ROUTE_SCOPE.has(scope)) {
      invalid.push({
        method,
        path,
        field: 'scope',
        value: String(route?.scope || '')
      });
    }
    if (
      access === 'public'
      && VALID_ROUTE_SCOPE.has(scope)
      && scope !== 'public'
    ) {
      invalid.push({
        method,
        path,
        field: 'scope',
        value: String(route?.scope || '')
      });
    }
    if (access === 'public' && permissionCode.length > 0) {
      invalid.push({
        method,
        path,
        field: 'permission_code',
        value: permissionCode
      });
    }
    if (access !== 'protected') {
      continue;
    }
    if (scope === 'public') {
      invalid.push({
        method,
        path,
        field: 'scope',
        value: String(route?.scope || '')
      });
    }
    if (permissionCode.length === 0) {
      missing.push({
        method,
        path
      });
      continue;
    }
    if (supportedPermissionCodes && !supportedPermissionCodes.has(permissionCode)) {
      unknown.push({
        method,
        path,
        permission_code: permissionCode
      });
    }
    if (supportedPermissionScopes && supportedPermissionScopes.has(permissionCode)) {
      const allowedScopes = supportedPermissionScopes.get(permissionCode);
      if (!allowedScopes.has(scope)) {
        incompatible.push({
          method,
          path,
          permission_code: permissionCode,
          scope,
          allowed_scopes: [...allowedScopes]
        });
      }
    }
  }

  const executableRouteKeys = Array.isArray(options.executableRouteKeys)
    ? options.executableRouteKeys
        .map((routeKey) => normalizeRouteKey(routeKey))
        .filter((routeKey) => routeKey)
    : [];
  if (executableRouteKeys.length > 0) {
    const executableKeySet = new Set(executableRouteKeys);
    for (const routeKey of executableKeySet) {
      if (declarationKeys.has(routeKey)) {
        continue;
      }
      const parsed = parseRouteKey(routeKey);
      if (parsed) {
        undeclared.push(parsed);
      }
    }

    for (const routeKey of declarationKeys) {
      if (executableKeySet.has(routeKey)) {
        continue;
      }
      const parsed = parseRouteKey(routeKey);
      if (parsed) {
        unhandled.push(parsed);
      }
    }
  }

  return {
    ok:
      missing.length === 0
      && invalid.length === 0
      && unknown.length === 0
      && incompatible.length === 0
      && duplicate.length === 0
      && undeclared.length === 0
      && unhandled.length === 0,
    missing,
    invalid,
    unknown,
    incompatible,
    duplicate,
    undeclared,
    unhandled
  };
};

const ensureRoutePermissionDeclarationsOrThrow = (
  routeDefinitions = ROUTE_DEFINITIONS,
  options = {}
) => {
  const result = validateRoutePermissionDeclarations(routeDefinitions, options);
  if (result.ok) {
    return result;
  }

  const failures = [];
  if (result.missing.length > 0) {
    failures.push(
      `missing protected route declarations: ${routeListToText(result.missing)}`
    );
  }
  if (result.invalid.length > 0) {
    failures.push(
      `invalid route declaration fields: ${invalidDeclarationToText(result.invalid)}`
    );
  }
  if (result.unknown.length > 0) {
    failures.push(
      `unknown permission codes: ${unknownPermissionCodeToText(result.unknown)}`
    );
  }
  if (result.incompatible.length > 0) {
    failures.push(
      `incompatible permission scope declarations: ${incompatiblePermissionScopeToText(result.incompatible)}`
    );
  }
  if (result.duplicate.length > 0) {
    failures.push(
      `duplicate route declarations: ${routeListToText(result.duplicate)}`
    );
  }
  if (result.undeclared.length > 0) {
    failures.push(
      `executable routes missing declarations: ${routeListToText(result.undeclared)}`
    );
  }
  if (result.unhandled.length > 0) {
    failures.push(
      `declared routes missing executable handlers: ${routeListToText(result.unhandled)}`
    );
  }

  throw new Error(
    `Route permission preflight failed: ${failures.join('; ')}`
  );
};

module.exports = {
  ROUTE_DEFINITIONS,
  ROUTE_DEFINITION_MAP,
  createImmutableRouteDefinitions,
  toRouteDefinitionsSnapshot,
  createRouteDefinitionMap,
  listDeclaredRoutePaths,
  findRouteDefinitionInMap,
  asRouteKey,
  parseRouteKey,
  normalizeRouteKey,
  isRoutePathMatch,
  extractRoutePathParams,
  findRouteDefinition,
  validateRoutePermissionDeclarations,
  ensureRoutePermissionDeclarationsOrThrow
};
