const { AuthProblemError } = require('../../../../../shared-kernel/auth/auth-problem-error');
const {
  resolveRoutePreauthorizedContext
} = require('../../../../../shared-kernel/auth/route-authz');
const {
  TENANT_CUSTOMER_VIEW_PERMISSION_CODE,
  TENANT_CUSTOMER_OPERATE_PERMISSION_CODE,
  TENANT_CUSTOMER_SCOPE_MY_VIEW_PERMISSION_CODE,
  TENANT_CUSTOMER_SCOPE_MY_OPERATE_PERMISSION_CODE,
  TENANT_CUSTOMER_SCOPE_ASSIST_VIEW_PERMISSION_CODE,
  TENANT_CUSTOMER_SCOPE_ASSIST_OPERATE_PERMISSION_CODE,
  TENANT_CUSTOMER_SCOPE_ALL_VIEW_PERMISSION_CODE,
  TENANT_CUSTOMER_SCOPE_ALL_OPERATE_PERMISSION_CODE,
  TENANT_CUSTOMER_SCOPE
} = require('../constants');

const CONTROL_CHAR_PATTERN = /[\u0000-\u001F\u007F]/;
const CUSTOMER_ID_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/;
const ACCOUNT_ID_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/;
const MAX_CUSTOMER_ID_LENGTH = 64;
const MAX_ACCOUNT_ID_LENGTH = 64;
const MAX_WECHAT_ID_LENGTH = 128;
const MAX_NICKNAME_LENGTH = 128;
const MAX_SOURCE_LENGTH = 16;
const MAX_REAL_NAME_LENGTH = 64;
const MAX_SCHOOL_LENGTH = 128;
const MAX_CLASS_NAME_LENGTH = 128;
const MAX_RELATION_LENGTH = 128;
const MAX_PHONE_LENGTH = 32;
const MAX_ADDRESS_LENGTH = 255;
const MAX_OPERATION_LOGS_LIMIT = 200;
const DEFAULT_PAGE = 1;
const DEFAULT_PAGE_SIZE = 20;
const MAX_PAGE_SIZE = 200;

const CUSTOMER_STATUS_SET = new Set(['enabled', 'disabled']);
const SOURCE_VALUE_SET = new Set(['ground', 'fission', 'other']);
const CUSTOMER_SCOPE_SET = new Set(['my', 'assist', 'all']);

const SOURCE_ALIAS_MAPPING = Object.freeze({
  ground: 'ground',
  '地推': 'ground',
  '地堆': 'ground',
  fission: 'fission',
  '裂变': 'fission',
  other: 'other',
  '其它': 'other',
  '其他': 'other'
});

const LIST_CUSTOMER_ALLOWED_FIELDS = new Set([
  'scope',
  'wechat_id',
  'wechatId',
  'account_ids',
  'accountIds',
  'nickname',
  'source',
  'real_name',
  'realName',
  'phone',
  'status',
  'created_time_start',
  'createdTimeStart',
  'created_time_end',
  'createdTimeEnd',
  'created_at_start',
  'createdAtStart',
  'created_at_end',
  'createdAtEnd',
  'page',
  'page_size',
  'pageSize'
]);

const CREATE_CUSTOMER_ALLOWED_FIELDS = new Set([
  'account_id',
  'accountId',
  'wechat_id',
  'wechatId',
  'nickname',
  'source',
  'real_name',
  'realName',
  'school',
  'class_name',
  'className',
  'relation',
  'phone',
  'address'
]);

const UPDATE_CUSTOMER_BASIC_ALLOWED_FIELDS = new Set(['source']);

const UPDATE_CUSTOMER_REALNAME_ALLOWED_FIELDS = new Set([
  'real_name',
  'realName',
  'school',
  'class_name',
  'className',
  'relation',
  'phone',
  'address'
]);

const customerProblem = ({ status, title, detail, errorCode, extensions = {} }) =>
  new AuthProblemError({
    status,
    title,
    detail,
    errorCode,
    extensions
  });

const tenantCustomerErrors = {
  invalidPayload: (detail = '请求参数不完整或格式错误') =>
    customerProblem({
      status: 400,
      title: 'Bad Request',
      detail,
      errorCode: 'TCUSTOMER-400-INVALID-PAYLOAD'
    }),

  forbidden: () =>
    customerProblem({
      status: 403,
      title: 'Forbidden',
      detail: '当前操作无权限',
      errorCode: 'AUTH-403-FORBIDDEN'
    }),

  noDomainAccess: () =>
    customerProblem({
      status: 403,
      title: 'Forbidden',
      detail: '当前入口无可用访问域权限',
      errorCode: 'AUTH-403-NO-DOMAIN'
    }),

  customerNotFound: () =>
    customerProblem({
      status: 404,
      title: 'Not Found',
      detail: '目标客户不存在',
      errorCode: 'TCUSTOMER-404-NOT-FOUND',
      extensions: {
        retryable: false
      }
    }),

  wechatConflict: () =>
    customerProblem({
      status: 409,
      title: 'Conflict',
      detail: '微信号在当前组织内已存在',
      errorCode: 'TCUSTOMER-409-WECHAT-CONFLICT',
      extensions: {
        retryable: false
      }
    }),

  dependencyUnavailable: () =>
    customerProblem({
      status: 503,
      title: 'Service Unavailable',
      detail: '客户治理依赖暂不可用，请稍后重试',
      errorCode: 'TCUSTOMER-503-DEPENDENCY-UNAVAILABLE',
      extensions: {
        retryable: true
      }
    })
};

const isPlainObject = (candidate) =>
  candidate !== null
  && typeof candidate === 'object'
  && !Array.isArray(candidate);

const normalizeRequiredString = (candidate) => {
  if (typeof candidate !== 'string') {
    return '';
  }
  return candidate.trim();
};

const normalizeStrictRequiredString = (candidate) => {
  if (typeof candidate !== 'string') {
    return '';
  }
  const normalized = candidate.trim();
  if (!normalized || candidate !== normalized) {
    return '';
  }
  return normalized;
};

const resolveRawCamelSnakeField = (
  source = {},
  camelCaseKey = '',
  snakeCaseKey = ''
) => {
  if (!source || typeof source !== 'object') {
    return undefined;
  }
  const hasCamelCaseKey = Object.prototype.hasOwnProperty.call(
    source,
    camelCaseKey
  );
  const hasSnakeCaseKey = Object.prototype.hasOwnProperty.call(
    source,
    snakeCaseKey
  );
  if (hasCamelCaseKey) {
    const camelCaseValue = source[camelCaseKey];
    if (camelCaseValue !== undefined && camelCaseValue !== null) {
      return camelCaseValue;
    }
  }
  if (hasSnakeCaseKey) {
    const snakeCaseValue = source[snakeCaseKey];
    if (snakeCaseValue !== undefined && snakeCaseValue !== null) {
      return snakeCaseValue;
    }
  }
  if (hasCamelCaseKey) {
    return source[camelCaseKey];
  }
  if (hasSnakeCaseKey) {
    return source[snakeCaseKey];
  }
  return undefined;
};

const toIsoTimestamp = (value) => {
  if (value instanceof Date) {
    return value.toISOString();
  }
  if (value === null || value === undefined) {
    return '';
  }
  const asDate = new Date(value);
  if (Number.isNaN(asDate.getTime())) {
    return '';
  }
  return asDate.toISOString();
};

const toPositiveInteger = (value, fallback, { min = 1, max = Number.MAX_SAFE_INTEGER } = {}) => {
  const parsed = Number(value);
  if (!Number.isFinite(parsed)) {
    return fallback;
  }
  const rounded = Math.floor(parsed);
  if (rounded < min) {
    return min;
  }
  if (rounded > max) {
    return max;
  }
  return rounded;
};

const readPermissionCodeSet = (permissionContext) => {
  const permissionCodeSet = permissionContext?.permission_code_set
    ?? permissionContext?.permissionCodeSet;
  if (permissionCodeSet instanceof Set) {
    return permissionCodeSet;
  }
  if (Array.isArray(permissionCodeSet)) {
    return new Set(
      permissionCodeSet
        .map((permissionCode) => String(permissionCode || '').trim().toLowerCase())
        .filter((permissionCode) => permissionCode.length > 0)
    );
  }
  return null;
};

const normalizeTenantPermissionContext = (permissionContext = null) => {
  if (!permissionContext || typeof permissionContext !== 'object') {
    return null;
  }
  const normalized = {
    can_view_customer_management: Boolean(
      permissionContext.can_view_customer_management
      ?? permissionContext.canViewCustomerManagement
    ),
    can_operate_customer_management: Boolean(
      permissionContext.can_operate_customer_management
      ?? permissionContext.canOperateCustomerManagement
    ),
    can_view_customer_scope_my: Boolean(
      permissionContext.can_view_customer_scope_my
      ?? permissionContext.canViewCustomerScopeMy
    ),
    can_operate_customer_scope_my: Boolean(
      permissionContext.can_operate_customer_scope_my
      ?? permissionContext.canOperateCustomerScopeMy
    ),
    can_view_customer_scope_assist: Boolean(
      permissionContext.can_view_customer_scope_assist
      ?? permissionContext.canViewCustomerScopeAssist
    ),
    can_operate_customer_scope_assist: Boolean(
      permissionContext.can_operate_customer_scope_assist
      ?? permissionContext.canOperateCustomerScopeAssist
    ),
    can_view_customer_scope_all: Boolean(
      permissionContext.can_view_customer_scope_all
      ?? permissionContext.canViewCustomerScopeAll
    ),
    can_operate_customer_scope_all: Boolean(
      permissionContext.can_operate_customer_scope_all
      ?? permissionContext.canOperateCustomerScopeAll
    )
  };
  const permissionCodeSet = readPermissionCodeSet(permissionContext);
  if (permissionCodeSet instanceof Set) {
    Object.defineProperty(normalized, 'permission_code_set', {
      value: permissionCodeSet,
      enumerable: false,
      configurable: true
    });
    Object.defineProperty(normalized, 'permissionCodeSet', {
      value: permissionCodeSet,
      enumerable: false,
      configurable: true
    });
  }
  return normalized;
};

const resolveActiveTenantIdFromAuthorizationContext = (authorizationContext = null) =>
  normalizeRequiredString(
    authorizationContext?.active_tenant_id
      || authorizationContext?.activeTenantId
      || authorizationContext?.session_context?.active_tenant_id
      || authorizationContext?.session_context?.activeTenantId
      || authorizationContext?.session?.sessionContext?.active_tenant_id
      || authorizationContext?.session?.sessionContext?.activeTenantId
      || authorizationContext?.session?.session_context?.active_tenant_id
      || authorizationContext?.session?.session_context?.activeTenantId
  );

const resolveTenantPermissionContextFromAuthorizationContext = (
  authorizationContext = null
) =>
  normalizeTenantPermissionContext(
    authorizationContext?.tenant_permission_context
      || authorizationContext?.tenantPermissionContext
      || authorizationContext?.session_context?.tenant_permission_context
      || authorizationContext?.session_context?.tenantPermissionContext
      || authorizationContext?.session?.sessionContext?.tenant_permission_context
      || authorizationContext?.session?.sessionContext?.tenantPermissionContext
      || authorizationContext?.session?.session_context?.tenant_permission_context
      || authorizationContext?.session?.session_context?.tenantPermissionContext
  );

const isResolvedOperatorIdentifier = (value) => {
  const normalized = String(value || '').trim();
  return normalized.length > 0 && normalized.toLowerCase() !== 'unknown';
};

const resolveAuthorizedOperatorContext = ({
  authorizationContext = null,
  expectedPermissionCode = ''
}) => {
  const preauthorizedContext = resolveRoutePreauthorizedContext({
    authorizationContext,
    expectedPermissionCode,
    expectedScope: TENANT_CUSTOMER_SCOPE,
    expectedEntryDomain: TENANT_CUSTOMER_SCOPE
  });
  if (!preauthorizedContext) {
    return null;
  }

  const activeTenantId = resolveActiveTenantIdFromAuthorizationContext(
    authorizationContext
  );
  if (!activeTenantId) {
    throw tenantCustomerErrors.noDomainAccess();
  }
  if (
    !isResolvedOperatorIdentifier(preauthorizedContext.userId)
    || !isResolvedOperatorIdentifier(preauthorizedContext.sessionId)
  ) {
    throw tenantCustomerErrors.forbidden();
  }

  return {
    operatorUserId: preauthorizedContext.userId,
    operatorSessionId: preauthorizedContext.sessionId,
    activeTenantId,
    tenantPermissionContext: resolveTenantPermissionContextFromAuthorizationContext(
      authorizationContext
    )
  };
};

const resolveAuthorizedTenantRoute = async ({
  authService,
  requestId,
  accessToken,
  authorizationContext,
  permissionCode
}) => {
  const preAuthorizedOperatorContext = resolveAuthorizedOperatorContext({
    authorizationContext,
    expectedPermissionCode: permissionCode
  });
  if (preAuthorizedOperatorContext) {
    return preAuthorizedOperatorContext;
  }

  let authorizedRoute = null;
  try {
    authorizedRoute = await authService.authorizeRoute({
      requestId,
      accessToken,
      permissionCode,
      scope: 'tenant',
      authorizationContext
    });
  } catch (error) {
    if (error instanceof AuthProblemError) {
      throw error;
    }
    throw tenantCustomerErrors.dependencyUnavailable();
  }

  const operatorUserId = normalizeRequiredString(
    authorizedRoute?.user_id || authorizedRoute?.userId
  );
  const operatorSessionId = normalizeRequiredString(
    authorizedRoute?.session_id || authorizedRoute?.sessionId
  );
  const activeTenantId = normalizeStrictRequiredString(
    authorizedRoute?.active_tenant_id || authorizedRoute?.activeTenantId
  );

  if (
    !isResolvedOperatorIdentifier(operatorUserId)
    || !isResolvedOperatorIdentifier(operatorSessionId)
  ) {
    throw tenantCustomerErrors.forbidden();
  }
  if (!activeTenantId) {
    throw tenantCustomerErrors.noDomainAccess();
  }

  return {
    operatorUserId,
    operatorSessionId,
    activeTenantId,
    tenantPermissionContext: normalizeTenantPermissionContext(
      authorizedRoute?.tenant_permission_context
        || authorizedRoute?.tenantPermissionContext
    )
  };
};

const normalizeStrictCustomerId = (customerId) => {
  const normalizedCustomerId = normalizeStrictRequiredString(customerId).toLowerCase();
  if (
    !normalizedCustomerId
    || normalizedCustomerId.length > MAX_CUSTOMER_ID_LENGTH
    || !CUSTOMER_ID_PATTERN.test(normalizedCustomerId)
  ) {
    throw tenantCustomerErrors.invalidPayload('customer_id 格式错误');
  }
  return normalizedCustomerId;
};

const normalizeStrictAccountId = (accountId) => {
  const normalizedAccountId = normalizeStrictRequiredString(accountId).toLowerCase();
  if (
    !normalizedAccountId
    || normalizedAccountId.length > MAX_ACCOUNT_ID_LENGTH
    || !ACCOUNT_ID_PATTERN.test(normalizedAccountId)
  ) {
    throw tenantCustomerErrors.invalidPayload('account_id 格式错误');
  }
  return normalizedAccountId;
};

const normalizeStrictWechatId = (wechatId) => {
  const normalizedWechatId = normalizeStrictRequiredString(wechatId);
  if (
    !normalizedWechatId
    || normalizedWechatId.length > MAX_WECHAT_ID_LENGTH
    || CONTROL_CHAR_PATTERN.test(normalizedWechatId)
  ) {
    throw tenantCustomerErrors.invalidPayload('微信号格式错误');
  }
  return normalizedWechatId;
};

const normalizeStrictNickname = (nickname) => {
  const normalizedNickname = normalizeStrictRequiredString(nickname);
  if (
    !normalizedNickname
    || normalizedNickname.length > MAX_NICKNAME_LENGTH
    || CONTROL_CHAR_PATTERN.test(normalizedNickname)
  ) {
    throw tenantCustomerErrors.invalidPayload('昵称格式错误');
  }
  return normalizedNickname;
};

const normalizeStrictSource = (source) => {
  const normalizedSourceRaw = normalizeStrictRequiredString(source);
  if (!normalizedSourceRaw || normalizedSourceRaw.length > MAX_SOURCE_LENGTH) {
    throw tenantCustomerErrors.invalidPayload('来源格式错误');
  }
  const mappedSource = SOURCE_ALIAS_MAPPING[normalizedSourceRaw]
    || SOURCE_ALIAS_MAPPING[normalizedSourceRaw.toLowerCase()]
    || '';
  if (!SOURCE_VALUE_SET.has(mappedSource)) {
    throw tenantCustomerErrors.invalidPayload('来源格式错误');
  }
  return mappedSource;
};

const normalizeOptionalProfileField = ({
  value,
  maxLength,
  fieldLabel
}) => {
  if (value === undefined) {
    return undefined;
  }
  if (value === null) {
    return null;
  }
  if (typeof value !== 'string') {
    throw tenantCustomerErrors.invalidPayload(`${fieldLabel} 格式错误`);
  }
  const normalized = value.trim();
  if (!normalized) {
    return null;
  }
  if (normalized.length > maxLength || CONTROL_CHAR_PATTERN.test(normalized)) {
    throw tenantCustomerErrors.invalidPayload(`${fieldLabel} 格式错误`);
  }
  return normalized;
};

const normalizeStatus = (status) => {
  const normalized = normalizeRequiredString(status).toLowerCase();
  if (!normalized) {
    return '';
  }
  if (!CUSTOMER_STATUS_SET.has(normalized)) {
    return '';
  }
  return normalized;
};

const parseOptionalDateTime = ({
  value,
  errorDetail
}) => {
  if (value === undefined || value === null || value === '') {
    return null;
  }
  if (typeof value !== 'string') {
    throw tenantCustomerErrors.invalidPayload(errorDetail);
  }
  const normalized = value.trim();
  if (!normalized) {
    return null;
  }
  const asDate = new Date(normalized);
  if (Number.isNaN(asDate.getTime())) {
    throw tenantCustomerErrors.invalidPayload(errorDetail);
  }
  return asDate.toISOString();
};

const normalizeOptionalKeyword = ({ value, maxLength, fieldLabel }) => {
  if (value === undefined || value === null || value === '') {
    return '';
  }
  if (typeof value !== 'string') {
    throw tenantCustomerErrors.invalidPayload(`${fieldLabel} 格式错误`);
  }
  const normalized = value.trim();
  if (!normalized) {
    return '';
  }
  if (normalized.length > maxLength || CONTROL_CHAR_PATTERN.test(normalized)) {
    throw tenantCustomerErrors.invalidPayload(`${fieldLabel} 格式错误`);
  }
  return normalized;
};

const normalizeScope = (scope) => {
  const normalizedScope = normalizeRequiredString(scope).toLowerCase();
  if (!normalizedScope) {
    return 'my';
  }
  if (!CUSTOMER_SCOPE_SET.has(normalizedScope)) {
    throw tenantCustomerErrors.invalidPayload('scope 参数仅支持 my|assist|all');
  }
  return normalizedScope;
};

const toStringArray = (value) => {
  if (value === undefined || value === null || value === '') {
    return [];
  }
  if (Array.isArray(value)) {
    return value;
  }
  if (typeof value === 'string') {
    if (value.includes(',')) {
      return value.split(',');
    }
    return [value];
  }
  throw tenantCustomerErrors.invalidPayload('account_ids 格式错误');
};

const parseListFilters = (query = {}) => {
  if (!isPlainObject(query)) {
    throw tenantCustomerErrors.invalidPayload();
  }
  const entries = Object.entries(query || {});
  for (const [fieldKey] of entries) {
    if (!LIST_CUSTOMER_ALLOWED_FIELDS.has(fieldKey)) {
      throw tenantCustomerErrors.invalidPayload();
    }
  }

  const scope = normalizeScope(query.scope);
  const accountIds = [...new Set(
    toStringArray(resolveRawCamelSnakeField(query, 'accountIds', 'account_ids'))
      .map((item) => normalizeStrictRequiredString(item).toLowerCase())
      .filter((item) => item.length > 0)
      .map((item) => {
        if (item.length > MAX_ACCOUNT_ID_LENGTH || !ACCOUNT_ID_PATTERN.test(item)) {
          throw tenantCustomerErrors.invalidPayload('account_ids 格式错误');
        }
        return item;
      })
  )].sort((left, right) => left.localeCompare(right));

  const status = normalizeStatus(query.status || '');
  if ((query.status !== undefined && query.status !== null && query.status !== '') && !status) {
    throw tenantCustomerErrors.invalidPayload('status 参数格式错误');
  }

  const sourceRaw = resolveRawCamelSnakeField(query, 'source', 'source');
  const source = sourceRaw === undefined || sourceRaw === null || sourceRaw === ''
    ? ''
    : normalizeStrictSource(sourceRaw);

  const wechatIdRaw = resolveRawCamelSnakeField(query, 'wechatId', 'wechat_id');
  const wechatId = normalizeOptionalKeyword({
    value: wechatIdRaw,
    maxLength: MAX_WECHAT_ID_LENGTH,
    fieldLabel: 'wechat_id'
  });

  const realNameRaw = resolveRawCamelSnakeField(query, 'realName', 'real_name');
  const realName = normalizeOptionalKeyword({
    value: realNameRaw,
    maxLength: MAX_REAL_NAME_LENGTH,
    fieldLabel: 'real_name'
  });

  const nickname = normalizeOptionalKeyword({
    value: resolveRawCamelSnakeField(query, 'nickname', 'nickname'),
    maxLength: MAX_NICKNAME_LENGTH,
    fieldLabel: 'nickname'
  });

  const phone = normalizeOptionalKeyword({
    value: resolveRawCamelSnakeField(query, 'phone', 'phone'),
    maxLength: MAX_PHONE_LENGTH,
    fieldLabel: 'phone'
  });

  const createdAtStart = parseOptionalDateTime({
    value: resolveRawCamelSnakeField(query, 'createdTimeStart', 'created_time_start')
      ?? resolveRawCamelSnakeField(query, 'createdAtStart', 'created_at_start'),
    errorDetail: 'created_time_start 参数格式错误'
  });
  const createdAtEnd = parseOptionalDateTime({
    value: resolveRawCamelSnakeField(query, 'createdTimeEnd', 'created_time_end')
      ?? resolveRawCamelSnakeField(query, 'createdAtEnd', 'created_at_end'),
    errorDetail: 'created_time_end 参数格式错误'
  });

  const page = toPositiveInteger(
    resolveRawCamelSnakeField(query, 'page', 'page'),
    DEFAULT_PAGE,
    { min: 1, max: Number.MAX_SAFE_INTEGER }
  );
  const pageSize = toPositiveInteger(
    resolveRawCamelSnakeField(query, 'pageSize', 'page_size'),
    DEFAULT_PAGE_SIZE,
    { min: 1, max: MAX_PAGE_SIZE }
  );

  return {
    scope,
    wechatId,
    accountIds,
    nickname,
    source,
    realName,
    phone,
    status,
    createdAtStart,
    createdAtEnd,
    page,
    pageSize
  };
};

const parseCreatePayload = (payload = {}) => {
  if (!isPlainObject(payload)) {
    throw tenantCustomerErrors.invalidPayload();
  }

  for (const fieldKey of Object.keys(payload)) {
    if (fieldKey === 'status') {
      throw tenantCustomerErrors.invalidPayload('创建客户不支持传入 status');
    }
    if (!CREATE_CUSTOMER_ALLOWED_FIELDS.has(fieldKey)) {
      throw tenantCustomerErrors.invalidPayload();
    }
  }

  const accountId = normalizeStrictAccountId(
    resolveRawCamelSnakeField(payload, 'accountId', 'account_id')
  );
  const wechatId = normalizeStrictWechatId(
    resolveRawCamelSnakeField(payload, 'wechatId', 'wechat_id')
  );
  const nickname = normalizeStrictNickname(
    resolveRawCamelSnakeField(payload, 'nickname', 'nickname')
  );
  const source = normalizeStrictSource(
    resolveRawCamelSnakeField(payload, 'source', 'source')
  );

  return {
    accountId,
    wechatId,
    nickname,
    source,
    realName: normalizeOptionalProfileField({
      value: resolveRawCamelSnakeField(payload, 'realName', 'real_name'),
      maxLength: MAX_REAL_NAME_LENGTH,
      fieldLabel: 'real_name'
    }),
    school: normalizeOptionalProfileField({
      value: resolveRawCamelSnakeField(payload, 'school', 'school'),
      maxLength: MAX_SCHOOL_LENGTH,
      fieldLabel: 'school'
    }),
    className: normalizeOptionalProfileField({
      value: resolveRawCamelSnakeField(payload, 'className', 'class_name'),
      maxLength: MAX_CLASS_NAME_LENGTH,
      fieldLabel: 'class_name'
    }),
    relation: normalizeOptionalProfileField({
      value: resolveRawCamelSnakeField(payload, 'relation', 'relation'),
      maxLength: MAX_RELATION_LENGTH,
      fieldLabel: 'relation'
    }),
    phone: normalizeOptionalProfileField({
      value: resolveRawCamelSnakeField(payload, 'phone', 'phone'),
      maxLength: MAX_PHONE_LENGTH,
      fieldLabel: 'phone'
    }),
    address: normalizeOptionalProfileField({
      value: resolveRawCamelSnakeField(payload, 'address', 'address'),
      maxLength: MAX_ADDRESS_LENGTH,
      fieldLabel: 'address'
    })
  };
};

const parseUpdateBasicPayload = (payload = {}) => {
  if (!isPlainObject(payload)) {
    throw tenantCustomerErrors.invalidPayload();
  }
  for (const fieldKey of Object.keys(payload)) {
    if (!UPDATE_CUSTOMER_BASIC_ALLOWED_FIELDS.has(fieldKey)) {
      throw tenantCustomerErrors.invalidPayload();
    }
  }
  const source = normalizeStrictSource(
    resolveRawCamelSnakeField(payload, 'source', 'source')
  );
  return { source };
};

const parseUpdateRealnamePayload = (payload = {}) => {
  if (!isPlainObject(payload)) {
    throw tenantCustomerErrors.invalidPayload();
  }
  for (const fieldKey of Object.keys(payload)) {
    if (!UPDATE_CUSTOMER_REALNAME_ALLOWED_FIELDS.has(fieldKey)) {
      throw tenantCustomerErrors.invalidPayload();
    }
  }

  const parsed = {
    realName: normalizeOptionalProfileField({
      value: resolveRawCamelSnakeField(payload, 'realName', 'real_name'),
      maxLength: MAX_REAL_NAME_LENGTH,
      fieldLabel: 'real_name'
    }),
    school: normalizeOptionalProfileField({
      value: resolveRawCamelSnakeField(payload, 'school', 'school'),
      maxLength: MAX_SCHOOL_LENGTH,
      fieldLabel: 'school'
    }),
    className: normalizeOptionalProfileField({
      value: resolveRawCamelSnakeField(payload, 'className', 'class_name'),
      maxLength: MAX_CLASS_NAME_LENGTH,
      fieldLabel: 'class_name'
    }),
    relation: normalizeOptionalProfileField({
      value: resolveRawCamelSnakeField(payload, 'relation', 'relation'),
      maxLength: MAX_RELATION_LENGTH,
      fieldLabel: 'relation'
    }),
    phone: normalizeOptionalProfileField({
      value: resolveRawCamelSnakeField(payload, 'phone', 'phone'),
      maxLength: MAX_PHONE_LENGTH,
      fieldLabel: 'phone'
    }),
    address: normalizeOptionalProfileField({
      value: resolveRawCamelSnakeField(payload, 'address', 'address'),
      maxLength: MAX_ADDRESS_LENGTH,
      fieldLabel: 'address'
    })
  };

  const hasAnyField = Object.values(parsed).some((value) => value !== undefined);
  if (!hasAnyField) {
    throw tenantCustomerErrors.invalidPayload();
  }
  return parsed;
};

const toOperationLogsLimit = (value) => {
  if (value === undefined || value === null || value === '') {
    return MAX_OPERATION_LOGS_LIMIT;
  }
  const parsed = Number(value);
  if (!Number.isFinite(parsed) || parsed < 1) {
    throw tenantCustomerErrors.invalidPayload('limit 参数格式错误');
  }
  return Math.max(1, Math.min(MAX_OPERATION_LOGS_LIMIT, Math.floor(parsed)));
};

const hasScopePermission = ({
  permissionContext = null,
  scope = 'my',
  action = 'view'
}) => {
  const permissionCodeSet = readPermissionCodeSet(permissionContext);
  const hasPermissionCode = (permissionCode) =>
    permissionCodeSet instanceof Set
    && permissionCodeSet.has(String(permissionCode || '').trim().toLowerCase());

  const isOperateAction = String(action || '').trim().toLowerCase() === 'operate';

  if (scope === 'my') {
    if (isOperateAction) {
      return Boolean(
        permissionContext?.can_operate_customer_scope_my
        || permissionContext?.canOperateCustomerScopeMy
        || hasPermissionCode(TENANT_CUSTOMER_SCOPE_MY_OPERATE_PERMISSION_CODE)
      );
    }
    return Boolean(
      permissionContext?.can_view_customer_scope_my
      || permissionContext?.canViewCustomerScopeMy
      || hasPermissionCode(TENANT_CUSTOMER_SCOPE_MY_VIEW_PERMISSION_CODE)
    );
  }
  if (scope === 'assist') {
    if (isOperateAction) {
      return Boolean(
        permissionContext?.can_operate_customer_scope_assist
        || permissionContext?.canOperateCustomerScopeAssist
        || hasPermissionCode(TENANT_CUSTOMER_SCOPE_ASSIST_OPERATE_PERMISSION_CODE)
      );
    }
    return Boolean(
      permissionContext?.can_view_customer_scope_assist
      || permissionContext?.canViewCustomerScopeAssist
      || hasPermissionCode(TENANT_CUSTOMER_SCOPE_ASSIST_VIEW_PERMISSION_CODE)
    );
  }
  if (scope === 'all') {
    if (isOperateAction) {
      return Boolean(
        permissionContext?.can_operate_customer_scope_all
        || permissionContext?.canOperateCustomerScopeAll
        || hasPermissionCode(TENANT_CUSTOMER_SCOPE_ALL_OPERATE_PERMISSION_CODE)
      );
    }
    return Boolean(
      permissionContext?.can_view_customer_scope_all
      || permissionContext?.canViewCustomerScopeAll
      || hasPermissionCode(TENANT_CUSTOMER_SCOPE_ALL_VIEW_PERMISSION_CODE)
    );
  }
  return false;
};

const ensureScopePermission = ({
  permissionContext = null,
  scope = 'my',
  action = 'view'
}) => {
  if (!hasScopePermission({ permissionContext, scope, action })) {
    throw tenantCustomerErrors.forbidden();
  }
};

const resolvePermittedScopes = ({
  permissionContext = null,
  action = 'view'
} = {}) => {
  const scopes = [];
  for (const scope of ['my', 'assist', 'all']) {
    if (hasScopePermission({ permissionContext, scope, action })) {
      scopes.push(scope);
    }
  }
  return scopes;
};

const mapStoreErrorToDomainError = (error) => {
  if (error instanceof AuthProblemError) {
    return error;
  }
  const errorCode = String(error?.code || '').trim();
  if (errorCode === 'ERR_TENANT_CUSTOMER_WECHAT_CONFLICT') {
    return tenantCustomerErrors.wechatConflict();
  }
  if (errorCode === 'ERR_TENANT_CUSTOMER_NOT_FOUND') {
    return tenantCustomerErrors.customerNotFound();
  }
  if (errorCode === 'ERR_TENANT_CUSTOMER_ACCOUNT_NOT_FOUND') {
    return tenantCustomerErrors.invalidPayload('所属账号不存在或不可用');
  }
  if (errorCode === 'ERR_TENANT_CUSTOMER_SCOPE_FORBIDDEN') {
    return tenantCustomerErrors.forbidden();
  }
  return tenantCustomerErrors.dependencyUnavailable();
};

const normalizeCustomerRecordFromStore = ({
  customer,
  expectedTenantId,
  expectedCustomerId = ''
}) => {
  if (!customer || typeof customer !== 'object') {
    return null;
  }
  const tenantId = normalizeStrictRequiredString(
    customer.tenant_id || customer.tenantId
  );
  const customerId = normalizeStrictRequiredString(
    customer.customer_id || customer.customerId
  ).toLowerCase();
  const accountId = normalizeStrictRequiredString(
    customer.account_id || customer.accountId
  ).toLowerCase();
  const wechatId = normalizeStrictRequiredString(
    customer.wechat_id || customer.wechatId
  );
  const nickname = normalizeStrictRequiredString(customer.nickname);
  const source = normalizeRequiredString(customer.source).toLowerCase();
  const status = normalizeRequiredString(customer.status).toLowerCase();

  if (
    !tenantId
    || tenantId !== expectedTenantId
    || !customerId
    || (expectedCustomerId && customerId !== expectedCustomerId)
    || !accountId
    || !wechatId
    || !nickname
    || !SOURCE_VALUE_SET.has(source)
    || !CUSTOMER_STATUS_SET.has(status)
  ) {
    return null;
  }

  return {
    customer_id: customerId,
    tenant_id: tenantId,
    account_id: accountId,
    wechat_id: wechatId,
    nickname,
    source,
    status,
    real_name:
      customer.real_name === undefined
        ? null
        : normalizeRequiredString(customer.real_name) || null,
    school:
      customer.school === undefined
        ? null
        : normalizeRequiredString(customer.school) || null,
    class_name:
      (customer.class_name === undefined && customer.className === undefined)
        ? null
        : normalizeRequiredString(
          customer.class_name === undefined ? customer.className : customer.class_name
        ) || null,
    relation:
      customer.relation === undefined
        ? null
        : normalizeRequiredString(customer.relation) || null,
    phone:
      customer.phone === undefined
        ? null
        : normalizeRequiredString(customer.phone) || null,
    address:
      customer.address === undefined
        ? null
        : normalizeRequiredString(customer.address) || null,
    created_by_user_id: normalizeRequiredString(
      customer.created_by_user_id || customer.createdByUserId
    ) || null,
    updated_by_user_id: normalizeRequiredString(
      customer.updated_by_user_id || customer.updatedByUserId
    ) || null,
    created_at: toIsoTimestamp(customer.created_at || customer.createdAt),
    updated_at: toIsoTimestamp(customer.updated_at || customer.updatedAt)
  };
};

const normalizeOperationLogRecordFromStore = ({
  record,
  expectedTenantId,
  expectedCustomerId
}) => {
  if (!record || typeof record !== 'object') {
    return null;
  }
  const tenantId = normalizeStrictRequiredString(
    record.tenant_id || record.tenantId
  );
  const customerId = normalizeStrictRequiredString(
    record.customer_id || record.customerId
  ).toLowerCase();
  const operationId = normalizeStrictRequiredString(
    record.operation_id || record.operationId
  );
  const operationType = normalizeStrictRequiredString(
    record.operation_type || record.operationType
  );
  const operationTime = toIsoTimestamp(record.operation_time || record.operationTime);

  if (
    !tenantId
    || tenantId !== expectedTenantId
    || !customerId
    || customerId !== expectedCustomerId
    || !operationId
    || !operationType
    || !operationTime
  ) {
    return null;
  }

  return {
    operation_id: operationId,
    customer_id: customerId,
    tenant_id: tenantId,
    operation_type: operationType,
    operation_content:
      record.operation_content === undefined
        ? null
        : normalizeRequiredString(record.operation_content) || null,
    operator_user_id: normalizeRequiredString(
      record.operator_user_id || record.operatorUserId
    ) || null,
    operator_name: normalizeRequiredString(
      record.operator_name || record.operatorName
    ) || null,
    operation_time: operationTime,
    created_at: toIsoTimestamp(record.created_at || record.createdAt) || operationTime
  };
};

const mapCustomerForResponse = ({ normalizedCustomer }) => ({
  customer_id: normalizedCustomer.customer_id,
  tenant_id: normalizedCustomer.tenant_id,
  account_id: normalizedCustomer.account_id,
  wechat_id: normalizedCustomer.wechat_id,
  nickname: normalizedCustomer.nickname,
  source: normalizedCustomer.source,
  status: normalizedCustomer.status,
  real_name: normalizedCustomer.real_name,
  school: normalizedCustomer.school,
  class_name: normalizedCustomer.class_name,
  relation: normalizedCustomer.relation,
  phone: normalizedCustomer.phone,
  address: normalizedCustomer.address,
  created_by_user_id: normalizedCustomer.created_by_user_id,
  updated_by_user_id: normalizedCustomer.updated_by_user_id,
  created_at: normalizedCustomer.created_at,
  updated_at: normalizedCustomer.updated_at
});

const createTenantCustomerService = ({ authService } = {}) => {
  const authStore = authService?._internals?.authStore;
  if (
    !authService
    || typeof authService.authorizeRoute !== 'function'
    || !authStore
    || typeof authStore.listTenantCustomersByTenantId !== 'function'
    || typeof authStore.createTenantCustomer !== 'function'
    || typeof authStore.findTenantCustomerByCustomerId !== 'function'
    || typeof authStore.updateTenantCustomerBasic !== 'function'
    || typeof authStore.updateTenantCustomerRealname !== 'function'
    || typeof authStore.listTenantCustomerOperationLogs !== 'function'
  ) {
    throw new TypeError(
      'createTenantCustomerService requires authService.authorizeRoute and authService._internals.authStore customer capabilities'
    );
  }

  const listCustomers = async ({
    requestId,
    accessToken,
    query = {},
    authorizationContext = null
  }) => {
    const {
      operatorUserId,
      activeTenantId,
      tenantPermissionContext
    } = await resolveAuthorizedTenantRoute({
      authService,
      requestId,
      accessToken,
      authorizationContext,
      permissionCode: TENANT_CUSTOMER_VIEW_PERMISSION_CODE
    });

    const filters = parseListFilters(query || {});
    ensureScopePermission({
      permissionContext: tenantPermissionContext,
      scope: filters.scope
    });

    let customers = [];
    try {
      customers = await authStore.listTenantCustomersByTenantId({
        tenantId: activeTenantId,
        operatorUserId,
        scope: filters.scope,
        filters
      });
    } catch (error) {
      throw mapStoreErrorToDomainError(error);
    }

    if (!Array.isArray(customers)) {
      throw tenantCustomerErrors.dependencyUnavailable();
    }

    const normalizedCustomers = customers
      .map((customer) =>
        normalizeCustomerRecordFromStore({
          customer,
          expectedTenantId: activeTenantId
        })
      )
      .filter(Boolean)
      .sort((left, right) => {
        const leftCreatedAt = Date.parse(left.created_at || 0);
        const rightCreatedAt = Date.parse(right.created_at || 0);
        if (leftCreatedAt !== rightCreatedAt) {
          return rightCreatedAt - leftCreatedAt;
        }
        return String(right.customer_id).localeCompare(String(left.customer_id));
      });

    const offset = (filters.page - 1) * filters.pageSize;
    const pagedCustomers = normalizedCustomers
      .slice(offset, offset + filters.pageSize)
      .map((normalizedCustomer) =>
        mapCustomerForResponse({
          normalizedCustomer
        })
      );

    return {
      request_id: requestId || 'request_id_unset',
      tenant_id: activeTenantId,
      scope: filters.scope,
      page: filters.page,
      page_size: filters.pageSize,
      total: normalizedCustomers.length,
      filters: {
        scope: filters.scope,
        wechat_id: filters.wechatId,
        account_ids: filters.accountIds,
        nickname: filters.nickname,
        source: filters.source,
        real_name: filters.realName,
        phone: filters.phone,
        status: filters.status,
        created_time_start: filters.createdAtStart,
        created_time_end: filters.createdAtEnd
      },
      customers: pagedCustomers
    };
  };

  const createCustomer = async ({
    requestId,
    accessToken,
    payload,
    traceparent = null,
    authorizationContext = null
  }) => {
    const {
      operatorUserId,
      activeTenantId,
      tenantPermissionContext
    } = await resolveAuthorizedTenantRoute({
      authService,
      requestId,
      accessToken,
      authorizationContext,
      permissionCode: TENANT_CUSTOMER_OPERATE_PERMISSION_CODE
    });
    const permittedScopes = resolvePermittedScopes({
      permissionContext: tenantPermissionContext,
      action: 'operate'
    });
    if (permittedScopes.length < 1) {
      throw tenantCustomerErrors.forbidden();
    }

    const parsedPayload = parseCreatePayload(payload || {});

    let storeResult = null;
    try {
      storeResult = await authStore.createTenantCustomer({
        tenantId: activeTenantId,
        accountId: parsedPayload.accountId,
        wechatId: parsedPayload.wechatId,
        nickname: parsedPayload.nickname,
        source: parsedPayload.source,
        status: 'enabled',
        realName: parsedPayload.realName,
        school: parsedPayload.school,
        className: parsedPayload.className,
        relation: parsedPayload.relation,
        phone: parsedPayload.phone,
        address: parsedPayload.address,
        operatorUserId,
        operatorName: null,
        requestId,
        traceparent
      });
    } catch (error) {
      throw mapStoreErrorToDomainError(error);
    }

    if (!storeResult) {
      throw tenantCustomerErrors.dependencyUnavailable();
    }

    const normalizedCustomer = normalizeCustomerRecordFromStore({
      customer: storeResult,
      expectedTenantId: activeTenantId
    });
    if (!normalizedCustomer) {
      throw tenantCustomerErrors.dependencyUnavailable();
    }

    return {
      ...mapCustomerForResponse({ normalizedCustomer }),
      request_id: requestId || 'request_id_unset'
    };
  };

  const getCustomerDetail = async ({
    requestId,
    accessToken,
    params = {},
    authorizationContext = null
  }) => {
    const customerId = normalizeStrictCustomerId(
      resolveRawCamelSnakeField(params || {}, 'customerId', 'customer_id')
    );

    const {
      operatorUserId,
      activeTenantId,
      tenantPermissionContext
    } = await resolveAuthorizedTenantRoute({
      authService,
      requestId,
      accessToken,
      authorizationContext,
      permissionCode: TENANT_CUSTOMER_VIEW_PERMISSION_CODE
    });
    const permittedScopes = resolvePermittedScopes({
      permissionContext: tenantPermissionContext,
      action: 'view'
    });
    if (permittedScopes.length < 1) {
      throw tenantCustomerErrors.forbidden();
    }

    let customerRecord = null;
    let operationLogs = [];

    try {
      customerRecord = await authStore.findTenantCustomerByCustomerId({
        tenantId: activeTenantId,
        customerId,
        operatorUserId,
        scopes: permittedScopes
      });
      operationLogs = await authStore.listTenantCustomerOperationLogs({
        tenantId: activeTenantId,
        customerId,
        operatorUserId,
        scopes: permittedScopes,
        limit: MAX_OPERATION_LOGS_LIMIT
      });
    } catch (error) {
      throw mapStoreErrorToDomainError(error);
    }

    if (!customerRecord) {
      throw tenantCustomerErrors.customerNotFound();
    }

    const normalizedCustomer = normalizeCustomerRecordFromStore({
      customer: customerRecord,
      expectedTenantId: activeTenantId,
      expectedCustomerId: customerId
    });
    if (!normalizedCustomer) {
      throw tenantCustomerErrors.dependencyUnavailable();
    }

    const normalizedOperationLogs = (Array.isArray(operationLogs) ? operationLogs : [])
      .map((record) =>
        normalizeOperationLogRecordFromStore({
          record,
          expectedTenantId: activeTenantId,
          expectedCustomerId: customerId
        })
      )
      .filter(Boolean)
      .sort((left, right) => {
        const leftTime = Date.parse(left.operation_time || 0);
        const rightTime = Date.parse(right.operation_time || 0);
        if (leftTime !== rightTime) {
          return rightTime - leftTime;
        }
        return String(right.operation_id).localeCompare(String(left.operation_id));
      });

    return {
      ...mapCustomerForResponse({ normalizedCustomer }),
      operation_logs: normalizedOperationLogs,
      request_id: requestId || 'request_id_unset'
    };
  };

  const updateCustomerBasic = async ({
    requestId,
    accessToken,
    params = {},
    payload,
    traceparent = null,
    authorizationContext = null
  }) => {
    const customerId = normalizeStrictCustomerId(
      resolveRawCamelSnakeField(params || {}, 'customerId', 'customer_id')
    );
    const parsedPayload = parseUpdateBasicPayload(payload || {});

    const {
      operatorUserId,
      activeTenantId,
      tenantPermissionContext
    } = await resolveAuthorizedTenantRoute({
      authService,
      requestId,
      accessToken,
      authorizationContext,
      permissionCode: TENANT_CUSTOMER_OPERATE_PERMISSION_CODE
    });
    const permittedScopes = resolvePermittedScopes({
      permissionContext: tenantPermissionContext,
      action: 'operate'
    });
    if (permittedScopes.length < 1) {
      throw tenantCustomerErrors.forbidden();
    }

    let storeResult = null;
    try {
      storeResult = await authStore.updateTenantCustomerBasic({
        tenantId: activeTenantId,
        customerId,
        scopes: permittedScopes,
        source: parsedPayload.source,
        operatorUserId,
        operatorName: null,
        requestId,
        traceparent
      });
    } catch (error) {
      throw mapStoreErrorToDomainError(error);
    }

    if (!storeResult) {
      throw tenantCustomerErrors.customerNotFound();
    }

    const normalizedCustomer = normalizeCustomerRecordFromStore({
      customer: storeResult,
      expectedTenantId: activeTenantId,
      expectedCustomerId: customerId
    });
    if (!normalizedCustomer) {
      throw tenantCustomerErrors.dependencyUnavailable();
    }

    return {
      ...mapCustomerForResponse({ normalizedCustomer }),
      request_id: requestId || 'request_id_unset'
    };
  };

  const updateCustomerRealname = async ({
    requestId,
    accessToken,
    params = {},
    payload,
    traceparent = null,
    authorizationContext = null
  }) => {
    const customerId = normalizeStrictCustomerId(
      resolveRawCamelSnakeField(params || {}, 'customerId', 'customer_id')
    );
    const parsedPayload = parseUpdateRealnamePayload(payload || {});

    const {
      operatorUserId,
      activeTenantId,
      tenantPermissionContext
    } = await resolveAuthorizedTenantRoute({
      authService,
      requestId,
      accessToken,
      authorizationContext,
      permissionCode: TENANT_CUSTOMER_OPERATE_PERMISSION_CODE
    });
    const permittedScopes = resolvePermittedScopes({
      permissionContext: tenantPermissionContext,
      action: 'operate'
    });
    if (permittedScopes.length < 1) {
      throw tenantCustomerErrors.forbidden();
    }

    let storeResult = null;
    try {
      storeResult = await authStore.updateTenantCustomerRealname({
        tenantId: activeTenantId,
        customerId,
        scopes: permittedScopes,
        realName: parsedPayload.realName,
        school: parsedPayload.school,
        className: parsedPayload.className,
        relation: parsedPayload.relation,
        phone: parsedPayload.phone,
        address: parsedPayload.address,
        operatorUserId,
        operatorName: null,
        requestId,
        traceparent
      });
    } catch (error) {
      throw mapStoreErrorToDomainError(error);
    }

    if (!storeResult) {
      throw tenantCustomerErrors.customerNotFound();
    }

    const normalizedCustomer = normalizeCustomerRecordFromStore({
      customer: storeResult,
      expectedTenantId: activeTenantId,
      expectedCustomerId: customerId
    });
    if (!normalizedCustomer) {
      throw tenantCustomerErrors.dependencyUnavailable();
    }

    return {
      ...mapCustomerForResponse({ normalizedCustomer }),
      request_id: requestId || 'request_id_unset'
    };
  };

  const listCustomerOperationLogs = async ({
    requestId,
    accessToken,
    params = {},
    query = {},
    authorizationContext = null
  }) => {
    const customerId = normalizeStrictCustomerId(
      resolveRawCamelSnakeField(params || {}, 'customerId', 'customer_id')
    );
    const limit = toOperationLogsLimit(query?.limit);

    const {
      operatorUserId,
      activeTenantId,
      tenantPermissionContext
    } = await resolveAuthorizedTenantRoute({
      authService,
      requestId,
      accessToken,
      authorizationContext,
      permissionCode: TENANT_CUSTOMER_VIEW_PERMISSION_CODE
    });
    const permittedScopes = resolvePermittedScopes({
      permissionContext: tenantPermissionContext,
      action: 'view'
    });
    if (permittedScopes.length < 1) {
      throw tenantCustomerErrors.forbidden();
    }

    let customerRecord = null;
    let operationLogs = [];
    try {
      customerRecord = await authStore.findTenantCustomerByCustomerId({
        tenantId: activeTenantId,
        customerId,
        operatorUserId,
        scopes: permittedScopes
      });
      operationLogs = await authStore.listTenantCustomerOperationLogs({
        tenantId: activeTenantId,
        customerId,
        operatorUserId,
        scopes: permittedScopes,
        limit
      });
    } catch (error) {
      throw mapStoreErrorToDomainError(error);
    }

    if (!customerRecord) {
      throw tenantCustomerErrors.customerNotFound();
    }

    const normalizedCustomer = normalizeCustomerRecordFromStore({
      customer: customerRecord,
      expectedTenantId: activeTenantId,
      expectedCustomerId: customerId
    });
    if (!normalizedCustomer) {
      throw tenantCustomerErrors.dependencyUnavailable();
    }

    const normalizedOperationLogs = (Array.isArray(operationLogs) ? operationLogs : [])
      .map((record) =>
        normalizeOperationLogRecordFromStore({
          record,
          expectedTenantId: activeTenantId,
          expectedCustomerId: customerId
        })
      )
      .filter(Boolean)
      .sort((left, right) => {
        const leftTime = Date.parse(left.operation_time || 0);
        const rightTime = Date.parse(right.operation_time || 0);
        if (leftTime !== rightTime) {
          return rightTime - leftTime;
        }
        return String(right.operation_id).localeCompare(String(left.operation_id));
      });

    return {
      request_id: requestId || 'request_id_unset',
      tenant_id: activeTenantId,
      customer_id: customerId,
      operation_logs: normalizedOperationLogs
    };
  };

  return {
    listCustomers,
    createCustomer,
    getCustomerDetail,
    updateCustomerBasic,
    updateCustomerRealname,
    listCustomerOperationLogs,
    _internals: {
      tenantCustomerErrors,
      ensureScopePermission,
      hasScopePermission
    }
  };
};

module.exports = {
  createTenantCustomerService
};
