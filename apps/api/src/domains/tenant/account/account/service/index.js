const { AuthProblemError } = require('../../../../../shared-kernel/auth/auth-problem-error');
const {
  resolveRoutePreauthorizedContext
} = require('../../../../../shared-kernel/auth/route-authz');
const {
  TENANT_ACCOUNT_VIEW_PERMISSION_CODE,
  TENANT_ACCOUNT_OPERATE_PERMISSION_CODE,
  TENANT_ACCOUNT_SCOPE
} = require('../constants');

const CONTROL_CHAR_PATTERN = /[\u0000-\u001F\u007F]/;
const ACCOUNT_ID_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/;
const MEMBERSHIP_ID_PATTERN = /^[^\s\u0000-\u001F\u007F]{1,64}$/;
const MAX_WECHAT_ID_LENGTH = 128;
const MAX_NICKNAME_LENGTH = 128;
const MAX_ACCOUNT_ID_LENGTH = 64;
const MAX_OPERATOR_NAME_LENGTH = 128;
const MAX_ASSISTANT_COUNT = 20;
const MAX_OPERATION_LOGS_LIMIT = 200;
const MAX_MEMBER_LIST_PAGE = 200;
const MEMBER_LIST_PAGE_SIZE = 200;

const CREATE_ACCOUNT_ALLOWED_FIELDS = new Set([
  'wechat_id',
  'wechatId',
  'nickname',
  'owner_membership_id',
  'ownerMembershipId',
  'assistant_membership_ids',
  'assistantMembershipIds'
]);

const UPDATE_ACCOUNT_ALLOWED_FIELDS = new Set([
  ...CREATE_ACCOUNT_ALLOWED_FIELDS
]);

const UPDATE_ACCOUNT_STATUS_ALLOWED_FIELDS = new Set(['status']);

const LIST_ACCOUNT_ALLOWED_FIELDS = new Set([
  'page',
  'page_size',
  'pageSize',
  'wechat_id',
  'wechatId',
  'nickname',
  'owner_keyword',
  'ownerKeyword',
  'assistant_keyword',
  'assistantKeyword',
  'status',
  'created_time_start',
  'createdTimeStart',
  'created_time_end',
  'createdTimeEnd',
  'created_at_start',
  'createdAtStart',
  'created_at_end',
  'createdAtEnd'
]);

const ACCOUNT_STATUS_SET = new Set(['enabled', 'disabled']);
const ACCOUNT_STATUS_MAPPING = Object.freeze({
  active: 'enabled',
  inactive: 'disabled'
});

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

const normalizeTenantId = (tenantId) => normalizeStrictRequiredString(tenantId);

const normalizeAccountStatus = (status) => {
  const normalized = normalizeRequiredString(status).toLowerCase();
  if (!normalized) {
    return '';
  }
  const mapped = ACCOUNT_STATUS_MAPPING[normalized] || normalized;
  if (!ACCOUNT_STATUS_SET.has(mapped)) {
    return '';
  }
  return mapped;
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

const toNonNegativeInteger = (value) => {
  const parsed = Number(value);
  if (!Number.isFinite(parsed) || parsed < 0) {
    return 0;
  }
  return Math.floor(parsed);
};

const accountProblem = ({ status, title, detail, errorCode, extensions = {} }) =>
  new AuthProblemError({
    status,
    title,
    detail,
    errorCode,
    extensions
  });

const tenantAccountErrors = {
  invalidPayload: (detail = '请求参数不完整或格式错误') =>
    accountProblem({
      status: 400,
      title: 'Bad Request',
      detail,
      errorCode: 'TACCOUNT-400-INVALID-PAYLOAD'
    }),

  forbidden: () =>
    accountProblem({
      status: 403,
      title: 'Forbidden',
      detail: '当前操作无权限',
      errorCode: 'AUTH-403-FORBIDDEN'
    }),

  noDomainAccess: () =>
    accountProblem({
      status: 403,
      title: 'Forbidden',
      detail: '当前入口无可用访问域权限',
      errorCode: 'AUTH-403-NO-DOMAIN'
    }),

  accountNotFound: () =>
    accountProblem({
      status: 404,
      title: 'Not Found',
      detail: '目标账号不存在',
      errorCode: 'TACCOUNT-404-NOT-FOUND',
      extensions: {
        retryable: false
      }
    }),

  wechatConflict: () =>
    accountProblem({
      status: 409,
      title: 'Conflict',
      detail: '微信号在当前组织内已存在',
      errorCode: 'TACCOUNT-409-WECHAT-CONFLICT',
      extensions: {
        retryable: false
      }
    }),

  dependencyUnavailable: () =>
    accountProblem({
      status: 503,
      title: 'Service Unavailable',
      detail: '账号治理依赖暂不可用，请稍后重试',
      errorCode: 'TACCOUNT-503-DEPENDENCY-UNAVAILABLE',
      extensions: {
        retryable: true
      }
    })
};

const isResolvedOperatorIdentifier = (value) => {
  const normalized = String(value || '').trim();
  return normalized.length > 0 && normalized.toLowerCase() !== 'unknown';
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

const resolveAuthorizedOperatorContext = ({
  authorizationContext = null,
  expectedPermissionCode = ''
}) => {
  const preauthorizedContext = resolveRoutePreauthorizedContext({
    authorizationContext,
    expectedPermissionCode,
    expectedScope: TENANT_ACCOUNT_SCOPE,
    expectedEntryDomain: TENANT_ACCOUNT_SCOPE
  });
  if (!preauthorizedContext) {
    return null;
  }

  const activeTenantId = resolveActiveTenantIdFromAuthorizationContext(
    authorizationContext
  );
  if (!activeTenantId) {
    throw tenantAccountErrors.noDomainAccess();
  }
  if (
    !isResolvedOperatorIdentifier(preauthorizedContext.userId)
    || !isResolvedOperatorIdentifier(preauthorizedContext.sessionId)
  ) {
    throw tenantAccountErrors.forbidden();
  }
  return {
    operatorUserId: preauthorizedContext.userId,
    operatorSessionId: preauthorizedContext.sessionId,
    activeTenantId
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
    throw tenantAccountErrors.dependencyUnavailable();
  }

  const operatorUserId = normalizeRequiredString(
    authorizedRoute?.user_id || authorizedRoute?.userId
  );
  const operatorSessionId = normalizeRequiredString(
    authorizedRoute?.session_id || authorizedRoute?.sessionId
  );
  const activeTenantId = normalizeTenantId(
    authorizedRoute?.active_tenant_id || authorizedRoute?.activeTenantId
  );

  if (
    !isResolvedOperatorIdentifier(operatorUserId)
    || !isResolvedOperatorIdentifier(operatorSessionId)
  ) {
    throw tenantAccountErrors.forbidden();
  }
  if (!activeTenantId) {
    throw tenantAccountErrors.noDomainAccess();
  }

  return {
    operatorUserId,
    operatorSessionId,
    activeTenantId
  };
};

const normalizeStrictMembershipId = (membershipId, fieldLabel) => {
  const normalizedMembershipId = normalizeStrictRequiredString(membershipId);
  if (
    !normalizedMembershipId
    || normalizedMembershipId.length > MAX_ACCOUNT_ID_LENGTH
    || !MEMBERSHIP_ID_PATTERN.test(normalizedMembershipId)
  ) {
    throw tenantAccountErrors.invalidPayload(`${fieldLabel} 格式错误`);
  }
  return normalizedMembershipId;
};

const normalizeStrictAccountId = (accountId) => {
  const normalizedAccountId = normalizeStrictRequiredString(accountId).toLowerCase();
  if (
    !normalizedAccountId
    || normalizedAccountId.length > MAX_ACCOUNT_ID_LENGTH
    || !ACCOUNT_ID_PATTERN.test(normalizedAccountId)
  ) {
    throw tenantAccountErrors.invalidPayload('account_id 格式错误');
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
    throw tenantAccountErrors.invalidPayload('微信号格式错误');
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
    throw tenantAccountErrors.invalidPayload('昵称格式错误');
  }
  return normalizedNickname;
};

const normalizeOptionalKeyword = (value) => {
  if (value === null || value === undefined) {
    return '';
  }
  if (typeof value !== 'string') {
    throw tenantAccountErrors.invalidPayload();
  }
  const normalized = value.trim();
  if (!normalized) {
    return '';
  }
  if (
    normalized.length > MAX_NICKNAME_LENGTH
    || CONTROL_CHAR_PATTERN.test(normalized)
  ) {
    throw tenantAccountErrors.invalidPayload();
  }
  return normalized;
};

const parseOptionalDateTime = (value) => {
  if (value === null || value === undefined || value === '') {
    return null;
  }
  if (typeof value !== 'string') {
    throw tenantAccountErrors.invalidPayload();
  }
  const normalized = value.trim();
  if (!normalized) {
    return null;
  }
  const asDate = new Date(normalized);
  if (Number.isNaN(asDate.getTime())) {
    throw tenantAccountErrors.invalidPayload('创建时间筛选格式错误');
  }
  return asDate.toISOString();
};

const parseAssistantMembershipIds = (value) => {
  if (value === undefined || value === null) {
    return [];
  }
  if (!Array.isArray(value)) {
    throw tenantAccountErrors.invalidPayload('协助人格式错误');
  }
  const deduped = [];
  const seenMembershipIds = new Set();
  for (const item of value) {
    const normalizedMembershipId = normalizeStrictMembershipId(item, '协助人');
    if (seenMembershipIds.has(normalizedMembershipId)) {
      continue;
    }
    seenMembershipIds.add(normalizedMembershipId);
    deduped.push(normalizedMembershipId);
  }
  if (deduped.length > MAX_ASSISTANT_COUNT) {
    throw tenantAccountErrors.invalidPayload(`协助人数不能超过 ${MAX_ASSISTANT_COUNT}`);
  }
  return deduped;
};

const readAllowedPayload = ({ payload, allowedFields }) => {
  if (!isPlainObject(payload)) {
    throw tenantAccountErrors.invalidPayload();
  }
  const unknownPayloadKeys = Object.keys(payload).filter(
    (key) => !allowedFields.has(key)
  );
  if (unknownPayloadKeys.length > 0) {
    throw tenantAccountErrors.invalidPayload();
  }
  return payload;
};

const parseListFilters = (query = {}) => {
  if (!isPlainObject(query)) {
    throw tenantAccountErrors.invalidPayload();
  }
  for (const key of Object.keys(query)) {
    if (!LIST_ACCOUNT_ALLOWED_FIELDS.has(key)) {
      throw tenantAccountErrors.invalidPayload();
    }
  }
  const status = normalizeAccountStatus(query.status);
  if (String(query.status || '').trim() && !status) {
    throw tenantAccountErrors.invalidPayload('状态格式错误');
  }
  return {
    wechatId: normalizeOptionalKeyword(
      resolveRawCamelSnakeField(query, 'wechatId', 'wechat_id')
    ),
    nickname: normalizeOptionalKeyword(query.nickname),
    ownerKeyword: normalizeOptionalKeyword(
      resolveRawCamelSnakeField(query, 'ownerKeyword', 'owner_keyword')
    ),
    assistantKeyword: normalizeOptionalKeyword(
      resolveRawCamelSnakeField(query, 'assistantKeyword', 'assistant_keyword')
    ),
    status,
    createdAtStart: parseOptionalDateTime(
      resolveRawCamelSnakeField(
        query,
        'createdTimeStart',
        'created_time_start'
      ) || resolveRawCamelSnakeField(query, 'createdAtStart', 'created_at_start')
    ),
    createdAtEnd: parseOptionalDateTime(
      resolveRawCamelSnakeField(
        query,
        'createdTimeEnd',
        'created_time_end'
      ) || resolveRawCamelSnakeField(query, 'createdAtEnd', 'created_at_end')
    )
  };
};

const parseAccountUpsertPayload = ({ payload, allowedFields }) => {
  const rawPayload = readAllowedPayload({ payload, allowedFields });
  const rawWechatId = resolveRawCamelSnakeField(rawPayload, 'wechatId', 'wechat_id');
  const rawOwnerMembershipId = resolveRawCamelSnakeField(
    rawPayload,
    'ownerMembershipId',
    'owner_membership_id'
  );
  const rawAssistantMembershipIds = resolveRawCamelSnakeField(
    rawPayload,
    'assistantMembershipIds',
    'assistant_membership_ids'
  );

  if (rawWechatId === undefined || rawOwnerMembershipId === undefined) {
    throw tenantAccountErrors.invalidPayload();
  }

  const ownerMembershipId = normalizeStrictMembershipId(rawOwnerMembershipId, '负责人');
  const assistantMembershipIds = parseAssistantMembershipIds(rawAssistantMembershipIds);
  if (assistantMembershipIds.includes(ownerMembershipId)) {
    throw tenantAccountErrors.invalidPayload('协助人不能包含负责人');
  }

  return {
    wechatId: normalizeStrictWechatId(rawWechatId),
    nickname: normalizeStrictNickname(rawPayload.nickname),
    ownerMembershipId,
    assistantMembershipIds
  };
};

const parseStatusPayload = (payload = {}) => {
  const rawPayload = readAllowedPayload({
    payload,
    allowedFields: UPDATE_ACCOUNT_STATUS_ALLOWED_FIELDS
  });
  if (!Object.prototype.hasOwnProperty.call(rawPayload, 'status')) {
    throw tenantAccountErrors.invalidPayload();
  }
  const status = normalizeAccountStatus(rawPayload.status);
  if (!status) {
    throw tenantAccountErrors.invalidPayload('状态格式错误');
  }
  return status;
};

const normalizeAccountRecordFromStore = ({
  account = null,
  expectedTenantId = '',
  expectedAccountId = ''
} = {}) => {
  if (!account || typeof account !== 'object' || Array.isArray(account)) {
    return null;
  }
  const accountId = normalizeStrictRequiredString(
    resolveRawCamelSnakeField(account, 'accountId', 'account_id')
  ).toLowerCase();
  const tenantId = normalizeTenantId(
    resolveRawCamelSnakeField(account, 'tenantId', 'tenant_id')
  );
  const wechatId = normalizeStrictRequiredString(
    resolveRawCamelSnakeField(account, 'wechatId', 'wechat_id')
  );
  const nickname = normalizeStrictRequiredString(account.nickname);
  const ownerMembershipId = normalizeStrictRequiredString(
    resolveRawCamelSnakeField(account, 'ownerMembershipId', 'owner_membership_id')
  );
  const status = normalizeAccountStatus(account.status);
  const createdAt = toIsoTimestamp(
    resolveRawCamelSnakeField(account, 'createdAt', 'created_at')
  );
  const updatedAt = toIsoTimestamp(
    resolveRawCamelSnakeField(account, 'updatedAt', 'updated_at')
  );

  if (
    !accountId
    || !tenantId
    || !wechatId
    || !nickname
    || !ownerMembershipId
    || !status
    || !createdAt
    || !updatedAt
  ) {
    return null;
  }

  if (expectedTenantId && tenantId !== expectedTenantId) {
    return null;
  }
  if (expectedAccountId && accountId !== expectedAccountId) {
    return null;
  }

  const assistantMembershipIds = [];
  const seenAssistantMembershipIds = new Set();
  for (const assistantMembershipId of (
    resolveRawCamelSnakeField(account, 'assistantMembershipIds', 'assistant_membership_ids')
    || []
  )) {
    const normalizedAssistantMembershipId = normalizeStrictRequiredString(
      assistantMembershipId
    );
    if (
      !normalizedAssistantMembershipId
      || seenAssistantMembershipIds.has(normalizedAssistantMembershipId)
    ) {
      continue;
    }
    seenAssistantMembershipIds.add(normalizedAssistantMembershipId);
    assistantMembershipIds.push(normalizedAssistantMembershipId);
  }

  return {
    account_id: accountId,
    tenant_id: tenantId,
    wechat_id: wechatId,
    nickname,
    owner_membership_id: ownerMembershipId,
    assistant_membership_ids: assistantMembershipIds,
    customer_count: toNonNegativeInteger(
      resolveRawCamelSnakeField(account, 'customerCount', 'customer_count')
    ),
    group_chat_count: toNonNegativeInteger(
      resolveRawCamelSnakeField(account, 'groupChatCount', 'group_chat_count')
    ),
    status,
    avatar_url: (() => {
      const avatarUrl = resolveRawCamelSnakeField(account, 'avatarUrl', 'avatar_url');
      if (avatarUrl === null || avatarUrl === undefined) {
        return null;
      }
      const normalizedAvatarUrl = String(avatarUrl).trim();
      return normalizedAvatarUrl || null;
    })(),
    created_by_user_id: normalizeRequiredString(
      resolveRawCamelSnakeField(account, 'createdByUserId', 'created_by_user_id')
    ) || null,
    updated_by_user_id: normalizeRequiredString(
      resolveRawCamelSnakeField(account, 'updatedByUserId', 'updated_by_user_id')
    ) || null,
    created_at: createdAt,
    updated_at: updatedAt
  };
};

const normalizeOperationLogRecordFromStore = ({
  record = null,
  expectedTenantId = '',
  expectedAccountId = ''
} = {}) => {
  if (!record || typeof record !== 'object' || Array.isArray(record)) {
    return null;
  }
  const operationId = normalizeStrictRequiredString(
    resolveRawCamelSnakeField(record, 'operationId', 'operation_id')
  );
  const accountId = normalizeStrictRequiredString(
    resolveRawCamelSnakeField(record, 'accountId', 'account_id')
  ).toLowerCase();
  const tenantId = normalizeTenantId(
    resolveRawCamelSnakeField(record, 'tenantId', 'tenant_id')
  );
  const operationType = normalizeStrictRequiredString(
    resolveRawCamelSnakeField(record, 'operationType', 'operation_type')
  );
  const operationTime = toIsoTimestamp(
    resolveRawCamelSnakeField(record, 'operationTime', 'operation_time')
    || resolveRawCamelSnakeField(record, 'createdAt', 'created_at')
  );
  const operatorUserId = normalizeRequiredString(
    resolveRawCamelSnakeField(record, 'operatorUserId', 'operator_user_id')
  ) || null;
  const operatorName = normalizeRequiredString(
    resolveRawCamelSnakeField(record, 'operatorName', 'operator_name')
  ) || null;
  const content = normalizeRequiredString(
    resolveRawCamelSnakeField(record, 'content', 'operation_content')
  );

  if (
    !operationId
    || !accountId
    || !tenantId
    || !operationType
    || !operationTime
  ) {
    return null;
  }
  if (expectedTenantId && tenantId !== expectedTenantId) {
    return null;
  }
  if (expectedAccountId && accountId !== expectedAccountId) {
    return null;
  }

  return {
    operation_id: operationId,
    account_id: accountId,
    tenant_id: tenantId,
    operation_type: operationType,
    operation_time: operationTime,
    operator_user_id: operatorUserId,
    operator_name: operatorName,
    content: content || null
  };
};

const toOperationLogsLimit = (value) => {
  if (value === null || value === undefined || value === '') {
    return MAX_OPERATION_LOGS_LIMIT;
  }
  if (
    typeof value === 'string'
    && value.trim() === ''
  ) {
    return MAX_OPERATION_LOGS_LIMIT;
  }
  const parsed = Number(value);
  if (!Number.isFinite(parsed) || parsed < 1) {
    throw tenantAccountErrors.invalidPayload('limit 参数格式错误');
  }
  return Math.min(MAX_OPERATION_LOGS_LIMIT, Math.floor(parsed));
};

const loadTenantMemberDirectory = async ({ authStore, tenantId }) => {
  const byMembershipId = new Map();
  const byUserId = new Map();

  for (let page = 1; page <= MAX_MEMBER_LIST_PAGE; page += 1) {
    let members = [];
    try {
      members = await authStore.listTenantUsersByTenantId({
        tenantId,
        page,
        pageSize: MEMBER_LIST_PAGE_SIZE
      });
    } catch (_error) {
      throw tenantAccountErrors.dependencyUnavailable();
    }

    if (!Array.isArray(members) || members.length < 1) {
      break;
    }

    for (const member of members) {
      const membershipId = normalizeRequiredString(
        resolveRawCamelSnakeField(member, 'membershipId', 'membership_id')
      );
      const userId = normalizeRequiredString(
        resolveRawCamelSnakeField(member, 'userId', 'user_id')
      );
      const displayName = normalizeRequiredString(
        resolveRawCamelSnakeField(member, 'displayName', 'display_name')
      ) || userId || membershipId;
      if (membershipId) {
        byMembershipId.set(membershipId, {
          membership_id: membershipId,
          user_id: userId || null,
          display_name: displayName || null
        });
      }
      if (userId && displayName) {
        if (!byUserId.has(userId)) {
          byUserId.set(userId, displayName);
        }
      }
    }

    if (members.length < MEMBER_LIST_PAGE_SIZE) {
      break;
    }
  }

  return {
    byMembershipId,
    byUserId
  };
};

const resolveOperatorDisplayName = async ({
  authStore,
  tenantId,
  operatorUserId,
  defaultName = null
}) => {
  if (!operatorUserId) {
    return defaultName;
  }
  if (typeof authStore.findTenantUsershipByUserAndTenantId !== 'function') {
    return defaultName;
  }
  try {
    const membership = await authStore.findTenantUsershipByUserAndTenantId({
      userId: operatorUserId,
      tenantId
    });
    const displayName = normalizeRequiredString(
      resolveRawCamelSnakeField(membership || {}, 'displayName', 'display_name')
    );
    if (displayName) {
      return displayName;
    }
  } catch (_error) {
    return defaultName;
  }
  return defaultName;
};

const mapStoreErrorToDomainError = (error) => {
  const code = String(error?.code || '').trim();
  if (code === 'ERR_TENANT_ACCOUNT_WECHAT_CONFLICT') {
    return tenantAccountErrors.wechatConflict();
  }
  if (code === 'ERR_TENANT_ACCOUNT_NOT_FOUND') {
    return tenantAccountErrors.accountNotFound();
  }
  if (error instanceof AuthProblemError) {
    return error;
  }
  return tenantAccountErrors.dependencyUnavailable();
};

const ensureMembershipIdsInTenant = ({
  ownerMembershipId,
  assistantMembershipIds = [],
  memberDirectory
}) => {
  if (!memberDirectory.byMembershipId.has(ownerMembershipId)) {
    throw tenantAccountErrors.invalidPayload('负责人必须是当前组织成员');
  }
  for (const assistantMembershipId of assistantMembershipIds) {
    if (!memberDirectory.byMembershipId.has(assistantMembershipId)) {
      throw tenantAccountErrors.invalidPayload('协助人必须是当前组织成员');
    }
  }
};

const mapAccountForResponse = ({
  normalizedAccount,
  memberDirectory
}) => {
  const ownerMembership = memberDirectory.byMembershipId.get(
    normalizedAccount.owner_membership_id
  ) || null;
  const ownerName = normalizeRequiredString(ownerMembership?.display_name)
    || ownerMembership?.user_id
    || normalizedAccount.owner_membership_id;
  const assistantNames = normalizedAccount.assistant_membership_ids
    .map((assistantMembershipId) => {
      const assistant = memberDirectory.byMembershipId.get(assistantMembershipId);
      return normalizeRequiredString(assistant?.display_name)
        || assistant?.user_id
        || assistantMembershipId;
    });
  const createdByName = memberDirectory.byUserId.get(
    normalizedAccount.created_by_user_id || ''
  ) || normalizedAccount.created_by_user_id || null;

  return {
    account_id: normalizedAccount.account_id,
    tenant_id: normalizedAccount.tenant_id,
    wechat_id: normalizedAccount.wechat_id,
    nickname: normalizedAccount.nickname,
    owner_membership_id: normalizedAccount.owner_membership_id,
    owner_name: ownerName,
    assistant_membership_ids: [...normalizedAccount.assistant_membership_ids],
    assistant_names: assistantNames,
    customer_count: normalizedAccount.customer_count,
    group_chat_count: normalizedAccount.group_chat_count,
    status: normalizedAccount.status,
    avatar_url: normalizedAccount.avatar_url,
    created_by_user_id: normalizedAccount.created_by_user_id,
    created_by_name: createdByName,
    updated_by_user_id: normalizedAccount.updated_by_user_id,
    created_at: normalizedAccount.created_at,
    updated_at: normalizedAccount.updated_at
  };
};

const createTenantAccountService = ({ authService } = {}) => {
  const authStore = authService?._internals?.authStore;
  if (
    !authService
    || typeof authService.authorizeRoute !== 'function'
    || !authStore
    || typeof authStore.listTenantAccountsByTenantId !== 'function'
    || typeof authStore.createTenantAccount !== 'function'
    || typeof authStore.findTenantAccountByAccountId !== 'function'
    || typeof authStore.updateTenantAccount !== 'function'
    || typeof authStore.updateTenantAccountStatus !== 'function'
    || typeof authStore.listTenantAccountOperationLogs !== 'function'
    || typeof authStore.listTenantUsersByTenantId !== 'function'
  ) {
    throw new TypeError(
      'createTenantAccountService requires authService.authorizeRoute and authService._internals.authStore account capabilities'
    );
  }

  const listAccounts = async ({
    requestId,
    accessToken,
    query = {},
    authorizationContext = null
  }) => {
    const {
      activeTenantId
    } = await resolveAuthorizedTenantRoute({
      authService,
      requestId,
      accessToken,
      authorizationContext,
      permissionCode: TENANT_ACCOUNT_VIEW_PERMISSION_CODE
    });

    const filters = parseListFilters(query || {});

    const memberDirectory = await loadTenantMemberDirectory({
      authStore,
      tenantId: activeTenantId
    });

    let accounts = [];
    try {
      accounts = await authStore.listTenantAccountsByTenantId({
        tenantId: activeTenantId,
        filters
      });
    } catch (error) {
      throw mapStoreErrorToDomainError(error);
    }

    if (!Array.isArray(accounts)) {
      throw tenantAccountErrors.dependencyUnavailable();
    }

    const normalizedAccounts = accounts
      .map((account) =>
        normalizeAccountRecordFromStore({
          account,
          expectedTenantId: activeTenantId
        })
      )
      .filter(Boolean)
      .map((normalizedAccount) =>
        mapAccountForResponse({
          normalizedAccount,
          memberDirectory
        })
      );

    return {
      request_id: requestId || 'request_id_unset',
      tenant_id: activeTenantId,
      filters: {
        wechat_id: filters.wechatId,
        nickname: filters.nickname,
        owner_keyword: filters.ownerKeyword,
        assistant_keyword: filters.assistantKeyword,
        status: filters.status,
        created_at_start: filters.createdAtStart,
        created_at_end: filters.createdAtEnd
      },
      accounts: normalizedAccounts
    };
  };

  const createOrUpdateAccount = async ({
    mode,
    requestId,
    traceparent = null,
    accessToken,
    params = {},
    payload,
    authorizationContext = null
  }) => {
    const {
      operatorUserId,
      activeTenantId
    } = await resolveAuthorizedTenantRoute({
      authService,
      requestId,
      accessToken,
      authorizationContext,
      permissionCode: TENANT_ACCOUNT_OPERATE_PERMISSION_CODE
    });

    const parsedPayload = parseAccountUpsertPayload({
      payload,
      allowedFields:
        mode === 'create' ? CREATE_ACCOUNT_ALLOWED_FIELDS : UPDATE_ACCOUNT_ALLOWED_FIELDS
    });

    const memberDirectory = await loadTenantMemberDirectory({
      authStore,
      tenantId: activeTenantId
    });

    ensureMembershipIdsInTenant({
      ownerMembershipId: parsedPayload.ownerMembershipId,
      assistantMembershipIds: parsedPayload.assistantMembershipIds,
      memberDirectory
    });

    const operatorNameFromDirectory = memberDirectory.byUserId.get(operatorUserId) || null;
    const operatorName = await resolveOperatorDisplayName({
      authStore,
      tenantId: activeTenantId,
      operatorUserId,
      defaultName: operatorNameFromDirectory
    });
    const normalizedOperatorName = normalizeRequiredString(operatorName || '')
      .slice(0, MAX_OPERATOR_NAME_LENGTH)
      || null;

    let storeResult = null;
    try {
      if (mode === 'create') {
        storeResult = await authStore.createTenantAccount({
          tenantId: activeTenantId,
          wechatId: parsedPayload.wechatId,
          nickname: parsedPayload.nickname,
          ownerMembershipId: parsedPayload.ownerMembershipId,
          assistantMembershipIds: parsedPayload.assistantMembershipIds,
          operatorUserId,
          operatorName: normalizedOperatorName,
          requestId,
          traceparent
        });
      } else {
        const accountId = normalizeStrictAccountId(
          resolveRawCamelSnakeField(params || {}, 'accountId', 'account_id')
        );
        storeResult = await authStore.updateTenantAccount({
          tenantId: activeTenantId,
          accountId,
          wechatId: parsedPayload.wechatId,
          nickname: parsedPayload.nickname,
          ownerMembershipId: parsedPayload.ownerMembershipId,
          assistantMembershipIds: parsedPayload.assistantMembershipIds,
          operatorUserId,
          operatorName: normalizedOperatorName,
          requestId,
          traceparent
        });
      }
    } catch (error) {
      throw mapStoreErrorToDomainError(error);
    }

    if (!storeResult) {
      throw tenantAccountErrors.accountNotFound();
    }

    const normalizedAccount = normalizeAccountRecordFromStore({
      account: storeResult,
      expectedTenantId: activeTenantId
    });
    if (!normalizedAccount) {
      throw tenantAccountErrors.dependencyUnavailable();
    }

    return {
      ...mapAccountForResponse({
        normalizedAccount,
        memberDirectory
      }),
      request_id: requestId || 'request_id_unset'
    };
  };

  const createAccount = async ({
    requestId,
    accessToken,
    payload,
    traceparent = null,
    authorizationContext = null
  }) =>
    createOrUpdateAccount({
      mode: 'create',
      requestId,
      accessToken,
      payload,
      traceparent,
      authorizationContext
    });

  const updateAccount = async ({
    requestId,
    accessToken,
    params = {},
    payload,
    traceparent = null,
    authorizationContext = null
  }) =>
    createOrUpdateAccount({
      mode: 'update',
      requestId,
      accessToken,
      params,
      payload,
      traceparent,
      authorizationContext
    });

  const updateAccountStatus = async ({
    requestId,
    traceparent = null,
    accessToken,
    params = {},
    payload,
    authorizationContext = null
  }) => {
    const accountId = normalizeStrictAccountId(
      resolveRawCamelSnakeField(params || {}, 'accountId', 'account_id')
    );
    const nextStatus = parseStatusPayload(payload || {});

    const {
      operatorUserId,
      activeTenantId
    } = await resolveAuthorizedTenantRoute({
      authService,
      requestId,
      accessToken,
      authorizationContext,
      permissionCode: TENANT_ACCOUNT_OPERATE_PERMISSION_CODE
    });

    const memberDirectory = await loadTenantMemberDirectory({
      authStore,
      tenantId: activeTenantId
    });

    const operatorNameFromDirectory = memberDirectory.byUserId.get(operatorUserId) || null;
    const operatorName = await resolveOperatorDisplayName({
      authStore,
      tenantId: activeTenantId,
      operatorUserId,
      defaultName: operatorNameFromDirectory
    });
    const normalizedOperatorName = normalizeRequiredString(operatorName || '')
      .slice(0, MAX_OPERATOR_NAME_LENGTH)
      || null;

    let storeResult = null;
    try {
      storeResult = await authStore.updateTenantAccountStatus({
        tenantId: activeTenantId,
        accountId,
        status: nextStatus,
        operatorUserId,
        operatorName: normalizedOperatorName,
        requestId,
        traceparent
      });
    } catch (error) {
      throw mapStoreErrorToDomainError(error);
    }

    if (!storeResult) {
      throw tenantAccountErrors.accountNotFound();
    }

    const normalizedAccount = normalizeAccountRecordFromStore({
      account: storeResult,
      expectedTenantId: activeTenantId,
      expectedAccountId: accountId
    });
    if (!normalizedAccount) {
      throw tenantAccountErrors.dependencyUnavailable();
    }

    return {
      ...mapAccountForResponse({
        normalizedAccount,
        memberDirectory
      }),
      request_id: requestId || 'request_id_unset'
    };
  };

  const getAccountDetail = async ({
    requestId,
    accessToken,
    params = {},
    authorizationContext = null
  }) => {
    const accountId = normalizeStrictAccountId(
      resolveRawCamelSnakeField(params || {}, 'accountId', 'account_id')
    );

    const {
      activeTenantId
    } = await resolveAuthorizedTenantRoute({
      authService,
      requestId,
      accessToken,
      authorizationContext,
      permissionCode: TENANT_ACCOUNT_VIEW_PERMISSION_CODE
    });

    const memberDirectory = await loadTenantMemberDirectory({
      authStore,
      tenantId: activeTenantId
    });

    let accountRecord = null;
    let operationLogs = [];
    try {
      accountRecord = await authStore.findTenantAccountByAccountId({
        tenantId: activeTenantId,
        accountId
      });
      operationLogs = await authStore.listTenantAccountOperationLogs({
        tenantId: activeTenantId,
        accountId,
        limit: MAX_OPERATION_LOGS_LIMIT
      });
    } catch (error) {
      throw mapStoreErrorToDomainError(error);
    }

    if (!accountRecord) {
      throw tenantAccountErrors.accountNotFound();
    }

    const normalizedAccount = normalizeAccountRecordFromStore({
      account: accountRecord,
      expectedTenantId: activeTenantId,
      expectedAccountId: accountId
    });
    if (!normalizedAccount) {
      throw tenantAccountErrors.dependencyUnavailable();
    }

    const normalizedOperationLogs = (Array.isArray(operationLogs) ? operationLogs : [])
      .map((record) =>
        normalizeOperationLogRecordFromStore({
          record,
          expectedTenantId: activeTenantId,
          expectedAccountId: accountId
        })
      )
      .filter(Boolean)
      .sort((left, right) => {
        const leftTime = Date.parse(left.operation_time);
        const rightTime = Date.parse(right.operation_time);
        if (leftTime !== rightTime) {
          return rightTime - leftTime;
        }
        return String(right.operation_id).localeCompare(String(left.operation_id));
      });

    return {
      ...mapAccountForResponse({
        normalizedAccount,
        memberDirectory
      }),
      operation_logs: normalizedOperationLogs,
      request_id: requestId || 'request_id_unset'
    };
  };

  const listAccountOperationLogs = async ({
    requestId,
    accessToken,
    params = {},
    query = {},
    authorizationContext = null
  }) => {
    const accountId = normalizeStrictAccountId(
      resolveRawCamelSnakeField(params || {}, 'accountId', 'account_id')
    );
    const limit = toOperationLogsLimit(query?.limit);

    const {
      activeTenantId
    } = await resolveAuthorizedTenantRoute({
      authService,
      requestId,
      accessToken,
      authorizationContext,
      permissionCode: TENANT_ACCOUNT_VIEW_PERMISSION_CODE
    });

    let operationLogs = [];
    try {
      operationLogs = await authStore.listTenantAccountOperationLogs({
        tenantId: activeTenantId,
        accountId,
        limit
      });
    } catch (error) {
      throw mapStoreErrorToDomainError(error);
    }

    const normalizedOperationLogs = (Array.isArray(operationLogs) ? operationLogs : [])
      .map((record) =>
        normalizeOperationLogRecordFromStore({
          record,
          expectedTenantId: activeTenantId,
          expectedAccountId: accountId
        })
      )
      .filter(Boolean)
      .sort((left, right) => {
        const leftTime = Date.parse(left.operation_time);
        const rightTime = Date.parse(right.operation_time);
        if (leftTime !== rightTime) {
          return rightTime - leftTime;
        }
        return String(right.operation_id).localeCompare(String(left.operation_id));
      });

    return {
      request_id: requestId || 'request_id_unset',
      tenant_id: activeTenantId,
      account_id: accountId,
      operation_logs: normalizedOperationLogs
    };
  };

  return {
    listAccounts,
    createAccount,
    getAccountDetail,
    updateAccount,
    updateAccountStatus,
    listAccountOperationLogs,
    _internals: {
      tenantAccountErrors
    }
  };
};

module.exports = {
  createTenantAccountService
};
