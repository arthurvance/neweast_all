'use strict';

const { AuthProblemError } = require('../../../../../shared-kernel/auth/auth-problem-error');
const {
  resolveRoutePreauthorizedContext
} = require('../../../../../shared-kernel/auth/route-authz');
const {
  TENANT_SESSION_VIEW_PERMISSION_CODE,
  TENANT_SESSION_OPERATE_PERMISSION_CODE,
  TENANT_SESSION_SCOPE_MY_VIEW_PERMISSION_CODE,
  TENANT_SESSION_SCOPE_ASSIST_VIEW_PERMISSION_CODE,
  TENANT_SESSION_SCOPE_ALL_VIEW_PERMISSION_CODE,
  TENANT_SESSION_SCOPE
} = require('../constants');

const CONTROL_CHAR_PATTERN = /[\u0000-\u001F\u007F]/;
const CONVERSATION_ID_PATTERN = /^[^\s\u0000-\u001F\u007F]{1,64}$/;
const MESSAGE_ID_PATTERN = /^[^\s\u0000-\u001F\u007F]{1,64}$/;
const OUTBOUND_MESSAGE_ID_PATTERN = /^[^\s\u0000-\u001F\u007F]{1,64}$/;
const CLIENT_MESSAGE_ID_PATTERN = /^[^\s\u0000-\u001F\u007F]{1,64}$/;
const MAX_WECHAT_ID_LENGTH = 128;
const MAX_NICKNAME_LENGTH = 128;
const MAX_CONVERSATION_NAME_LENGTH = 128;
const MAX_MESSAGE_TYPE_LENGTH = 32;
const MAX_MESSAGE_PREVIEW_LENGTH = 512;
const MAX_STATUS_LENGTH = 16;
const MAX_SOURCE_EVENT_ID_LENGTH = 128;
const MAX_SOURCE_NAME_LENGTH = 32;
const MAX_PROVIDER_MESSAGE_ID_LENGTH = 128;
const MAX_ERROR_CODE_LENGTH = 64;
const MAX_ERROR_MESSAGE_LENGTH = 512;
const DEFAULT_PAGE = 1;
const DEFAULT_PAGE_SIZE = 20;
const MAX_PAGE_SIZE = 200;
const DEFAULT_MESSAGE_LIMIT = 50;
const DEFAULT_PULL_LIMIT = 100;
const MAX_PULL_LIMIT = 200;
const MAX_MEMBER_LIST_PAGE = 200;
const MEMBER_LIST_PAGE_SIZE = 200;
const SESSION_SCOPE_SET = new Set(['my', 'assist', 'all']);
const CONVERSATION_TYPE_SET = new Set(['direct', 'group']);
const ACCOUNT_STATUS_SET = new Set(['enabled', 'disabled']);
const ACCOUNT_STATUS_MAPPING = Object.freeze({
  active: 'enabled',
  inactive: 'disabled'
});
const ENQUEUE_STATUS_SET = new Set([
  'pending',
  'processing',
  'retrying',
  'sent',
  'failed',
  'dead_letter',
  'cancelled'
]);
const DEFAULT_PULL_STATUS_LIST = Object.freeze(['pending', 'retrying']);
const MESSAGE_CURSOR_PREFIX = 'msg_v1';

const CONVERSATION_INGEST_ALLOWED_FIELDS = new Set([
  'account_wechat_id',
  'accountWechatId',
  'conversation_id',
  'conversationId',
  'conversation_type',
  'conversationType',
  'conversation_name',
  'conversationName',
  'last_message_time',
  'lastMessageTime',
  'last_message_preview',
  'lastMessagePreview',
  'external_updated_at',
  'externalUpdatedAt',
  'sync_source',
  'syncSource'
]);

const HISTORY_INGEST_ALLOWED_FIELDS = new Set([
  'conversation_id',
  'conversationId',
  'sender_name',
  'senderName',
  'message_type',
  'messageType',
  'message_payload_json',
  'messagePayloadJson',
  'message_time',
  'messageTime',
  'source_event_id',
  'sourceEventId',
  'ingest_source',
  'ingestSource'
]);

const CHAT_LIST_ALLOWED_FIELDS = new Set([
  'scope',
  'account_wechat_id',
  'accountWechatId',
  'keyword',
  'page',
  'page_size',
  'pageSize'
]);

const CHAT_MESSAGES_ALLOWED_FIELDS = new Set([
  'scope',
  'account_wechat_id',
  'accountWechatId',
  'cursor',
  'limit'
]);

const ACCOUNT_OPTIONS_ALLOWED_FIELDS = new Set([
  'scope'
]);

const MESSAGE_CREATE_ALLOWED_FIELDS = new Set([
  'account_wechat_id',
  'accountWechatId',
  'account_nickname',
  'accountNickname',
  'conversation_id',
  'conversationId',
  'conversation_name',
  'conversationName',
  'message_type',
  'messageType',
  'message_payload_json',
  'messagePayloadJson',
  'client_message_id',
  'clientMessageId'
]);

const OUTBOUND_PULL_ALLOWED_FIELDS = new Set([
  'status',
  'limit'
]);

const OUTBOUND_STATUS_ALLOWED_FIELDS = new Set([
  'outbound_message_id',
  'outboundMessageId',
  'enqueue_status',
  'enqueueStatus',
  'provider_message_id',
  'providerMessageId',
  'error_code',
  'errorCode',
  'error_message',
  'errorMessage'
]);

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

const toIsoTimestamp = (value) => {
  if (value instanceof Date) {
    return value.toISOString();
  }
  if (value === null || value === undefined) {
    return '';
  }
  const parsed = new Date(value);
  if (Number.isNaN(parsed.getTime())) {
    return '';
  }
  return parsed.toISOString();
};

const isPlainObject = (value) =>
  value !== null
  && typeof value === 'object'
  && !Array.isArray(value);

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

const normalizeDisplayNameForCompare = (value) => {
  const normalized = normalizeRequiredString(value);
  if (!normalized) {
    return '';
  }
  return normalized
    .normalize('NFKC')
    .replace(/\s+/g, ' ')
    .toLowerCase();
};

const normalizeWechatId = (value) => {
  const normalized = normalizeStrictRequiredString(value);
  if (
    !normalized
    || normalized.length > MAX_WECHAT_ID_LENGTH
    || CONTROL_CHAR_PATTERN.test(normalized)
  ) {
    return '';
  }
  return normalized.toLowerCase();
};

const normalizeConversationId = (value) => {
  const normalized = normalizeStrictRequiredString(value);
  if (
    !normalized
    || !CONVERSATION_ID_PATTERN.test(normalized)
  ) {
    return '';
  }
  return normalized;
};

const normalizeOutboundMessageId = (value) => {
  const normalized = normalizeStrictRequiredString(value);
  if (
    !normalized
    || !OUTBOUND_MESSAGE_ID_PATTERN.test(normalized)
  ) {
    return '';
  }
  return normalized;
};

const normalizeClientMessageId = (value) => {
  if (value === undefined || value === null || value === '') {
    return '';
  }
  const normalized = normalizeStrictRequiredString(value);
  if (
    !normalized
    || normalized.length > MAX_SOURCE_EVENT_ID_LENGTH
    || !CLIENT_MESSAGE_ID_PATTERN.test(normalized)
  ) {
    return '';
  }
  return normalized;
};

const normalizeConversationType = (value) => {
  const normalized = normalizeStrictRequiredString(value).toLowerCase();
  if (!CONVERSATION_TYPE_SET.has(normalized)) {
    return '';
  }
  return normalized;
};

const normalizeAccountStatus = (value) => {
  const normalized = normalizeRequiredString(value).toLowerCase();
  if (!normalized) {
    return '';
  }
  const mapped = ACCOUNT_STATUS_MAPPING[normalized] || normalized;
  if (!ACCOUNT_STATUS_SET.has(mapped)) {
    return '';
  }
  return mapped;
};

const normalizeMessageType = (value) => {
  const normalized = normalizeStrictRequiredString(value).toLowerCase();
  if (
    !normalized
    || normalized.length > MAX_MESSAGE_TYPE_LENGTH
    || CONTROL_CHAR_PATTERN.test(normalized)
  ) {
    return '';
  }
  return normalized;
};

const normalizeConversationName = (value) => {
  const normalized = normalizeStrictRequiredString(value);
  if (
    !normalized
    || normalized.length > MAX_CONVERSATION_NAME_LENGTH
    || CONTROL_CHAR_PATTERN.test(normalized)
  ) {
    return '';
  }
  return normalized;
};

const normalizeNickname = (value) => {
  const normalized = normalizeStrictRequiredString(value);
  if (
    !normalized
    || normalized.length > MAX_NICKNAME_LENGTH
    || CONTROL_CHAR_PATTERN.test(normalized)
  ) {
    return '';
  }
  return normalized;
};

const normalizePreviewText = (value) => {
  if (value === undefined || value === null) {
    return null;
  }
  const normalized = normalizeRequiredString(value);
  if (!normalized) {
    return null;
  }
  return normalized.slice(0, MAX_MESSAGE_PREVIEW_LENGTH);
};

const normalizeSourceName = (value, fallbackValue) => {
  const normalized = normalizeRequiredString(value).toLowerCase();
  if (
    !normalized
    || normalized.length > MAX_SOURCE_NAME_LENGTH
    || CONTROL_CHAR_PATTERN.test(normalized)
  ) {
    return fallbackValue;
  }
  return normalized;
};

const normalizeSourceEventId = (value) => {
  if (value === undefined || value === null || value === '') {
    return '';
  }
  const normalized = normalizeStrictRequiredString(value);
  if (
    !normalized
    || normalized.length > MAX_SOURCE_EVENT_ID_LENGTH
    || CONTROL_CHAR_PATTERN.test(normalized)
  ) {
    return '';
  }
  return normalized;
};

const normalizeOptionalTimestamp = (value) => {
  if (value === undefined || value === null || value === '') {
    return null;
  }
  if (typeof value !== 'string' && !(value instanceof Date)) {
    return null;
  }
  const normalizedTimestamp = toIsoTimestamp(value);
  if (!normalizedTimestamp) {
    return null;
  }
  return normalizedTimestamp;
};

const normalizeMessageId = (value) => {
  const normalized = normalizeStrictRequiredString(value);
  if (!normalized || !MESSAGE_ID_PATTERN.test(normalized)) {
    return '';
  }
  return normalized;
};

const toBase64Url = (value) =>
  Buffer.from(String(value || ''), 'utf8')
    .toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/g, '');

const fromBase64Url = (value) => {
  const normalized = String(value || '')
    .replace(/-/g, '+')
    .replace(/_/g, '/');
  if (!normalized) {
    return '';
  }
  const paddingLength = normalized.length % 4;
  const padded =
    normalized + (paddingLength === 0 ? '' : '='.repeat(4 - paddingLength));
  return Buffer.from(padded, 'base64').toString('utf8');
};

const encodeMessageCursor = ({
  messageTime = null,
  createdAt = null,
  messageId = ''
} = {}) => {
  const normalizedMessageTime = normalizeOptionalTimestamp(messageTime);
  const normalizedCreatedAt = normalizeOptionalTimestamp(createdAt);
  const normalizedMessageId = normalizeMessageId(messageId);
  if (!normalizedMessageTime || !normalizedCreatedAt || !normalizedMessageId) {
    return '';
  }
  return `${MESSAGE_CURSOR_PREFIX}.${toBase64Url(
    JSON.stringify({
      v: 1,
      message_time: normalizedMessageTime,
      created_at: normalizedCreatedAt,
      message_id: normalizedMessageId
    })
  )}`;
};

const parseMessageCursor = (cursor) => {
  if (cursor === undefined || cursor === null || cursor === '') {
    return {
      cursorRaw: null,
      cursorTime: null,
      cursorCreatedAt: null,
      cursorMessageId: ''
    };
  }
  if (typeof cursor !== 'string') {
    return null;
  }

  const cursorRaw = cursor.trim();
  if (!cursorRaw) {
    return null;
  }

  const legacyCursorTime = normalizeOptionalTimestamp(cursorRaw);
  if (legacyCursorTime) {
    return {
      cursorRaw,
      cursorTime: legacyCursorTime,
      cursorCreatedAt: null,
      cursorMessageId: ''
    };
  }

  const prefix = `${MESSAGE_CURSOR_PREFIX}.`;
  if (!cursorRaw.startsWith(prefix)) {
    return null;
  }

  let payload = null;
  try {
    payload = JSON.parse(fromBase64Url(cursorRaw.slice(prefix.length)));
  } catch (_error) {
    return null;
  }

  if (!payload || typeof payload !== 'object' || Number(payload.v) !== 1) {
    return null;
  }

  const cursorTime = normalizeOptionalTimestamp(payload.message_time);
  const cursorCreatedAt = normalizeOptionalTimestamp(payload.created_at);
  const cursorMessageId = normalizeMessageId(payload.message_id);
  if (!cursorTime || !cursorCreatedAt || !cursorMessageId) {
    return null;
  }

  return {
    cursorRaw,
    cursorTime,
    cursorCreatedAt,
    cursorMessageId
  };
};

const toPositiveInteger = (value, fallbackValue, maxValue) => {
  const parsed = Number(value);
  if (!Number.isFinite(parsed)) {
    return fallbackValue;
  }
  const normalized = Math.floor(parsed);
  if (normalized < 1) {
    return 1;
  }
  if (normalized > maxValue) {
    return maxValue;
  }
  return normalized;
};

const sessionProblem = ({ status, title, detail, errorCode, extensions = {} }) =>
  new AuthProblemError({
    status,
    title,
    detail,
    errorCode,
    extensions
  });

const tenantSessionErrors = {
  invalidPayload: (detail = '请求参数不完整或格式错误') =>
    sessionProblem({
      status: 400,
      title: 'Bad Request',
      detail,
      errorCode: 'TSESSION-400-INVALID-PAYLOAD'
    }),

  forbidden: () =>
    sessionProblem({
      status: 403,
      title: 'Forbidden',
      detail: '当前操作无权限',
      errorCode: 'AUTH-403-FORBIDDEN'
    }),

  noDomainAccess: () =>
    sessionProblem({
      status: 403,
      title: 'Forbidden',
      detail: '当前入口无可用访问域权限',
      errorCode: 'AUTH-403-NO-DOMAIN'
    }),

  conversationNotFound: () =>
    sessionProblem({
      status: 404,
      title: 'Not Found',
      detail: '目标会话不存在',
      errorCode: 'TSESSION-404-CONVERSATION-NOT-FOUND',
      extensions: {
        retryable: false
      }
    }),

  outboundMessageNotFound: () =>
    sessionProblem({
      status: 404,
      title: 'Not Found',
      detail: '目标消息不存在',
      errorCode: 'TSESSION-404-OUTBOUND-NOT-FOUND',
      extensions: {
        retryable: false
      }
    }),

  conversationConflict: () =>
    sessionProblem({
      status: 409,
      title: 'Conflict',
      detail: 'conversation_id 已存在',
      errorCode: 'CONVERSATION_ID_ALREADY_EXISTS',
      extensions: {
        retryable: false
      }
    }),

  dependencyUnavailable: () =>
    sessionProblem({
      status: 503,
      title: 'Service Unavailable',
      detail: '会话管理依赖暂不可用，请稍后重试',
      errorCode: 'TSESSION-503-DEPENDENCY-UNAVAILABLE',
      extensions: {
        retryable: true
      }
    })
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
    can_view_session_management: Boolean(
      permissionContext.can_view_session_management
      ?? permissionContext.canViewSessionManagement
    ),
    can_operate_session_management: Boolean(
      permissionContext.can_operate_session_management
      ?? permissionContext.canOperateSessionManagement
    ),
    can_view_session_scope_my: Boolean(
      permissionContext.can_view_session_scope_my
      ?? permissionContext.canViewSessionScopeMy
    ),
    can_operate_session_scope_my: Boolean(
      permissionContext.can_operate_session_scope_my
      ?? permissionContext.canOperateSessionScopeMy
    ),
    can_view_session_scope_assist: Boolean(
      permissionContext.can_view_session_scope_assist
      ?? permissionContext.canViewSessionScopeAssist
    ),
    can_operate_session_scope_assist: Boolean(
      permissionContext.can_operate_session_scope_assist
      ?? permissionContext.canOperateSessionScopeAssist
    ),
    can_view_session_scope_all: Boolean(
      permissionContext.can_view_session_scope_all
      ?? permissionContext.canViewSessionScopeAll
    ),
    can_operate_session_scope_all: Boolean(
      permissionContext.can_operate_session_scope_all
      ?? permissionContext.canOperateSessionScopeAll
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

const hasPermissionCodeGrant = (permissionContext = null, permissionCode = '') => {
  const permissionCodeSet = readPermissionCodeSet(permissionContext);
  if (!(permissionCodeSet instanceof Set)) {
    return false;
  }
  return permissionCodeSet.has(String(permissionCode || '').trim().toLowerCase());
};

const hasScopePermission = ({
  permissionContext = null,
  scope = 'my'
}) => {
  const normalizedScope = String(scope || '').trim().toLowerCase();
  if (!SESSION_SCOPE_SET.has(normalizedScope)) {
    return false;
  }
  const hasManagementView = Boolean(
    permissionContext?.can_view_session_management
    || permissionContext?.can_operate_session_management
    || hasPermissionCodeGrant(permissionContext, TENANT_SESSION_VIEW_PERMISSION_CODE)
    || hasPermissionCodeGrant(permissionContext, TENANT_SESSION_OPERATE_PERMISSION_CODE)
  );
  if (!hasManagementView) {
    return false;
  }
  if (normalizedScope === 'my') {
    return Boolean(
      permissionContext?.can_view_session_scope_my
      || permissionContext?.can_operate_session_scope_my
      || hasPermissionCodeGrant(
        permissionContext,
        TENANT_SESSION_SCOPE_MY_VIEW_PERMISSION_CODE
      )
    );
  }
  if (normalizedScope === 'assist') {
    return Boolean(
      permissionContext?.can_view_session_scope_assist
      || permissionContext?.can_operate_session_scope_assist
      || hasPermissionCodeGrant(
        permissionContext,
        TENANT_SESSION_SCOPE_ASSIST_VIEW_PERMISSION_CODE
      )
    );
  }
  return Boolean(
    permissionContext?.can_view_session_scope_all
    || permissionContext?.can_operate_session_scope_all
    || hasPermissionCodeGrant(
      permissionContext,
      TENANT_SESSION_SCOPE_ALL_VIEW_PERMISSION_CODE
    )
  );
};

const ensureScopePermission = ({
  permissionContext = null,
  scope = 'my'
}) => {
  if (!hasScopePermission({ permissionContext, scope })) {
    throw tenantSessionErrors.forbidden();
  }
};

const resolvePermittedScopes = ({
  permissionContext = null
}) => {
  const scopes = [];
  if (hasScopePermission({ permissionContext, scope: 'my' })) {
    scopes.push('my');
  }
  if (hasScopePermission({ permissionContext, scope: 'assist' })) {
    scopes.push('assist');
  }
  if (hasScopePermission({ permissionContext, scope: 'all' })) {
    scopes.push('all');
  }
  return scopes;
};

const resolveAuthorizedOperatorContext = ({
  authorizationContext = null,
  expectedPermissionCode = ''
}) => {
  const preauthorizedContext = resolveRoutePreauthorizedContext({
    authorizationContext,
    expectedPermissionCode,
    expectedScope: TENANT_SESSION_SCOPE,
    expectedEntryDomain: TENANT_SESSION_SCOPE
  });
  if (!preauthorizedContext) {
    return null;
  }

  const activeTenantId = resolveActiveTenantIdFromAuthorizationContext(
    authorizationContext
  );
  if (!activeTenantId) {
    throw tenantSessionErrors.noDomainAccess();
  }
  if (
    !isResolvedOperatorIdentifier(preauthorizedContext.userId)
    || !isResolvedOperatorIdentifier(preauthorizedContext.sessionId)
  ) {
    throw tenantSessionErrors.forbidden();
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
      scope: TENANT_SESSION_SCOPE,
      authorizationContext
    });
  } catch (error) {
    if (error instanceof AuthProblemError) {
      throw error;
    }
    throw tenantSessionErrors.dependencyUnavailable();
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
    throw tenantSessionErrors.forbidden();
  }
  if (!activeTenantId) {
    throw tenantSessionErrors.noDomainAccess();
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

const normalizeMembershipStatus = (status) =>
  normalizeRequiredString(status).toLowerCase();

const loadOperatorMembershipIdSet = async ({
  authStore,
  tenantId,
  operatorUserId
}) => {
  const membershipIdSet = new Set();
  for (let page = 1; page <= MAX_MEMBER_LIST_PAGE; page += 1) {
    let members = [];
    try {
      members = await authStore.listTenantUsersByTenantId({
        tenantId,
        page,
        pageSize: MEMBER_LIST_PAGE_SIZE
      });
    } catch (_error) {
      throw tenantSessionErrors.dependencyUnavailable();
    }
    if (!Array.isArray(members) || members.length < 1) {
      break;
    }
    for (const member of members) {
      const userId = normalizeRequiredString(
        resolveRawCamelSnakeField(member, 'userId', 'user_id')
      );
      if (userId !== operatorUserId) {
        continue;
      }
      const status = normalizeMembershipStatus(member?.status);
      if (status && status !== 'active' && status !== 'enabled') {
        continue;
      }
      const membershipId = normalizeRequiredString(
        resolveRawCamelSnakeField(member, 'membershipId', 'membership_id')
      );
      if (membershipId) {
        membershipIdSet.add(membershipId);
      }
    }
    if (members.length < MEMBER_LIST_PAGE_SIZE) {
      break;
    }
  }
  return membershipIdSet;
};

const normalizeAccountRecordFromStore = ({
  account = null,
  expectedTenantId = ''
}) => {
  if (!account || typeof account !== 'object' || Array.isArray(account)) {
    return null;
  }
  const tenantId = normalizeStrictRequiredString(
    resolveRawCamelSnakeField(account, 'tenantId', 'tenant_id')
  );
  const accountId = normalizeStrictRequiredString(
    resolveRawCamelSnakeField(account, 'accountId', 'account_id')
  ).toLowerCase();
  const wechatId = normalizeStrictRequiredString(
    resolveRawCamelSnakeField(account, 'wechatId', 'wechat_id')
  );
  const nickname = normalizeStrictRequiredString(account.nickname);
  const ownerMembershipId = normalizeRequiredString(
    resolveRawCamelSnakeField(account, 'ownerMembershipId', 'owner_membership_id')
  );
  const status = normalizeAccountStatus(account.status);

  if (
    !tenantId
    || !accountId
    || !wechatId
    || !nickname
    || !ownerMembershipId
    || !status
  ) {
    return null;
  }
  if (expectedTenantId && tenantId !== expectedTenantId) {
    return null;
  }
  const rawAssistantMembershipIds = resolveRawCamelSnakeField(
    account,
    'assistantMembershipIds',
    'assistant_membership_ids'
  );
  const assistantMembershipIdList = Array.isArray(rawAssistantMembershipIds)
    ? rawAssistantMembershipIds
    : normalizeRequiredString(rawAssistantMembershipIds)
      ? String(rawAssistantMembershipIds || '').split(',')
      : [];
  const assistantMembershipIds = [...new Set(
    assistantMembershipIdList
      .map((membershipId) => normalizeRequiredString(membershipId))
      .filter((membershipId) => membershipId.length > 0)
  )];

  return {
    account_id: accountId,
    tenant_id: tenantId,
    wechat_id: wechatId,
    wechat_id_normalized: normalizeWechatId(wechatId),
    nickname,
    nickname_normalized: normalizeDisplayNameForCompare(nickname),
    owner_membership_id: ownerMembershipId,
    assistant_membership_ids: assistantMembershipIds,
    status
  };
};

const loadTenantAccountDirectory = async ({
  authStore,
  tenantId
}) => {
  let accounts = [];
  try {
    accounts = await authStore.listTenantAccountsByTenantId({
      tenantId,
      filters: {
        status: 'enabled'
      }
    });
  } catch (_error) {
    throw tenantSessionErrors.dependencyUnavailable();
  }
  const normalizedAccounts = (Array.isArray(accounts) ? accounts : [])
    .map((account) =>
      normalizeAccountRecordFromStore({
        account,
        expectedTenantId: tenantId
      })
    )
    .filter((account) => account && account.status === 'enabled');
  const byWechatId = new Map();
  for (const account of normalizedAccounts) {
    if (!account.wechat_id_normalized) {
      continue;
    }
    byWechatId.set(account.wechat_id_normalized, account);
  }
  return {
    accounts: normalizedAccounts,
    byWechatId
  };
};

const resolveScopedAccountWechatIdSet = ({
  scope,
  accounts,
  operatorMembershipIdSet
}) => {
  const normalizedScope = String(scope || '').trim().toLowerCase();
  const nextSet = new Set();
  if (normalizedScope === 'all') {
    for (const account of accounts) {
      if (account.wechat_id_normalized) {
        nextSet.add(account.wechat_id_normalized);
      }
    }
    return nextSet;
  }
  if (!(operatorMembershipIdSet instanceof Set) || operatorMembershipIdSet.size < 1) {
    return nextSet;
  }
  for (const account of accounts) {
    if (!account.wechat_id_normalized) {
      continue;
    }
    if (
      normalizedScope === 'my'
      && operatorMembershipIdSet.has(account.owner_membership_id)
    ) {
      nextSet.add(account.wechat_id_normalized);
      continue;
    }
    if (normalizedScope === 'assist') {
      for (const assistantMembershipId of account.assistant_membership_ids) {
        if (operatorMembershipIdSet.has(assistantMembershipId)) {
          nextSet.add(account.wechat_id_normalized);
          break;
        }
      }
    }
  }
  return nextSet;
};

const resolveAllowedAccountWechatIdSet = ({
  permittedScopes,
  accounts,
  operatorMembershipIdSet
}) => {
  const allowedSet = new Set();
  for (const scope of permittedScopes) {
    const scopedSet = resolveScopedAccountWechatIdSet({
      scope,
      accounts,
      operatorMembershipIdSet
    });
    for (const accountWechatId of scopedSet) {
      allowedSet.add(accountWechatId);
    }
  }
  return allowedSet;
};

const parseScope = (value, fallbackScope = 'my') => {
  const normalizedScope = normalizeRequiredString(value).toLowerCase();
  if (!normalizedScope) {
    return fallbackScope;
  }
  if (!SESSION_SCOPE_SET.has(normalizedScope)) {
    throw tenantSessionErrors.invalidPayload('scope 参数仅支持 my|assist|all');
  }
  return normalizedScope;
};

const parseMessagePayloadJson = (value) => {
  if (value === undefined) {
    throw tenantSessionErrors.invalidPayload('message_payload_json 为必填');
  }
  if (typeof value === 'function') {
    throw tenantSessionErrors.invalidPayload('message_payload_json 格式错误');
  }
  return value;
};

const toMessagePreview = ({
  messageType,
  payload
}) => {
  const normalizedMessageType = normalizeRequiredString(messageType).toLowerCase();
  const buildFallbackPreview = () =>
    normalizePreviewText(`[${normalizedMessageType || 'unknown'}]`);
  if (normalizedMessageType === 'text') {
    if (typeof payload === 'string') {
      return normalizePreviewText(payload) || buildFallbackPreview();
    }
    if (isPlainObject(payload)) {
      const text = normalizeRequiredString(
        payload.text || payload.content || payload.message || ''
      );
      return normalizePreviewText(text) || buildFallbackPreview();
    }
  }
  return buildFallbackPreview();
};

const parseStatus = (value) => {
  const normalizedStatus = normalizeStrictRequiredString(value).toLowerCase();
  if (
    !normalizedStatus
    || normalizedStatus.length > MAX_STATUS_LENGTH
    || !ENQUEUE_STATUS_SET.has(normalizedStatus)
  ) {
    throw tenantSessionErrors.invalidPayload('enqueue_status 参数格式错误');
  }
  return normalizedStatus;
};

const parseStatusList = (value) => {
  if (value === undefined || value === null || value === '') {
    return [...DEFAULT_PULL_STATUS_LIST];
  }
  const rawValues = Array.isArray(value) ? value : [value];
  const normalizedStatuses = new Set();
  for (const rawValue of rawValues) {
    if (typeof rawValue !== 'string') {
      throw tenantSessionErrors.invalidPayload('status 参数格式错误');
    }
    for (const segment of rawValue.split(',')) {
      const normalizedStatus = normalizeRequiredString(segment).toLowerCase();
      if (!normalizedStatus) {
        continue;
      }
      if (!ENQUEUE_STATUS_SET.has(normalizedStatus)) {
        throw tenantSessionErrors.invalidPayload('status 参数格式错误');
      }
      normalizedStatuses.add(normalizedStatus);
    }
  }
  if (normalizedStatuses.size < 1) {
    return [...DEFAULT_PULL_STATUS_LIST];
  }
  return [...normalizedStatuses];
};

const mapStoreErrorToDomainError = (error) => {
  if (error instanceof AuthProblemError) {
    return error;
  }
  const code = String(error?.code || '').trim();
  if (code === 'ERR_TENANT_SESSION_CONVERSATION_DUPLICATE') {
    return tenantSessionErrors.conversationConflict();
  }
  if (code === 'ERR_TENANT_SESSION_CONVERSATION_NOT_FOUND') {
    return tenantSessionErrors.conversationNotFound();
  }
  if (code === 'ERR_TENANT_SESSION_OUTBOUND_MESSAGE_NOT_FOUND') {
    return tenantSessionErrors.outboundMessageNotFound();
  }
  return tenantSessionErrors.dependencyUnavailable();
};

const normalizeConversationRecordFromStore = (record) => {
  if (!record || typeof record !== 'object') {
    return null;
  }
  const conversationId = normalizeConversationId(
    resolveRawCamelSnakeField(record, 'conversationId', 'conversation_id')
  );
  const tenantId = normalizeStrictRequiredString(
    resolveRawCamelSnakeField(record, 'tenantId', 'tenant_id')
  );
  const accountWechatId = normalizeStrictRequiredString(
    resolveRawCamelSnakeField(record, 'accountWechatId', 'account_wechat_id')
  );
  const conversationType = normalizeConversationType(
    resolveRawCamelSnakeField(record, 'conversationType', 'conversation_type')
  );
  const conversationName = normalizeStrictRequiredString(
    resolveRawCamelSnakeField(record, 'conversationName', 'conversation_name')
  );
  if (
    !conversationId
    || !tenantId
    || !accountWechatId
    || !conversationType
    || !conversationName
  ) {
    return null;
  }
  return {
    conversation_id: conversationId,
    tenant_id: tenantId,
    account_wechat_id: accountWechatId,
    conversation_type: conversationType,
    conversation_name: conversationName,
    last_message_time: toIsoTimestamp(
      resolveRawCamelSnakeField(record, 'lastMessageTime', 'last_message_time')
    ) || null,
    last_message_preview: normalizePreviewText(
      resolveRawCamelSnakeField(record, 'lastMessagePreview', 'last_message_preview')
    ),
    external_updated_at: toIsoTimestamp(
      resolveRawCamelSnakeField(record, 'externalUpdatedAt', 'external_updated_at')
    ) || null,
    sync_source: normalizeRequiredString(
      resolveRawCamelSnakeField(record, 'syncSource', 'sync_source')
    ) || 'external',
    created_at: toIsoTimestamp(
      resolveRawCamelSnakeField(record, 'createdAt', 'created_at')
    ),
    updated_at: toIsoTimestamp(
      resolveRawCamelSnakeField(record, 'updatedAt', 'updated_at')
    )
  };
};

const normalizeHistoryMessageRecordFromStore = (record) => {
  if (!record || typeof record !== 'object') {
    return null;
  }
  const messageId = normalizeStrictRequiredString(
    resolveRawCamelSnakeField(record, 'messageId', 'message_id')
  );
  const tenantId = normalizeStrictRequiredString(
    resolveRawCamelSnakeField(record, 'tenantId', 'tenant_id')
  );
  const conversationId = normalizeConversationId(
    resolveRawCamelSnakeField(record, 'conversationId', 'conversation_id')
  );
  const senderName = normalizeStrictRequiredString(
    resolveRawCamelSnakeField(record, 'senderName', 'sender_name')
  );
  const messageType = normalizeMessageType(
    resolveRawCamelSnakeField(record, 'messageType', 'message_type')
  );
  const messageTime = toIsoTimestamp(
    resolveRawCamelSnakeField(record, 'messageTime', 'message_time')
  );
  if (
    !messageId
    || !tenantId
    || !conversationId
    || !senderName
    || !messageType
    || !messageTime
  ) {
    return null;
  }
  const isSelfRaw = resolveRawCamelSnakeField(record, 'isSelf', 'is_self');
  const isSelf = isSelfRaw === null || isSelfRaw === undefined
    ? null
    : Number(isSelfRaw) === 1
      ? 1
      : 0;
  return {
    message_id: messageId,
    tenant_id: tenantId,
    conversation_id: conversationId,
    sender_name: senderName,
    is_self: isSelf,
    message_type: messageType,
    message_payload_json: resolveRawCamelSnakeField(
      record,
      'messagePayloadJson',
      'message_payload_json'
    ),
    message_preview: normalizePreviewText(
      resolveRawCamelSnakeField(record, 'messagePreview', 'message_preview')
    ),
    message_time: messageTime,
    source_event_id: normalizeRequiredString(
      resolveRawCamelSnakeField(record, 'sourceEventId', 'source_event_id')
    ) || null,
    ingest_source: normalizeRequiredString(
      resolveRawCamelSnakeField(record, 'ingestSource', 'ingest_source')
    ) || 'external',
    ingested_at: toIsoTimestamp(
      resolveRawCamelSnakeField(record, 'ingestedAt', 'ingested_at')
    ) || null,
    created_at: toIsoTimestamp(
      resolveRawCamelSnakeField(record, 'createdAt', 'created_at')
    ) || null
  };
};

const normalizeOutboundMessageRecordFromStore = (record) => {
  if (!record || typeof record !== 'object') {
    return null;
  }
  const outboundMessageId = normalizeOutboundMessageId(
    resolveRawCamelSnakeField(record, 'outboundMessageId', 'outbound_message_id')
  );
  const tenantId = normalizeStrictRequiredString(
    resolveRawCamelSnakeField(record, 'tenantId', 'tenant_id')
  );
  const accountWechatId = normalizeStrictRequiredString(
    resolveRawCamelSnakeField(record, 'accountWechatId', 'account_wechat_id')
  );
  const accountNickname = normalizeStrictRequiredString(
    resolveRawCamelSnakeField(record, 'accountNickname', 'account_nickname')
  );
  const conversationId = normalizeConversationId(
    resolveRawCamelSnakeField(record, 'conversationId', 'conversation_id')
  );
  const conversationName = normalizeStrictRequiredString(
    resolveRawCamelSnakeField(record, 'conversationName', 'conversation_name')
  );
  const messageType = normalizeMessageType(
    resolveRawCamelSnakeField(record, 'messageType', 'message_type')
  );
  const sendTime = toIsoTimestamp(
    resolveRawCamelSnakeField(record, 'sendTime', 'send_time')
  );
  const enqueueStatus = normalizeRequiredString(
    resolveRawCamelSnakeField(record, 'enqueueStatus', 'enqueue_status')
  ).toLowerCase();
  if (
    !outboundMessageId
    || !tenantId
    || !accountWechatId
    || !accountNickname
    || !conversationId
    || !conversationName
    || !messageType
    || !sendTime
    || !ENQUEUE_STATUS_SET.has(enqueueStatus)
  ) {
    return null;
  }
  return {
    outbound_message_id: outboundMessageId,
    tenant_id: tenantId,
    account_wechat_id: accountWechatId,
    account_nickname: accountNickname,
    conversation_id: conversationId,
    conversation_name: conversationName,
    message_type: messageType,
    message_payload_json: resolveRawCamelSnakeField(
      record,
      'messagePayloadJson',
      'message_payload_json'
    ),
    message_preview: normalizePreviewText(
      resolveRawCamelSnakeField(record, 'messagePreview', 'message_preview')
    ),
    send_time: sendTime,
    enqueue_status: enqueueStatus,
    provider_message_id: normalizeRequiredString(
      resolveRawCamelSnakeField(record, 'providerMessageId', 'provider_message_id')
    ) || null,
    error_code: normalizeRequiredString(
      resolveRawCamelSnakeField(record, 'errorCode', 'error_code')
    ) || null,
    error_message: normalizeRequiredString(
      resolveRawCamelSnakeField(record, 'errorMessage', 'error_message')
    ) || null,
    status_updated_at: toIsoTimestamp(
      resolveRawCamelSnakeField(record, 'statusUpdatedAt', 'status_updated_at')
    ) || null,
    client_message_id: normalizeRequiredString(
      resolveRawCamelSnakeField(record, 'clientMessageId', 'client_message_id')
    ) || null,
    created_at: toIsoTimestamp(
      resolveRawCamelSnakeField(record, 'createdAt', 'created_at')
    ) || null
  };
};

const parseConversationIngestPayload = (payload = {}) => {
  if (!isPlainObject(payload)) {
    throw tenantSessionErrors.invalidPayload();
  }
  for (const key of Object.keys(payload)) {
    if (!CONVERSATION_INGEST_ALLOWED_FIELDS.has(key)) {
      throw tenantSessionErrors.invalidPayload();
    }
  }

  const accountWechatId = normalizeWechatId(
    resolveRawCamelSnakeField(payload, 'accountWechatId', 'account_wechat_id')
  );
  if (!accountWechatId) {
    throw tenantSessionErrors.invalidPayload('account_wechat_id 参数格式错误');
  }
  const conversationId = normalizeConversationId(
    resolveRawCamelSnakeField(payload, 'conversationId', 'conversation_id')
  );
  if (!conversationId) {
    throw tenantSessionErrors.invalidPayload('conversation_id 参数格式错误');
  }
  const conversationType = normalizeConversationType(
    resolveRawCamelSnakeField(payload, 'conversationType', 'conversation_type')
  );
  if (!conversationType) {
    throw tenantSessionErrors.invalidPayload('conversation_type 仅支持 direct|group');
  }
  const conversationName = normalizeConversationName(
    resolveRawCamelSnakeField(payload, 'conversationName', 'conversation_name')
  );
  if (!conversationName) {
    throw tenantSessionErrors.invalidPayload('conversation_name 参数格式错误');
  }
  const lastMessageTime = normalizeOptionalTimestamp(
    resolveRawCamelSnakeField(payload, 'lastMessageTime', 'last_message_time')
  );
  const lastMessagePreview = normalizePreviewText(
    resolveRawCamelSnakeField(payload, 'lastMessagePreview', 'last_message_preview')
  );
  const externalUpdatedAt = normalizeOptionalTimestamp(
    resolveRawCamelSnakeField(payload, 'externalUpdatedAt', 'external_updated_at')
  );
  const syncSource = normalizeSourceName(
    resolveRawCamelSnakeField(payload, 'syncSource', 'sync_source'),
    'external'
  );

  return {
    accountWechatId,
    conversationId,
    conversationType,
    conversationName,
    lastMessageTime,
    lastMessagePreview,
    externalUpdatedAt,
    syncSource
  };
};

const parseHistoryIngestPayload = (payload = {}) => {
  if (!isPlainObject(payload)) {
    throw tenantSessionErrors.invalidPayload();
  }
  for (const key of Object.keys(payload)) {
    if (!HISTORY_INGEST_ALLOWED_FIELDS.has(key)) {
      throw tenantSessionErrors.invalidPayload();
    }
  }
  const conversationId = normalizeConversationId(
    resolveRawCamelSnakeField(payload, 'conversationId', 'conversation_id')
  );
  if (!conversationId) {
    throw tenantSessionErrors.invalidPayload('conversation_id 参数格式错误');
  }
  const senderName = normalizeConversationName(
    resolveRawCamelSnakeField(payload, 'senderName', 'sender_name')
  );
  if (!senderName) {
    throw tenantSessionErrors.invalidPayload('sender_name 参数格式错误');
  }
  const messageType = normalizeMessageType(
    resolveRawCamelSnakeField(payload, 'messageType', 'message_type')
  );
  if (!messageType) {
    throw tenantSessionErrors.invalidPayload('message_type 参数格式错误');
  }
  const messagePayloadJson = parseMessagePayloadJson(
    resolveRawCamelSnakeField(payload, 'messagePayloadJson', 'message_payload_json')
  );
  const messageTime = normalizeOptionalTimestamp(
    resolveRawCamelSnakeField(payload, 'messageTime', 'message_time')
  );
  if (!messageTime) {
    throw tenantSessionErrors.invalidPayload('message_time 参数格式错误');
  }
  const sourceEventId = normalizeSourceEventId(
    resolveRawCamelSnakeField(payload, 'sourceEventId', 'source_event_id')
  );
  const ingestSource = normalizeSourceName(
    resolveRawCamelSnakeField(payload, 'ingestSource', 'ingest_source'),
    'external'
  );
  return {
    conversationId,
    senderName,
    messageType,
    messagePayloadJson,
    messageTime,
    sourceEventId,
    ingestSource
  };
};

const parseChatListQuery = (query = {}) => {
  if (!isPlainObject(query)) {
    throw tenantSessionErrors.invalidPayload();
  }
  for (const key of Object.keys(query)) {
    if (!CHAT_LIST_ALLOWED_FIELDS.has(key)) {
      throw tenantSessionErrors.invalidPayload();
    }
  }
  const scope = parseScope(query.scope, 'my');
  const accountWechatId = normalizeWechatId(
    resolveRawCamelSnakeField(query, 'accountWechatId', 'account_wechat_id')
  );
  const keyword = normalizeRequiredString(query.keyword);
  if (keyword && (keyword.length > MAX_CONVERSATION_NAME_LENGTH || CONTROL_CHAR_PATTERN.test(keyword))) {
    throw tenantSessionErrors.invalidPayload('keyword 参数格式错误');
  }
  const page = toPositiveInteger(
    resolveRawCamelSnakeField(query, 'page', 'page'),
    DEFAULT_PAGE,
    MAX_PAGE_SIZE
  );
  const pageSize = toPositiveInteger(
    resolveRawCamelSnakeField(query, 'pageSize', 'page_size'),
    DEFAULT_PAGE_SIZE,
    MAX_PAGE_SIZE
  );
  return {
    scope,
    accountWechatId,
    keyword,
    page,
    pageSize
  };
};

const parseChatMessagesInput = ({ params = {}, query = {} } = {}) => {
  if (!isPlainObject(params) || !isPlainObject(query)) {
    throw tenantSessionErrors.invalidPayload();
  }
  for (const key of Object.keys(query)) {
    if (!CHAT_MESSAGES_ALLOWED_FIELDS.has(key)) {
      throw tenantSessionErrors.invalidPayload();
    }
  }
  const conversationId = normalizeConversationId(
    resolveRawCamelSnakeField(params, 'conversationId', 'conversation_id')
  );
  if (!conversationId) {
    throw tenantSessionErrors.invalidPayload('conversation_id 参数格式错误');
  }
  const scope = parseScope(query.scope, 'my');
  const accountWechatId = normalizeWechatId(
    resolveRawCamelSnakeField(query, 'accountWechatId', 'account_wechat_id')
  );
  if (!accountWechatId) {
    throw tenantSessionErrors.invalidPayload('account_wechat_id 为必填');
  }
  const parsedCursor = parseMessageCursor(query.cursor);
  if (
    query.cursor !== undefined
    && query.cursor !== null
    && query.cursor !== ''
    && !parsedCursor
  ) {
    throw tenantSessionErrors.invalidPayload('cursor 参数格式错误');
  }
  const limit = toPositiveInteger(query.limit, DEFAULT_MESSAGE_LIMIT, MAX_PAGE_SIZE);
  return {
    conversationId,
    scope,
    accountWechatId,
    cursor: parsedCursor?.cursorTime || null,
    cursorCreatedAt: parsedCursor?.cursorCreatedAt || null,
    cursorMessageId: parsedCursor?.cursorMessageId || '',
    cursorToken: parsedCursor?.cursorRaw || null,
    limit
  };
};

const parseAccountOptionsQuery = (query = {}) => {
  if (!isPlainObject(query)) {
    throw tenantSessionErrors.invalidPayload();
  }
  for (const key of Object.keys(query)) {
    if (!ACCOUNT_OPTIONS_ALLOWED_FIELDS.has(key)) {
      throw tenantSessionErrors.invalidPayload();
    }
  }
  return {
    scope: parseScope(query.scope, 'my')
  };
};

const parseMessageCreatePayload = (payload = {}) => {
  if (!isPlainObject(payload)) {
    throw tenantSessionErrors.invalidPayload();
  }
  for (const key of Object.keys(payload)) {
    if (!MESSAGE_CREATE_ALLOWED_FIELDS.has(key)) {
      throw tenantSessionErrors.invalidPayload();
    }
  }
  const accountWechatId = normalizeWechatId(
    resolveRawCamelSnakeField(payload, 'accountWechatId', 'account_wechat_id')
  );
  if (!accountWechatId) {
    throw tenantSessionErrors.invalidPayload('account_wechat_id 参数格式错误');
  }
  const accountNickname = normalizeNickname(
    resolveRawCamelSnakeField(payload, 'accountNickname', 'account_nickname')
  );
  if (!accountNickname) {
    throw tenantSessionErrors.invalidPayload('account_nickname 参数格式错误');
  }
  const conversationId = normalizeConversationId(
    resolveRawCamelSnakeField(payload, 'conversationId', 'conversation_id')
  );
  if (!conversationId) {
    throw tenantSessionErrors.invalidPayload('conversation_id 参数格式错误');
  }
  const conversationName = normalizeConversationName(
    resolveRawCamelSnakeField(payload, 'conversationName', 'conversation_name')
  );
  if (!conversationName) {
    throw tenantSessionErrors.invalidPayload('conversation_name 参数格式错误');
  }
  const messageType = normalizeMessageType(
    resolveRawCamelSnakeField(payload, 'messageType', 'message_type')
  );
  if (!messageType) {
    throw tenantSessionErrors.invalidPayload('message_type 参数格式错误');
  }
  const messagePayloadJson = parseMessagePayloadJson(
    resolveRawCamelSnakeField(payload, 'messagePayloadJson', 'message_payload_json')
  );
  const clientMessageIdRaw = resolveRawCamelSnakeField(
    payload,
    'clientMessageId',
    'client_message_id'
  );
  const clientMessageId = normalizeClientMessageId(clientMessageIdRaw);
  if (clientMessageIdRaw !== undefined && clientMessageIdRaw !== null && clientMessageIdRaw !== '' && !clientMessageId) {
    throw tenantSessionErrors.invalidPayload('client_message_id 参数格式错误');
  }
  return {
    accountWechatId,
    accountNickname,
    conversationId,
    conversationName,
    messageType,
    messagePayloadJson,
    clientMessageId
  };
};

const parseOutboundPullQuery = (query = {}) => {
  if (!isPlainObject(query)) {
    throw tenantSessionErrors.invalidPayload();
  }
  for (const key of Object.keys(query)) {
    if (!OUTBOUND_PULL_ALLOWED_FIELDS.has(key)) {
      throw tenantSessionErrors.invalidPayload();
    }
  }
  const statuses = parseStatusList(query.status);
  const limit = toPositiveInteger(query.limit, DEFAULT_PULL_LIMIT, MAX_PULL_LIMIT);
  return {
    statuses,
    limit
  };
};

const parseOutboundStatusPayload = (payload = {}) => {
  if (!isPlainObject(payload)) {
    throw tenantSessionErrors.invalidPayload();
  }
  for (const key of Object.keys(payload)) {
    if (!OUTBOUND_STATUS_ALLOWED_FIELDS.has(key)) {
      throw tenantSessionErrors.invalidPayload();
    }
  }
  const outboundMessageId = normalizeOutboundMessageId(
    resolveRawCamelSnakeField(payload, 'outboundMessageId', 'outbound_message_id')
  );
  if (!outboundMessageId) {
    throw tenantSessionErrors.invalidPayload('outbound_message_id 参数格式错误');
  }
  const enqueueStatus = parseStatus(
    resolveRawCamelSnakeField(payload, 'enqueueStatus', 'enqueue_status')
  );
  const providerMessageId = normalizeRequiredString(
    resolveRawCamelSnakeField(payload, 'providerMessageId', 'provider_message_id')
  ).slice(0, MAX_PROVIDER_MESSAGE_ID_LENGTH) || null;
  const errorCode = normalizeRequiredString(
    resolveRawCamelSnakeField(payload, 'errorCode', 'error_code')
  ).slice(0, MAX_ERROR_CODE_LENGTH) || null;
  const errorMessage = normalizeRequiredString(
    resolveRawCamelSnakeField(payload, 'errorMessage', 'error_message')
  ).slice(0, MAX_ERROR_MESSAGE_LENGTH) || null;
  return {
    outboundMessageId,
    enqueueStatus,
    providerMessageId,
    errorCode,
    errorMessage
  };
};

const resolveScopedAccountContext = async ({
  authStore,
  tenantId,
  operatorUserId,
  tenantPermissionContext,
  scope
}) => {
  ensureScopePermission({
    permissionContext: tenantPermissionContext,
    scope
  });
  const accountDirectory = await loadTenantAccountDirectory({
    authStore,
    tenantId
  });
  const operatorMembershipIdSet = await loadOperatorMembershipIdSet({
    authStore,
    tenantId,
    operatorUserId
  });
  const scopedAccountWechatIdSet = resolveScopedAccountWechatIdSet({
    scope,
    accounts: accountDirectory.accounts,
    operatorMembershipIdSet
  });
  return {
    accountDirectory,
    operatorMembershipIdSet,
    scopedAccountWechatIdSet
  };
};

const resolveOperateAccountContext = async ({
  authStore,
  tenantId,
  operatorUserId,
  tenantPermissionContext
}) => {
  const permittedScopes = resolvePermittedScopes({
    permissionContext: tenantPermissionContext
  });
  if (permittedScopes.length < 1) {
    throw tenantSessionErrors.forbidden();
  }
  const accountDirectory = await loadTenantAccountDirectory({
    authStore,
    tenantId
  });
  const operatorMembershipIdSet = await loadOperatorMembershipIdSet({
    authStore,
    tenantId,
    operatorUserId
  });
  const allowedAccountWechatIdSet = resolveAllowedAccountWechatIdSet({
    permittedScopes,
    accounts: accountDirectory.accounts,
    operatorMembershipIdSet
  });
  return {
    accountDirectory,
    allowedAccountWechatIdSet
  };
};

const createTenantSessionService = ({ authService } = {}) => {
  const authStore = authService?._internals?.authStore;
  if (
    !authService
    || typeof authService.authorizeRoute !== 'function'
    || !authStore
    || typeof authStore.listTenantUsersByTenantId !== 'function'
    || typeof authStore.listTenantAccountsByTenantId !== 'function'
    || typeof authStore.createTenantSessionConversation !== 'function'
    || typeof authStore.findTenantSessionConversationByConversationId !== 'function'
    || typeof authStore.listTenantSessionConversationsByAccountWechatId !== 'function'
    || typeof authStore.createTenantSessionHistoryMessage !== 'function'
    || typeof authStore.listTenantSessionHistoryMessagesByConversationId !== 'function'
    || typeof authStore.createTenantSessionOutboundMessage !== 'function'
    || typeof authStore.listTenantSessionOutboundMessagesForPull !== 'function'
    || typeof authStore.findTenantSessionOutboundMessageByOutboundMessageId !== 'function'
    || typeof authStore.updateTenantSessionOutboundMessageStatus !== 'function'
  ) {
    throw new TypeError(
      'createTenantSessionService requires authService.authorizeRoute and authService._internals.authStore tenant session capabilities'
    );
  }

  const ingestConversation = async ({
    requestId,
    accessToken,
    payload,
    traceparent = null,
    authorizationContext = null
  }) => {
    const parsedPayload = parseConversationIngestPayload(payload || {});
    const {
      operatorUserId,
      activeTenantId,
      tenantPermissionContext
    } = await resolveAuthorizedTenantRoute({
      authService,
      requestId,
      accessToken,
      authorizationContext,
      permissionCode: TENANT_SESSION_OPERATE_PERMISSION_CODE
    });
    const {
      accountDirectory,
      allowedAccountWechatIdSet
    } = await resolveOperateAccountContext({
      authStore,
      tenantId: activeTenantId,
      operatorUserId,
      tenantPermissionContext
    });
    const targetAccount =
      accountDirectory.byWechatId.get(parsedPayload.accountWechatId) || null;
    if (!targetAccount) {
      throw tenantSessionErrors.invalidPayload('account_wechat_id 不存在或不可用');
    }
    if (!allowedAccountWechatIdSet.has(targetAccount.wechat_id_normalized)) {
      throw tenantSessionErrors.forbidden();
    }

    let storeResult = null;
    try {
      storeResult = await authStore.createTenantSessionConversation({
        tenantId: activeTenantId,
        accountWechatId: targetAccount.wechat_id,
        conversationId: parsedPayload.conversationId,
        conversationType: parsedPayload.conversationType,
        conversationName: parsedPayload.conversationName,
        lastMessageTime: parsedPayload.lastMessageTime,
        lastMessagePreview: parsedPayload.lastMessagePreview,
        externalUpdatedAt: parsedPayload.externalUpdatedAt,
        syncSource: parsedPayload.syncSource,
        operatorUserId,
        requestId,
        traceparent
      });
    } catch (error) {
      throw mapStoreErrorToDomainError(error);
    }

    const normalizedConversation = normalizeConversationRecordFromStore(storeResult);
    if (!normalizedConversation) {
      throw tenantSessionErrors.dependencyUnavailable();
    }
    return {
      ...normalizedConversation,
      request_id: requestId || 'request_id_unset'
    };
  };

  const ingestHistoryMessage = async ({
    requestId,
    accessToken,
    payload,
    traceparent = null,
    authorizationContext = null
  }) => {
    const parsedPayload = parseHistoryIngestPayload(payload || {});
    const {
      operatorUserId,
      activeTenantId,
      tenantPermissionContext
    } = await resolveAuthorizedTenantRoute({
      authService,
      requestId,
      accessToken,
      authorizationContext,
      permissionCode: TENANT_SESSION_OPERATE_PERMISSION_CODE
    });
    const {
      accountDirectory,
      allowedAccountWechatIdSet
    } = await resolveOperateAccountContext({
      authStore,
      tenantId: activeTenantId,
      operatorUserId,
      tenantPermissionContext
    });

    let conversationRecord = null;
    try {
      conversationRecord = await authStore.findTenantSessionConversationByConversationId({
        tenantId: activeTenantId,
        conversationId: parsedPayload.conversationId
      });
    } catch (error) {
      throw mapStoreErrorToDomainError(error);
    }
    const normalizedConversation = normalizeConversationRecordFromStore(conversationRecord);
    if (!normalizedConversation) {
      throw tenantSessionErrors.conversationNotFound();
    }
    const accountWechatIdNormalized = normalizeWechatId(
      normalizedConversation.account_wechat_id
    );
    if (!allowedAccountWechatIdSet.has(accountWechatIdNormalized)) {
      throw tenantSessionErrors.forbidden();
    }
    const account = accountDirectory.byWechatId.get(accountWechatIdNormalized) || null;
    if (!account) {
      throw tenantSessionErrors.invalidPayload('会话归属账号不存在或不可用');
    }
    const senderNameNormalized = normalizeDisplayNameForCompare(
      parsedPayload.senderName
    );
    const accountNicknameNormalized = normalizeDisplayNameForCompare(account.nickname);
    const isSelf = senderNameNormalized && accountNicknameNormalized
      ? (senderNameNormalized === accountNicknameNormalized ? 1 : 0)
      : null;
    const messagePreview = toMessagePreview({
      messageType: parsedPayload.messageType,
      payload: parsedPayload.messagePayloadJson
    });

    let storeResult = null;
    try {
      storeResult = await authStore.createTenantSessionHistoryMessage({
        tenantId: activeTenantId,
        conversationId: parsedPayload.conversationId,
        senderName: parsedPayload.senderName,
        senderNameNormalized,
        isSelf,
        messageType: parsedPayload.messageType,
        messagePayloadJson: parsedPayload.messagePayloadJson,
        messagePreview,
        messageTime: parsedPayload.messageTime,
        sourceEventId: parsedPayload.sourceEventId,
        ingestSource: parsedPayload.ingestSource,
        operatorUserId,
        requestId,
        traceparent
      });
    } catch (error) {
      throw mapStoreErrorToDomainError(error);
    }

    const normalizedMessage = normalizeHistoryMessageRecordFromStore(storeResult);
    if (!normalizedMessage) {
      throw tenantSessionErrors.dependencyUnavailable();
    }
    return {
      ...normalizedMessage,
      request_id: requestId || 'request_id_unset',
      idempotent_replay: Boolean(storeResult?.idempotent_replay)
    };
  };

  const listChats = async ({
    requestId,
    accessToken,
    query = {},
    authorizationContext = null
  }) => {
    const parsedQuery = parseChatListQuery(query || {});
    const {
      operatorUserId,
      activeTenantId,
      tenantPermissionContext
    } = await resolveAuthorizedTenantRoute({
      authService,
      requestId,
      accessToken,
      authorizationContext,
      permissionCode: TENANT_SESSION_VIEW_PERMISSION_CODE
    });
    const {
      accountDirectory,
      scopedAccountWechatIdSet
    } = await resolveScopedAccountContext({
      authStore,
      tenantId: activeTenantId,
      operatorUserId,
      tenantPermissionContext,
      scope: parsedQuery.scope
    });

    const scopedAccounts = accountDirectory.accounts
      .filter((account) => scopedAccountWechatIdSet.has(account.wechat_id_normalized))
      .sort((left, right) => {
        const leftNickname = String(left.nickname || '');
        const rightNickname = String(right.nickname || '');
        const byNickname = leftNickname.localeCompare(rightNickname, 'zh-Hans-CN');
        if (byNickname !== 0) {
          return byNickname;
        }
        return String(left.wechat_id || '').localeCompare(String(right.wechat_id || ''));
      });

    let selectedAccount = null;
    if (parsedQuery.accountWechatId) {
      if (!scopedAccountWechatIdSet.has(parsedQuery.accountWechatId)) {
        throw tenantSessionErrors.forbidden();
      }
      selectedAccount =
        accountDirectory.byWechatId.get(parsedQuery.accountWechatId) || null;
      if (!selectedAccount) {
        throw tenantSessionErrors.invalidPayload('account_wechat_id 不存在或不可用');
      }
    } else {
      selectedAccount = scopedAccounts[0] || null;
    }

    if (!selectedAccount) {
      return {
        request_id: requestId || 'request_id_unset',
        tenant_id: activeTenantId,
        scope: parsedQuery.scope,
        account_wechat_id: null,
        page: parsedQuery.page,
        page_size: parsedQuery.pageSize,
        total: 0,
        filters: {
          scope: parsedQuery.scope,
          account_wechat_id: '',
          keyword: parsedQuery.keyword || ''
        },
        chats: []
      };
    }

    let conversations = [];
    try {
      conversations = await authStore.listTenantSessionConversationsByAccountWechatId({
        tenantId: activeTenantId,
        accountWechatId: selectedAccount.wechat_id,
        keyword: parsedQuery.keyword
      });
    } catch (error) {
      throw mapStoreErrorToDomainError(error);
    }

    const normalizedConversations = (Array.isArray(conversations) ? conversations : [])
      .map((record) => normalizeConversationRecordFromStore(record))
      .filter(Boolean);
    const offset = (parsedQuery.page - 1) * parsedQuery.pageSize;
    const pagedConversations = normalizedConversations.slice(
      offset,
      offset + parsedQuery.pageSize
    );

    return {
      request_id: requestId || 'request_id_unset',
      tenant_id: activeTenantId,
      scope: parsedQuery.scope,
      account_wechat_id: selectedAccount.wechat_id,
      page: parsedQuery.page,
      page_size: parsedQuery.pageSize,
      total: normalizedConversations.length,
      filters: {
        scope: parsedQuery.scope,
        account_wechat_id: selectedAccount.wechat_id,
        keyword: parsedQuery.keyword || ''
      },
      chats: pagedConversations
    };
  };

  const listChatMessages = async ({
    requestId,
    accessToken,
    params = {},
    query = {},
    authorizationContext = null
  }) => {
    const parsedInput = parseChatMessagesInput({
      params,
      query
    });
    const {
      operatorUserId,
      activeTenantId,
      tenantPermissionContext
    } = await resolveAuthorizedTenantRoute({
      authService,
      requestId,
      accessToken,
      authorizationContext,
      permissionCode: TENANT_SESSION_VIEW_PERMISSION_CODE
    });
    const {
      accountDirectory,
      scopedAccountWechatIdSet
    } = await resolveScopedAccountContext({
      authStore,
      tenantId: activeTenantId,
      operatorUserId,
      tenantPermissionContext,
      scope: parsedInput.scope
    });
    if (!scopedAccountWechatIdSet.has(parsedInput.accountWechatId)) {
      throw tenantSessionErrors.forbidden();
    }
    const selectedAccount =
      accountDirectory.byWechatId.get(parsedInput.accountWechatId) || null;
    if (!selectedAccount) {
      throw tenantSessionErrors.invalidPayload('account_wechat_id 不存在或不可用');
    }

    let conversationRecord = null;
    try {
      conversationRecord = await authStore.findTenantSessionConversationByConversationId({
        tenantId: activeTenantId,
        conversationId: parsedInput.conversationId
      });
    } catch (error) {
      throw mapStoreErrorToDomainError(error);
    }
    const normalizedConversation = normalizeConversationRecordFromStore(conversationRecord);
    if (!normalizedConversation) {
      throw tenantSessionErrors.conversationNotFound();
    }
    if (
      normalizeWechatId(normalizedConversation.account_wechat_id)
      !== selectedAccount.wechat_id_normalized
    ) {
      throw tenantSessionErrors.conversationNotFound();
    }

    let messages = [];
    try {
      messages = await authStore.listTenantSessionHistoryMessagesByConversationId({
        tenantId: activeTenantId,
        conversationId: parsedInput.conversationId,
        cursor: parsedInput.cursor,
        cursorCreatedAt: parsedInput.cursorCreatedAt,
        cursorMessageId: parsedInput.cursorMessageId,
        limit: parsedInput.limit
      });
    } catch (error) {
      throw mapStoreErrorToDomainError(error);
    }

    const normalizedMessages = (Array.isArray(messages) ? messages : [])
      .map((record) => normalizeHistoryMessageRecordFromStore(record))
      .filter(Boolean);
    const lastMessage = normalizedMessages.at(-1) || null;
    const nextCursor = normalizedMessages.length >= parsedInput.limit
      ? (
        encodeMessageCursor({
          messageTime: lastMessage?.message_time,
          createdAt:
            lastMessage?.created_at
            || lastMessage?.ingested_at
            || lastMessage?.message_time,
          messageId: lastMessage?.message_id
        })
        || lastMessage?.message_time
        || null
      )
      : null;

    return {
      request_id: requestId || 'request_id_unset',
      tenant_id: activeTenantId,
      scope: parsedInput.scope,
      account_wechat_id: selectedAccount.wechat_id,
      conversation_id: parsedInput.conversationId,
      cursor: parsedInput.cursorToken,
      limit: parsedInput.limit,
      next_cursor: nextCursor,
      messages: normalizedMessages
    };
  };

  const listAccountOptions = async ({
    requestId,
    accessToken,
    query = {},
    authorizationContext = null
  }) => {
    const parsedQuery = parseAccountOptionsQuery(query || {});
    const {
      operatorUserId,
      activeTenantId,
      tenantPermissionContext
    } = await resolveAuthorizedTenantRoute({
      authService,
      requestId,
      accessToken,
      authorizationContext,
      permissionCode: TENANT_SESSION_VIEW_PERMISSION_CODE
    });
    const {
      accountDirectory,
      scopedAccountWechatIdSet
    } = await resolveScopedAccountContext({
      authStore,
      tenantId: activeTenantId,
      operatorUserId,
      tenantPermissionContext,
      scope: parsedQuery.scope
    });
    const options = accountDirectory.accounts
      .filter((account) => scopedAccountWechatIdSet.has(account.wechat_id_normalized))
      .map((account) => ({
        account_id: account.account_id,
        account_wechat_id: account.wechat_id,
        account_nickname: account.nickname
      }))
      .sort((left, right) => {
        const leftNickname = String(left.account_nickname || '');
        const rightNickname = String(right.account_nickname || '');
        const byNickname = leftNickname.localeCompare(rightNickname, 'zh-Hans-CN');
        if (byNickname !== 0) {
          return byNickname;
        }
        return String(left.account_wechat_id || '').localeCompare(
          String(right.account_wechat_id || '')
        );
      });

    return {
      request_id: requestId || 'request_id_unset',
      tenant_id: activeTenantId,
      scope: parsedQuery.scope,
      accounts: options
    };
  };

  const createOutboundMessage = async ({
    requestId,
    accessToken,
    payload,
    traceparent = null,
    authorizationContext = null
  }) => {
    const parsedPayload = parseMessageCreatePayload(payload || {});
    const {
      operatorUserId,
      activeTenantId,
      tenantPermissionContext
    } = await resolveAuthorizedTenantRoute({
      authService,
      requestId,
      accessToken,
      authorizationContext,
      permissionCode: TENANT_SESSION_OPERATE_PERMISSION_CODE
    });
    const {
      accountDirectory,
      allowedAccountWechatIdSet
    } = await resolveOperateAccountContext({
      authStore,
      tenantId: activeTenantId,
      operatorUserId,
      tenantPermissionContext
    });
    const selectedAccount =
      accountDirectory.byWechatId.get(parsedPayload.accountWechatId) || null;
    if (!selectedAccount) {
      throw tenantSessionErrors.invalidPayload('account_wechat_id 不存在或不可用');
    }
    if (!allowedAccountWechatIdSet.has(selectedAccount.wechat_id_normalized)) {
      throw tenantSessionErrors.forbidden();
    }
    if (
      normalizeDisplayNameForCompare(parsedPayload.accountNickname)
      !== selectedAccount.nickname_normalized
    ) {
      throw tenantSessionErrors.invalidPayload('account_nickname 与账号归属不一致');
    }

    let conversationRecord = null;
    try {
      conversationRecord = await authStore.findTenantSessionConversationByConversationId({
        tenantId: activeTenantId,
        conversationId: parsedPayload.conversationId
      });
    } catch (error) {
      throw mapStoreErrorToDomainError(error);
    }
    const normalizedConversation = normalizeConversationRecordFromStore(conversationRecord);
    if (!normalizedConversation) {
      throw tenantSessionErrors.conversationNotFound();
    }
    if (
      normalizeWechatId(normalizedConversation.account_wechat_id)
      !== selectedAccount.wechat_id_normalized
    ) {
      throw tenantSessionErrors.conversationNotFound();
    }
    if (
      normalizeDisplayNameForCompare(parsedPayload.conversationName)
      !== normalizeDisplayNameForCompare(normalizedConversation.conversation_name)
    ) {
      throw tenantSessionErrors.invalidPayload(
        'conversation_name 与会话归属不一致'
      );
    }

    const messagePreview = toMessagePreview({
      messageType: parsedPayload.messageType,
      payload: parsedPayload.messagePayloadJson
    });
    let storeResult = null;
    try {
      storeResult = await authStore.createTenantSessionOutboundMessage({
        tenantId: activeTenantId,
        accountWechatId: selectedAccount.wechat_id,
        accountNickname: selectedAccount.nickname,
        conversationId: parsedPayload.conversationId,
        conversationName: normalizedConversation.conversation_name,
        messageType: parsedPayload.messageType,
        messagePayloadJson: parsedPayload.messagePayloadJson,
        messagePreview,
        clientMessageId: parsedPayload.clientMessageId,
        operatorUserId,
        requestId,
        traceparent
      });
    } catch (error) {
      throw mapStoreErrorToDomainError(error);
    }
    const normalizedOutbound = normalizeOutboundMessageRecordFromStore(storeResult);
    if (!normalizedOutbound) {
      throw tenantSessionErrors.dependencyUnavailable();
    }
    return {
      ...normalizedOutbound,
      request_id: requestId || 'request_id_unset',
      idempotent_replay: Boolean(storeResult?.idempotent_replay)
    };
  };

  const pullOutboundMessages = async ({
    requestId,
    accessToken,
    query = {},
    authorizationContext = null
  }) => {
    const parsedQuery = parseOutboundPullQuery(query || {});
    const {
      operatorUserId,
      activeTenantId,
      tenantPermissionContext
    } = await resolveAuthorizedTenantRoute({
      authService,
      requestId,
      accessToken,
      authorizationContext,
      permissionCode: TENANT_SESSION_OPERATE_PERMISSION_CODE
    });
    const {
      allowedAccountWechatIdSet
    } = await resolveOperateAccountContext({
      authStore,
      tenantId: activeTenantId,
      operatorUserId,
      tenantPermissionContext
    });
    if (allowedAccountWechatIdSet.size < 1) {
      throw tenantSessionErrors.forbidden();
    }

    let outboundMessages = [];
    try {
      outboundMessages = await authStore.listTenantSessionOutboundMessagesForPull({
        tenantId: activeTenantId,
        statuses: parsedQuery.statuses,
        limit: parsedQuery.limit,
        accountWechatIds: [...allowedAccountWechatIdSet]
      });
    } catch (error) {
      throw mapStoreErrorToDomainError(error);
    }
    const normalizedMessages = (Array.isArray(outboundMessages) ? outboundMessages : [])
      .map((record) => normalizeOutboundMessageRecordFromStore(record))
      .filter(Boolean);
    return {
      request_id: requestId || 'request_id_unset',
      tenant_id: activeTenantId,
      statuses: parsedQuery.statuses,
      limit: parsedQuery.limit,
      messages: normalizedMessages
    };
  };

  const updateOutboundMessageStatus = async ({
    requestId,
    accessToken,
    payload,
    traceparent = null,
    authorizationContext = null
  }) => {
    const parsedPayload = parseOutboundStatusPayload(payload || {});
    const {
      operatorUserId,
      activeTenantId,
      tenantPermissionContext
    } = await resolveAuthorizedTenantRoute({
      authService,
      requestId,
      accessToken,
      authorizationContext,
      permissionCode: TENANT_SESSION_OPERATE_PERMISSION_CODE
    });
    const {
      allowedAccountWechatIdSet
    } = await resolveOperateAccountContext({
      authStore,
      tenantId: activeTenantId,
      operatorUserId,
      tenantPermissionContext
    });
    if (allowedAccountWechatIdSet.size < 1) {
      throw tenantSessionErrors.forbidden();
    }

    let outboundRecord = null;
    try {
      outboundRecord = await authStore.findTenantSessionOutboundMessageByOutboundMessageId({
        tenantId: activeTenantId,
        outboundMessageId: parsedPayload.outboundMessageId
      });
    } catch (error) {
      throw mapStoreErrorToDomainError(error);
    }
    const normalizedOutboundRecord = normalizeOutboundMessageRecordFromStore(outboundRecord);
    if (!normalizedOutboundRecord) {
      throw tenantSessionErrors.outboundMessageNotFound();
    }
    if (!allowedAccountWechatIdSet.has(
      normalizeWechatId(normalizedOutboundRecord.account_wechat_id)
    )) {
      throw tenantSessionErrors.forbidden();
    }

    let storeResult = null;
    try {
      storeResult = await authStore.updateTenantSessionOutboundMessageStatus({
        tenantId: activeTenantId,
        outboundMessageId: parsedPayload.outboundMessageId,
        enqueueStatus: parsedPayload.enqueueStatus,
        providerMessageId: parsedPayload.providerMessageId,
        errorCode: parsedPayload.errorCode,
        errorMessage: parsedPayload.errorMessage,
        statusUpdatedAt: new Date().toISOString(),
        operatorUserId,
        requestId,
        traceparent
      });
    } catch (error) {
      throw mapStoreErrorToDomainError(error);
    }
    if (!storeResult) {
      throw tenantSessionErrors.outboundMessageNotFound();
    }
    const normalizedOutbound = normalizeOutboundMessageRecordFromStore(storeResult);
    if (!normalizedOutbound) {
      throw tenantSessionErrors.dependencyUnavailable();
    }
    return {
      ...normalizedOutbound,
      request_id: requestId || 'request_id_unset'
    };
  };

  return {
    ingestConversation,
    ingestHistoryMessage,
    listChats,
    listChatMessages,
    listAccountOptions,
    createOutboundMessage,
    pullOutboundMessages,
    updateOutboundMessageStatus,
    _internals: {
      tenantSessionErrors,
      hasScopePermission,
      resolvePermittedScopes
    }
  };
};

module.exports = {
  createTenantSessionService
};
