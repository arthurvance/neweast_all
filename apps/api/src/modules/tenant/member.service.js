const { log } = require('../../common/logger');
const { AuthProblemError } = require('../auth/auth.service');
const {
  resolveRoutePreauthorizedContext
} = require('../auth/route-preauthorization');
const {
  TENANT_MEMBER_VIEW_PERMISSION_CODE,
  TENANT_MEMBER_OPERATE_PERMISSION_CODE,
  TENANT_MEMBER_SCOPE
} = require('./member.constants');

const CONTROL_CHAR_PATTERN = /[\u0000-\u001F\u007F]/;
const MAX_STATUS_REASON_LENGTH = 256;
const MAX_MEMBERSHIP_ID_LENGTH = 64;
const MAX_MEMBER_ROLE_BINDINGS = 5;
const MAX_ROLE_ID_LENGTH = 64;
const MAX_AUDIT_TRAIL_ENTRIES = 200;
const DEFAULT_MEMBER_LIST_PAGE = 1;
const DEFAULT_MEMBER_LIST_PAGE_SIZE = 50;
const MAX_MEMBER_LIST_PAGE_SIZE = 200;
const MEMBERSHIP_ID_PATTERN = /^[^\s\u0000-\u001F\u007F]{1,64}$/;
const ROLE_ID_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/;
const MAINLAND_PHONE_PATTERN = /^1\d{10}$/;
const CREATE_MEMBER_ALLOWED_FIELDS = new Set(['phone']);
const UPDATE_MEMBER_STATUS_ALLOWED_FIELDS = new Set(['status', 'reason']);
const REPLACE_MEMBER_ROLES_ALLOWED_FIELDS = new Set(['role_ids']);
const LIST_MEMBER_ALLOWED_FIELDS = new Set(['page', 'page_size']);
const VALID_MEMBER_STATUS = new Set(['active', 'disabled', 'left']);

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

const normalizeMemberStatus = (status) => {
  const normalizedStatus = String(status || '').trim().toLowerCase();
  if (normalizedStatus === 'enabled') {
    return 'active';
  }
  return normalizedStatus;
};

const resolveRawMemberField = (
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

const isValidOptionalTenantName = (value) => {
  if (value === null || value === undefined) {
    return true;
  }
  if (typeof value !== 'string') {
    return false;
  }
  return normalizeRequiredString(value).length > 0;
};

const normalizeOptionalTenantName = (value) => {
  if (!isValidOptionalTenantName(value)) {
    return null;
  }
  if (value === null || value === undefined) {
    return null;
  }
  return normalizeRequiredString(value);
};

const isValidOptionalStrictTenantName = (value) => {
  if (value === null || value === undefined) {
    return true;
  }
  if (typeof value !== 'string') {
    return false;
  }
  return normalizeStrictRequiredString(value).length > 0;
};

const isValidOptionalDateTime = (value) => {
  if (value === null || value === undefined) {
    return true;
  }
  if (typeof value !== 'string') {
    return false;
  }
  const normalized = normalizeRequiredString(value);
  if (!normalized) {
    return false;
  }
  return Number.isFinite(Date.parse(normalized));
};

const normalizeOptionalDateTime = (value) => {
  if (!isValidOptionalDateTime(value)) {
    return null;
  }
  if (value === null || value === undefined) {
    return null;
  }
  return new Date(Date.parse(normalizeRequiredString(value))).toISOString();
};

const isValidOptionalStrictDateTime = (value) => {
  if (value === null || value === undefined) {
    return true;
  }
  if (typeof value !== 'string') {
    return false;
  }
  const normalized = normalizeStrictRequiredString(value);
  if (!normalized) {
    return false;
  }
  return Number.isFinite(Date.parse(normalized));
};

const isValidMembershipId = (value = '') =>
  MEMBERSHIP_ID_PATTERN.test(String(value || ''));

const isValidMainlandPhone = (value = '') =>
  MAINLAND_PHONE_PATTERN.test(String(value || ''));

const maskPhone = (phone) => {
  if (typeof phone !== 'string') {
    return null;
  }
  const normalizedPhone = phone.trim().replace(/\s+/g, '');
  if (!normalizedPhone) {
    return null;
  }
  if (/^1\d{10}$/.test(normalizedPhone)) {
    return `${normalizedPhone.slice(0, 3)}****${normalizedPhone.slice(-4)}`;
  }
  if (normalizedPhone.length <= 4) {
    return '*'.repeat(normalizedPhone.length);
  }
  return `${normalizedPhone.slice(0, 2)}${'*'.repeat(normalizedPhone.length - 4)}${normalizedPhone.slice(-2)}`;
};

const isResolvedOperatorIdentifier = (value) => {
  const normalized = String(value || '').trim();
  return normalized.length > 0 && normalized.toLowerCase() !== 'unknown';
};

const tenantMemberProblem = ({
  status,
  title,
  detail,
  errorCode,
  extensions = {}
}) =>
  new AuthProblemError({
    status,
    title,
    detail,
    errorCode,
    extensions
  });

const tenantMemberErrors = {
  invalidPayload: (detail = '请求参数不完整或格式错误') =>
    tenantMemberProblem({
      status: 400,
      title: 'Bad Request',
      detail,
      errorCode: 'AUTH-400-INVALID-PAYLOAD'
    }),

  forbidden: () =>
    tenantMemberProblem({
      status: 403,
      title: 'Forbidden',
      detail: '当前操作无权限',
      errorCode: 'AUTH-403-FORBIDDEN'
    }),

  noDomainAccess: () =>
    tenantMemberProblem({
      status: 403,
      title: 'Forbidden',
      detail: '当前入口无可用访问域权限',
      errorCode: 'AUTH-403-NO-DOMAIN'
    }),

  membershipNotFound: () =>
    tenantMemberProblem({
      status: 404,
      title: 'Not Found',
      detail: '目标成员关系不存在',
      errorCode: 'AUTH-404-TENANT-MEMBERSHIP-NOT-FOUND',
      extensions: {
        retryable: false
      }
    }),

  dependencyUnavailable: () =>
    tenantMemberProblem({
      status: 503,
      title: 'Service Unavailable',
      detail: '组织成员治理依赖暂不可用，请稍后重试',
      errorCode: 'AUTH-503-TENANT-MEMBER-DEPENDENCY-UNAVAILABLE',
      extensions: {
        retryable: true
      }
    })
};

const mapOperatorContextError = (error) =>
  error instanceof AuthProblemError ? error : tenantMemberErrors.dependencyUnavailable();

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
    expectedScope: TENANT_MEMBER_SCOPE,
    expectedEntryDomain: TENANT_MEMBER_SCOPE
  });
  if (!preauthorizedContext) {
    return null;
  }
  const activeTenantId = resolveActiveTenantIdFromAuthorizationContext(
    authorizationContext
  );
  if (!activeTenantId) {
    return null;
  }
  return {
    operatorUserId: preauthorizedContext.userId,
    operatorSessionId: preauthorizedContext.sessionId,
    activeTenantId
  };
};

const parseCreateMemberPayload = (payload = {}) => {
  if (!isPlainObject(payload)) {
    throw tenantMemberErrors.invalidPayload();
  }
  const unknownPayloadKeys = Object.keys(payload).filter(
    (key) => !CREATE_MEMBER_ALLOWED_FIELDS.has(key)
  );
  if (unknownPayloadKeys.length > 0) {
    throw tenantMemberErrors.invalidPayload();
  }
  if (!Object.prototype.hasOwnProperty.call(payload, 'phone')) {
    throw tenantMemberErrors.invalidPayload('phone 为必填字段');
  }
  if (typeof payload.phone !== 'string') {
    throw tenantMemberErrors.invalidPayload('phone 格式错误');
  }
  const phone = normalizeRequiredString(payload.phone);
  if (!isValidMainlandPhone(phone)) {
    throw tenantMemberErrors.invalidPayload('phone 格式错误');
  }
  return {
    phone
  };
};

const parseMembershipIdFromParams = (params = {}) => {
  const rawMembershipId = params.membership_id;
  if (typeof rawMembershipId !== 'string') {
    throw tenantMemberErrors.invalidPayload('membership_id 不能为空');
  }
  const trimmedMembershipId = normalizeRequiredString(rawMembershipId);
  if (!trimmedMembershipId) {
    throw tenantMemberErrors.invalidPayload('membership_id 不能为空');
  }
  if (rawMembershipId !== trimmedMembershipId) {
    throw tenantMemberErrors.invalidPayload('membership_id 不能包含前后空白字符');
  }
  const membershipId = trimmedMembershipId.toLowerCase();
  if (membershipId.length > MAX_MEMBERSHIP_ID_LENGTH) {
    throw tenantMemberErrors.invalidPayload(
      `membership_id 长度不能超过 ${MAX_MEMBERSHIP_ID_LENGTH}`
    );
  }
  if (CONTROL_CHAR_PATTERN.test(membershipId)) {
    throw tenantMemberErrors.invalidPayload('membership_id 不能包含控制字符');
  }
  if (!isValidMembershipId(membershipId)) {
    throw tenantMemberErrors.invalidPayload('membership_id 格式错误');
  }
  return membershipId;
};

const parseUpdateMemberStatusInput = ({ params = {}, payload = {} } = {}) => {
  const membershipId = parseMembershipIdFromParams(params);
  if (!isPlainObject(payload)) {
    throw tenantMemberErrors.invalidPayload();
  }
  const unknownPayloadKeys = Object.keys(payload).filter(
    (key) => !UPDATE_MEMBER_STATUS_ALLOWED_FIELDS.has(key)
  );
  if (unknownPayloadKeys.length > 0) {
    throw tenantMemberErrors.invalidPayload();
  }
  if (!Object.prototype.hasOwnProperty.call(payload, 'status')) {
    throw tenantMemberErrors.invalidPayload('status 为必填字段');
  }
  if (typeof payload.status !== 'string') {
    throw tenantMemberErrors.invalidPayload('status 必须为字符串');
  }
  const nextStatus = normalizeMemberStatus(payload.status);
  if (!VALID_MEMBER_STATUS.has(nextStatus)) {
    throw tenantMemberErrors.invalidPayload('status 必须为 active、disabled 或 left');
  }

  let reason = null;
  if (Object.prototype.hasOwnProperty.call(payload, 'reason')) {
    if (typeof payload.reason !== 'string') {
      throw tenantMemberErrors.invalidPayload('reason 必须为字符串');
    }
    const normalizedReason = normalizeRequiredString(payload.reason);
    if (!normalizedReason) {
      throw tenantMemberErrors.invalidPayload('reason 不能为空字符串');
    }
    if (CONTROL_CHAR_PATTERN.test(normalizedReason)) {
      throw tenantMemberErrors.invalidPayload('reason 不能包含控制字符');
    }
    if (normalizedReason.length > MAX_STATUS_REASON_LENGTH) {
      throw tenantMemberErrors.invalidPayload(
        `reason 长度不能超过 ${MAX_STATUS_REASON_LENGTH}`
      );
    }
    reason = normalizedReason;
  }

  return {
    membershipId,
    nextStatus,
    reason
  };
};

const parseReplaceMemberRolesInput = ({ params = {}, payload = {} } = {}) => {
  const membershipId = parseMembershipIdFromParams(params);
  if (!isPlainObject(payload)) {
    throw tenantMemberErrors.invalidPayload();
  }
  const unknownPayloadKeys = Object.keys(payload).filter(
    (key) => !REPLACE_MEMBER_ROLES_ALLOWED_FIELDS.has(key)
  );
  if (unknownPayloadKeys.length > 0) {
    throw tenantMemberErrors.invalidPayload('请求参数不完整或格式错误');
  }
  if (!Object.prototype.hasOwnProperty.call(payload, 'role_ids')) {
    throw tenantMemberErrors.invalidPayload('role_ids 为必填字段');
  }
  if (!Array.isArray(payload.role_ids)) {
    throw tenantMemberErrors.invalidPayload('role_ids 必须为数组');
  }
  if (
    payload.role_ids.length === 0
    || payload.role_ids.length > MAX_MEMBER_ROLE_BINDINGS
  ) {
    throw tenantMemberErrors.invalidPayload(
      `role_ids 数量必须在 1 到 ${MAX_MEMBER_ROLE_BINDINGS} 之间`
    );
  }
  const dedupedRoleIds = new Map();
  for (const roleId of payload.role_ids) {
    if (typeof roleId !== 'string') {
      throw tenantMemberErrors.invalidPayload('role_ids 仅允许字符串');
    }
    const normalizedRoleId = roleId.trim().toLowerCase();
    if (!normalizedRoleId) {
      throw tenantMemberErrors.invalidPayload('role_ids 不能为空字符串');
    }
    if (roleId !== roleId.trim()) {
      throw tenantMemberErrors.invalidPayload('role_ids 不能包含前后空白字符');
    }
    if (normalizedRoleId.length > MAX_ROLE_ID_LENGTH) {
      throw tenantMemberErrors.invalidPayload(
        `role_ids 中元素长度不能超过 ${MAX_ROLE_ID_LENGTH}`
      );
    }
    if (CONTROL_CHAR_PATTERN.test(normalizedRoleId)) {
      throw tenantMemberErrors.invalidPayload('role_ids 不能包含控制字符');
    }
    if (!ROLE_ID_PATTERN.test(normalizedRoleId)) {
      throw tenantMemberErrors.invalidPayload('role_ids 格式错误');
    }
    if (dedupedRoleIds.has(normalizedRoleId)) {
      throw tenantMemberErrors.invalidPayload('role_ids 不允许重复');
    }
    dedupedRoleIds.set(normalizedRoleId, normalizedRoleId);
  }
  return {
    membershipId,
    roleIds: [...dedupedRoleIds.values()]
  };
};

const normalizeStrictRoleIdsFromBindings = ({
  bindings = {},
  minCount = 0,
  maxCount = MAX_MEMBER_ROLE_BINDINGS
} = {}) => {
  const rawRoleIds = Array.isArray(bindings?.role_ids)
    ? bindings.role_ids
    : Array.isArray(bindings?.roleIds)
      ? bindings.roleIds
      : null;
  if (!Array.isArray(rawRoleIds)) {
    return null;
  }
  if (rawRoleIds.length < minCount || rawRoleIds.length > maxCount) {
    return null;
  }
  const normalizedRoleIds = [];
  const seenRoleIds = new Set();
  for (const roleId of rawRoleIds) {
    if (typeof roleId !== 'string') {
      return null;
    }
    const trimmedRoleId = roleId.trim();
    if (roleId !== trimmedRoleId) {
      return null;
    }
    const normalizedRoleId = trimmedRoleId.toLowerCase();
    if (
      !normalizedRoleId
      || normalizedRoleId.length > MAX_ROLE_ID_LENGTH
      || CONTROL_CHAR_PATTERN.test(normalizedRoleId)
      || !ROLE_ID_PATTERN.test(normalizedRoleId)
      || seenRoleIds.has(normalizedRoleId)
    ) {
      return null;
    }
    seenRoleIds.add(normalizedRoleId);
    normalizedRoleIds.push(normalizedRoleId);
  }
  return normalizedRoleIds;
};

const parsePositiveInteger = ({
  rawValue,
  fallback,
  min = 1,
  max = Number.MAX_SAFE_INTEGER,
  field
}) => {
  if (rawValue === undefined || rawValue === null) {
    return fallback;
  }
  if (typeof rawValue !== 'string' && typeof rawValue !== 'number') {
    throw tenantMemberErrors.invalidPayload(`${field} 必须为正整数`);
  }
  const normalized = String(rawValue).trim();
  if (!/^\d+$/.test(normalized)) {
    throw tenantMemberErrors.invalidPayload(`${field} 必须为正整数`);
  }
  const parsed = Number.parseInt(normalized, 10);
  if (!Number.isFinite(parsed) || parsed < min || parsed > max) {
    throw tenantMemberErrors.invalidPayload(
      `${field} 必须在 ${min} 到 ${max} 之间`
    );
  }
  return parsed;
};

const parseListMembersQuery = (query = {}) => {
  if (!isPlainObject(query)) {
    throw tenantMemberErrors.invalidPayload('查询参数格式错误');
  }
  const unknownQueryKeys = Object.keys(query).filter(
    (key) => !LIST_MEMBER_ALLOWED_FIELDS.has(key)
  );
  if (unknownQueryKeys.length > 0) {
    throw tenantMemberErrors.invalidPayload('查询参数不支持');
  }
  const page = parsePositiveInteger({
    rawValue: query.page,
    fallback: DEFAULT_MEMBER_LIST_PAGE,
    min: 1,
    max: 100000,
    field: 'page'
  });
  const pageSize = parsePositiveInteger({
    rawValue: query.page_size,
    fallback: DEFAULT_MEMBER_LIST_PAGE_SIZE,
    min: 1,
    max: MAX_MEMBER_LIST_PAGE_SIZE,
    field: 'page_size'
  });
  return {
    page,
    pageSize
  };
};

const normalizeMemberRecord = (record = {}) => {
  const source = isPlainObject(record) ? record : {};
  const rawTenantName = resolveRawMemberField(
    source,
    'tenantName',
    'tenant_name'
  ) ?? null;
  const rawJoinedAt = resolveRawMemberField(
    source,
    'joinedAt',
    'joined_at'
  ) ?? null;
  const rawLeftAt = resolveRawMemberField(
    source,
    'leftAt',
    'left_at'
  ) ?? null;
  return {
    membership_id: normalizeRequiredString(resolveRawMemberField(
      source,
      'membershipId',
      'membership_id'
    )),
    user_id: normalizeRequiredString(resolveRawMemberField(
      source,
      'userId',
      'user_id'
    )),
    tenant_id: normalizeRequiredString(resolveRawMemberField(
      source,
      'tenantId',
      'tenant_id'
    )),
    tenant_name: normalizeOptionalTenantName(rawTenantName),
    phone: normalizeRequiredString(source.phone),
    status: normalizeMemberStatus(source.status),
    joined_at: normalizeOptionalDateTime(rawJoinedAt),
    left_at: normalizeOptionalDateTime(rawLeftAt)
  };
};

const isValidNormalizedMemberRecordFromRaw = ({
  member = {},
  rawMember = {},
  activeTenantId = '',
  expectedStatus = null,
  expectedUserId = '',
  expectedPhone = ''
} = {}) => {
  const rawMembershipId = normalizeStrictRequiredString(
    resolveRawMemberField(rawMember, 'membershipId', 'membership_id')
  );
  const rawUserId = normalizeStrictRequiredString(
    resolveRawMemberField(rawMember, 'userId', 'user_id')
  );
  const rawTenantId = normalizeStrictRequiredString(
    resolveRawMemberField(rawMember, 'tenantId', 'tenant_id')
  );
  const rawPhone = normalizeStrictRequiredString(rawMember?.phone);
  const rawStatus = normalizeMemberStatus(
    normalizeStrictRequiredString(rawMember?.status)
  );
  const rawTenantName = resolveRawMemberField(
    rawMember,
    'tenantName',
    'tenant_name'
  ) ?? null;
  const rawJoinedAt = resolveRawMemberField(
    rawMember,
    'joinedAt',
    'joined_at'
  ) ?? null;
  const rawLeftAt = resolveRawMemberField(
    rawMember,
    'leftAt',
    'left_at'
  ) ?? null;
  const normalizedExpectedStatus = expectedStatus === null
    ? null
    : normalizeMemberStatus(expectedStatus);
  const normalizedExpectedUserId = normalizeRequiredString(expectedUserId);
  const normalizedExpectedPhone = normalizeRequiredString(expectedPhone);

  return (
    !!rawMembershipId
    && !!rawUserId
    && !!rawTenantId
    && !!rawPhone
    && !!rawStatus
    && rawMembershipId === String(member?.membership_id || '')
    && rawUserId === String(member?.user_id || '')
    && rawTenantId === String(member?.tenant_id || '')
    && rawPhone === String(member?.phone || '')
    && rawStatus === String(member?.status || '')
    && isValidMembershipId(member?.membership_id)
    && !!member?.user_id
    && !!member?.tenant_id
    && isValidMainlandPhone(member?.phone)
    && VALID_MEMBER_STATUS.has(String(member?.status || ''))
    && String(member?.tenant_id || '') === String(activeTenantId || '').trim()
    && (
      normalizedExpectedStatus === null
      || String(member?.status || '') === normalizedExpectedStatus
    )
    && (
      !normalizedExpectedUserId
      || String(member?.user_id || '') === normalizedExpectedUserId
    )
    && (
      !normalizedExpectedPhone
      || String(member?.phone || '') === normalizedExpectedPhone
    )
    && isValidOptionalStrictTenantName(rawTenantName)
    && isValidOptionalStrictDateTime(rawJoinedAt)
    && isValidOptionalStrictDateTime(rawLeftAt)
  );
};

const createTenantMemberService = ({ authService } = {}) => {
  const auditTrail = [];

  const addAuditEvent = ({
    type,
    requestId,
    operatorUserId = 'unknown',
    detail,
    metadata = {}
  }) => {
    const event = {
      type: String(type || '').trim() || 'tenant.member.unknown',
      at: new Date().toISOString(),
      request_id: String(requestId || '').trim() || 'request_id_unset',
      operator_user_id: String(operatorUserId || '').trim() || 'unknown',
      detail: String(detail || '').trim(),
      ...metadata
    };
    auditTrail.push(event);
    if (auditTrail.length > MAX_AUDIT_TRAIL_ENTRIES) {
      auditTrail.splice(0, auditTrail.length - MAX_AUDIT_TRAIL_ENTRIES);
    }
    log('info', 'Tenant member audit event', event);
  };

  const assertAuthServiceMethod = (methodName) => {
    if (!authService || typeof authService[methodName] !== 'function') {
      throw tenantMemberErrors.dependencyUnavailable();
    }
  };

  const resolveOperatorContext = async ({
    requestId,
    accessToken,
    authorizationContext = null,
    permissionCode
  }) => {
    const preAuthorizedOperatorContext = resolveAuthorizedOperatorContext({
      authorizationContext,
      expectedPermissionCode: permissionCode
    });
    if (preAuthorizedOperatorContext) {
      return preAuthorizedOperatorContext;
    }

    assertAuthServiceMethod('authorizeRoute');
    const authorized = await authService.authorizeRoute({
      requestId,
      accessToken,
      permissionCode,
      scope: TENANT_MEMBER_SCOPE,
      authorizationContext
    });
    const operatorUserId = normalizeRequiredString(
      authorized?.user_id
        || authorized?.userId
        || authorized?.user?.id
        || authorized?.user?.user_id
        || authorized?.user?.userId
    );
    const operatorSessionId = normalizeRequiredString(
      authorized?.session_id
        || authorized?.sessionId
        || authorized?.session?.session_id
        || authorized?.session?.sessionId
    );
    const activeTenantId = resolveActiveTenantIdFromAuthorizationContext(authorized);
    if (!activeTenantId) {
      throw tenantMemberErrors.noDomainAccess();
    }
    if (
      !isResolvedOperatorIdentifier(operatorUserId)
      || !isResolvedOperatorIdentifier(operatorSessionId)
    ) {
      throw tenantMemberErrors.forbidden();
    }

    return {
      operatorUserId,
      operatorSessionId,
      activeTenantId
    };
  };

  const listMembers = async ({
    requestId,
    accessToken,
    query = {},
    authorizationContext = null
  }) => {
    const resolvedRequestId = String(requestId || '').trim() || 'request_id_unset';
    const listQuery = parseListMembersQuery(query);
    let operatorContext;
    try {
      operatorContext = await resolveOperatorContext({
        requestId: resolvedRequestId,
        accessToken,
        authorizationContext,
        permissionCode: TENANT_MEMBER_VIEW_PERMISSION_CODE
      });
    } catch (error) {
      const mappedError = mapOperatorContextError(error);
      addAuditEvent({
        type: 'tenant.member.list.rejected',
        requestId: resolvedRequestId,
        operatorUserId: 'unknown',
        detail: 'operator authorization context invalid',
        metadata: {
          error_code: mappedError.errorCode
        }
      });
      throw mappedError;
    }

    const { operatorUserId, activeTenantId } = operatorContext;
    assertAuthServiceMethod('listTenantMembers');
    let members = [];
    try {
      members = await authService.listTenantMembers({
        requestId: resolvedRequestId,
        tenantId: activeTenantId,
        page: listQuery.page,
        pageSize: listQuery.pageSize,
        authorizationContext
      });
    } catch (error) {
      if (error instanceof AuthProblemError) {
        addAuditEvent({
          type: 'tenant.member.list.rejected',
          requestId: resolvedRequestId,
          operatorUserId,
          detail: 'tenant member listing rejected',
          metadata: {
            tenant_id: activeTenantId,
            error_code: error.errorCode
          }
        });
        throw error;
      }
      addAuditEvent({
        type: 'tenant.member.list.rejected',
        requestId: resolvedRequestId,
        operatorUserId,
        detail: 'tenant member listing dependency unavailable',
        metadata: {
          tenant_id: activeTenantId,
          error_code: 'AUTH-503-TENANT-MEMBER-DEPENDENCY-UNAVAILABLE'
        }
      });
      throw tenantMemberErrors.dependencyUnavailable();
    }

    if (!Array.isArray(members)) {
      addAuditEvent({
        type: 'tenant.member.list.rejected',
        requestId: resolvedRequestId,
        operatorUserId,
        detail: 'tenant member listing returned malformed payload',
        metadata: {
          tenant_id: activeTenantId,
          error_code: 'AUTH-503-TENANT-MEMBER-DEPENDENCY-UNAVAILABLE'
        }
      });
      throw tenantMemberErrors.dependencyUnavailable();
    }
    const normalizedMembers = members.map((member) => normalizeMemberRecord(member));
    const hasMalformedMember = normalizedMembers.some((member, index) =>
      !isValidNormalizedMemberRecordFromRaw({
        member,
        rawMember: members[index],
        activeTenantId
      })
    );
    if (hasMalformedMember) {
      addAuditEvent({
        type: 'tenant.member.list.rejected',
        requestId: resolvedRequestId,
        operatorUserId,
        detail: 'tenant member listing returned malformed relationship record',
        metadata: {
          tenant_id: activeTenantId,
          error_code: 'AUTH-503-TENANT-MEMBER-DEPENDENCY-UNAVAILABLE'
        }
      });
      throw tenantMemberErrors.dependencyUnavailable();
    }
    const hasCrossTenantMember = normalizedMembers.some(
      (member) => member.tenant_id !== activeTenantId
    );
    if (hasCrossTenantMember) {
      addAuditEvent({
        type: 'tenant.member.list.rejected',
        requestId: resolvedRequestId,
        operatorUserId,
        detail: 'tenant member listing returned inconsistent tenant relationship',
        metadata: {
          tenant_id: activeTenantId,
          error_code: 'AUTH-503-TENANT-MEMBER-DEPENDENCY-UNAVAILABLE'
        }
      });
      throw tenantMemberErrors.dependencyUnavailable();
    }

    addAuditEvent({
      type: 'tenant.member.listed',
      requestId: resolvedRequestId,
      operatorUserId,
      detail: 'tenant members listed',
      metadata: {
        tenant_id: activeTenantId,
        page: listQuery.page,
        page_size: listQuery.pageSize,
        member_count: normalizedMembers.length
      }
    });

    return {
      tenant_id: activeTenantId,
      page: listQuery.page,
      page_size: listQuery.pageSize,
      members: normalizedMembers,
      request_id: resolvedRequestId
    };
  };

  const createMember = async ({
    requestId,
    accessToken,
    payload = {},
    authorizationContext = null
  }) => {
    const resolvedRequestId = String(requestId || '').trim() || 'request_id_unset';
    const parsedPayload = parseCreateMemberPayload(payload);
    const maskedPhone = maskPhone(parsedPayload.phone);
    let operatorContext;
    try {
      operatorContext = await resolveOperatorContext({
        requestId: resolvedRequestId,
        accessToken,
        authorizationContext,
        permissionCode: TENANT_MEMBER_OPERATE_PERMISSION_CODE
      });
    } catch (error) {
      const mappedError = mapOperatorContextError(error);
      addAuditEvent({
        type: 'tenant.member.create.rejected',
        requestId: resolvedRequestId,
        operatorUserId: 'unknown',
        detail: 'operator authorization context invalid',
        metadata: {
          tenant_id: null,
          phone: maskedPhone,
          error_code: mappedError.errorCode
        }
      });
      throw mappedError;
    }

    const { operatorUserId, operatorSessionId, activeTenantId } = operatorContext;
    assertAuthServiceMethod('provisionTenantUserByPhone');
    assertAuthServiceMethod('findTenantMembershipByUserAndTenantId');

    let provisionedUser = null;
    try {
      provisionedUser = await authService.provisionTenantUserByPhone({
        requestId: resolvedRequestId,
        accessToken,
        payload: parsedPayload,
        authorizationContext,
        authorizedRoute: {
          user_id: operatorUserId,
          session_id: operatorSessionId,
          entry_domain: TENANT_MEMBER_SCOPE,
          active_tenant_id: activeTenantId
        }
      });
    } catch (error) {
      if (error instanceof AuthProblemError) {
        addAuditEvent({
          type: 'tenant.member.create.rejected',
          requestId: resolvedRequestId,
          operatorUserId,
          detail: 'tenant member provisioning rejected',
          metadata: {
            tenant_id: activeTenantId,
            phone: maskedPhone,
            error_code: error.errorCode
          }
        });
        throw error;
      }
      addAuditEvent({
        type: 'tenant.member.create.rejected',
        requestId: resolvedRequestId,
        operatorUserId,
        detail: 'tenant member provisioning dependency unavailable',
        metadata: {
          tenant_id: activeTenantId,
          phone: maskedPhone,
          error_code: 'AUTH-503-TENANT-MEMBER-DEPENDENCY-UNAVAILABLE'
        }
      });
      throw tenantMemberErrors.dependencyUnavailable();
    }

    const targetUserId = normalizeRequiredString(provisionedUser?.user_id);
    if (!targetUserId) {
      addAuditEvent({
        type: 'tenant.member.create.rejected',
        requestId: resolvedRequestId,
        operatorUserId,
        detail: 'tenant member provisioning returned incomplete user identity',
        metadata: {
          tenant_id: activeTenantId,
          phone: maskedPhone,
          error_code: 'AUTH-503-TENANT-MEMBER-DEPENDENCY-UNAVAILABLE'
        }
      });
      throw tenantMemberErrors.dependencyUnavailable();
    }
    const hasCreatedUserFlag = typeof provisionedUser?.created_user === 'boolean';
    const hasReusedExistingUserFlag = typeof provisionedUser?.reused_existing_user === 'boolean';
    if (!hasCreatedUserFlag || !hasReusedExistingUserFlag) {
      addAuditEvent({
        type: 'tenant.member.create.rejected',
        requestId: resolvedRequestId,
        operatorUserId,
        detail: 'tenant member provisioning returned incomplete identity reuse flags',
        metadata: {
          tenant_id: activeTenantId,
          phone: maskedPhone,
          target_user_id: targetUserId,
          error_code: 'AUTH-503-TENANT-MEMBER-DEPENDENCY-UNAVAILABLE'
        }
      });
      throw tenantMemberErrors.dependencyUnavailable();
    }
    const createdUser = provisionedUser.created_user;
    const reusedExistingUser = provisionedUser.reused_existing_user;
    if (createdUser === reusedExistingUser) {
      addAuditEvent({
        type: 'tenant.member.create.rejected',
        requestId: resolvedRequestId,
        operatorUserId,
        detail: 'tenant member provisioning returned inconsistent identity reuse flags',
        metadata: {
          tenant_id: activeTenantId,
          phone: maskedPhone,
          target_user_id: targetUserId,
          error_code: 'AUTH-503-TENANT-MEMBER-DEPENDENCY-UNAVAILABLE'
        }
      });
      throw tenantMemberErrors.dependencyUnavailable();
    }

    let membership = null;
    try {
      membership = await authService.findTenantMembershipByUserAndTenantId({
        userId: targetUserId,
        tenantId: activeTenantId
      });
    } catch (error) {
      if (error instanceof AuthProblemError) {
        addAuditEvent({
          type: 'tenant.member.create.rejected',
          requestId: resolvedRequestId,
          operatorUserId,
          detail: 'tenant member lookup rejected',
          metadata: {
            tenant_id: activeTenantId,
            phone: maskedPhone,
            target_user_id: targetUserId,
            error_code: error.errorCode
          }
        });
        throw error;
      }
      addAuditEvent({
        type: 'tenant.member.create.rejected',
        requestId: resolvedRequestId,
        operatorUserId,
        detail: 'tenant member lookup dependency unavailable',
        metadata: {
          tenant_id: activeTenantId,
          phone: maskedPhone,
          target_user_id: targetUserId,
          error_code: 'AUTH-503-TENANT-MEMBER-DEPENDENCY-UNAVAILABLE'
        }
      });
      throw tenantMemberErrors.dependencyUnavailable();
    }
    const normalizedMembership = normalizeMemberRecord(membership || {});
    if (
      !isValidNormalizedMemberRecordFromRaw({
        member: normalizedMembership,
        rawMember: membership || {},
        activeTenantId,
        expectedStatus: 'active',
        expectedUserId: targetUserId,
        expectedPhone: parsedPayload.phone
      })
    ) {
      addAuditEvent({
        type: 'tenant.member.create.rejected',
        requestId: resolvedRequestId,
        operatorUserId,
        detail: 'tenant member lookup returned inconsistent relationship',
        metadata: {
          tenant_id: activeTenantId,
          phone: maskedPhone,
          target_user_id: targetUserId,
          error_code: 'AUTH-503-TENANT-MEMBER-DEPENDENCY-UNAVAILABLE'
        }
      });
      throw tenantMemberErrors.dependencyUnavailable();
    }

    addAuditEvent({
      type:
        createdUser
          ? 'tenant.member.created'
          : 'tenant.member.identity_reused',
      requestId: resolvedRequestId,
      operatorUserId,
      detail:
        createdUser
          ? 'tenant member created with new user identity'
          : 'tenant member created by reusing existing user identity',
      metadata: {
        tenant_id: activeTenantId,
        membership_id: normalizedMembership.membership_id,
        target_user_id: normalizedMembership.user_id,
        phone: maskedPhone
      }
    });

    return {
      membership_id: normalizedMembership.membership_id,
      user_id: normalizedMembership.user_id,
      tenant_id: normalizedMembership.tenant_id,
      status: normalizedMembership.status,
      created_user: createdUser,
      reused_existing_user: reusedExistingUser,
      request_id: resolvedRequestId
    };
  };

  const updateMemberStatus = async ({
    requestId,
    accessToken,
    params = {},
    payload = {},
    authorizationContext = null
  }) => {
    const resolvedRequestId = String(requestId || '').trim() || 'request_id_unset';
    const parsedInput = parseUpdateMemberStatusInput({
      params,
      payload
    });

    let operatorContext;
    try {
      operatorContext = await resolveOperatorContext({
        requestId: resolvedRequestId,
        accessToken,
        authorizationContext,
        permissionCode: TENANT_MEMBER_OPERATE_PERMISSION_CODE
      });
    } catch (error) {
      const mappedError = mapOperatorContextError(error);
      addAuditEvent({
        type: 'tenant.member.status.rejected',
        requestId: resolvedRequestId,
        operatorUserId: 'unknown',
        detail: 'operator authorization context invalid',
        metadata: {
          tenant_id: null,
          membership_id: parsedInput.membershipId,
          next_status: parsedInput.nextStatus,
          error_code: mappedError.errorCode
        }
      });
      throw mappedError;
    }

    const { operatorUserId, operatorSessionId, activeTenantId } = operatorContext;
    assertAuthServiceMethod('updateTenantMemberStatus');

    let updatedMembership = null;
    try {
      updatedMembership = await authService.updateTenantMemberStatus({
        requestId: resolvedRequestId,
        accessToken,
        membershipId: parsedInput.membershipId,
        nextStatus: parsedInput.nextStatus,
        reason: parsedInput.reason,
        authorizationContext,
        authorizedRoute: {
          user_id: operatorUserId,
          session_id: operatorSessionId,
          entry_domain: TENANT_MEMBER_SCOPE,
          active_tenant_id: activeTenantId
        }
      });
    } catch (error) {
      if (error instanceof AuthProblemError) {
        addAuditEvent({
          type: 'tenant.member.status.rejected',
          requestId: resolvedRequestId,
          operatorUserId,
          detail: 'tenant member status update rejected',
          metadata: {
            tenant_id: activeTenantId,
            membership_id: parsedInput.membershipId,
            next_status: parsedInput.nextStatus,
            error_code: error.errorCode
          }
        });
        throw error;
      }
      addAuditEvent({
        type: 'tenant.member.status.rejected',
        requestId: resolvedRequestId,
        operatorUserId,
        detail: 'tenant member status update dependency unavailable',
        metadata: {
          tenant_id: activeTenantId,
          membership_id: parsedInput.membershipId,
          next_status: parsedInput.nextStatus,
          error_code: 'AUTH-503-TENANT-MEMBER-DEPENDENCY-UNAVAILABLE'
        }
      });
      throw tenantMemberErrors.dependencyUnavailable();
    }

    if (!updatedMembership) {
      throw tenantMemberErrors.membershipNotFound();
    }
    const resolvedMembershipId = normalizeStrictRequiredString(
      resolveRawMemberField(updatedMembership, 'membershipId', 'membership_id')
    );
    const resolvedUserId = normalizeStrictRequiredString(
      resolveRawMemberField(updatedMembership, 'userId', 'user_id')
    );
    const resolvedTenantId = normalizeStrictRequiredString(
      resolveRawMemberField(updatedMembership, 'tenantId', 'tenant_id')
    );
    const resolvedPreviousStatus = normalizeMemberStatus(
      normalizeStrictRequiredString(
        resolveRawMemberField(updatedMembership, 'previousStatus', 'previous_status')
      )
    );
    const resolvedCurrentStatus = normalizeMemberStatus(
      normalizeStrictRequiredString(
        resolveRawMemberField(updatedMembership, 'currentStatus', 'current_status')
      )
    );
    const isRejoinTransition =
      resolvedPreviousStatus === 'left'
      && parsedInput.nextStatus === 'active'
      && resolvedCurrentStatus === 'active';
    const hasMembershipIdMismatch = resolvedMembershipId !== parsedInput.membershipId;
    const hasDisallowedMembershipIdMismatch =
      hasMembershipIdMismatch && !isRejoinTransition;
    const hasMissingRejoinMembershipRotation =
      isRejoinTransition
      && resolvedMembershipId === parsedInput.membershipId;
    const hasUnexpectedStatus =
      !VALID_MEMBER_STATUS.has(resolvedPreviousStatus)
      || !VALID_MEMBER_STATUS.has(resolvedCurrentStatus);
    const hasStatusResultMismatch = resolvedCurrentStatus !== parsedInput.nextStatus;
    if (
      !isValidMembershipId(resolvedMembershipId)
      || !resolvedUserId
      || !resolvedTenantId
      || !resolvedPreviousStatus
      || !resolvedCurrentStatus
      || hasDisallowedMembershipIdMismatch
      || hasMissingRejoinMembershipRotation
      || hasUnexpectedStatus
      || hasStatusResultMismatch
      || resolvedTenantId !== activeTenantId
    ) {
      addAuditEvent({
        type: 'tenant.member.status.rejected',
        requestId: resolvedRequestId,
        operatorUserId,
        detail: 'tenant member status update returned inconsistent relationship',
        metadata: {
          tenant_id: activeTenantId,
          membership_id: parsedInput.membershipId,
          next_status: parsedInput.nextStatus,
          error_code: 'AUTH-503-TENANT-MEMBER-DEPENDENCY-UNAVAILABLE'
        }
      });
      throw tenantMemberErrors.dependencyUnavailable();
    }

    addAuditEvent({
      type: 'tenant.member.status.updated',
      requestId: resolvedRequestId,
      operatorUserId,
      detail: 'tenant member status updated',
      metadata: {
        tenant_id: activeTenantId,
        membership_id: resolvedMembershipId,
        target_user_id: resolvedUserId,
        previous_status: resolvedPreviousStatus,
        current_status: resolvedCurrentStatus,
        reason: parsedInput.reason || null
      }
    });

    return {
      membership_id: resolvedMembershipId,
      user_id: resolvedUserId,
      tenant_id: resolvedTenantId,
      previous_status: resolvedPreviousStatus,
      current_status: resolvedCurrentStatus,
      request_id: resolvedRequestId
    };
  };

  const getMemberRoles = async ({
    requestId,
    accessToken,
    params = {},
    authorizationContext = null
  }) => {
    const resolvedRequestId = String(requestId || '').trim() || 'request_id_unset';
    const membershipId = parseMembershipIdFromParams(params);

    let operatorContext;
    try {
      operatorContext = await resolveOperatorContext({
        requestId: resolvedRequestId,
        accessToken,
        authorizationContext,
        permissionCode: TENANT_MEMBER_VIEW_PERMISSION_CODE
      });
    } catch (error) {
      const mappedError = mapOperatorContextError(error);
      addAuditEvent({
        type: 'tenant.member.roles.read.rejected',
        requestId: resolvedRequestId,
        operatorUserId: 'unknown',
        detail: 'operator authorization context invalid',
        metadata: {
          tenant_id: null,
          membership_id: membershipId,
          error_code: mappedError.errorCode
        }
      });
      throw mappedError;
    }

    const { operatorUserId, activeTenantId } = operatorContext;
    assertAuthServiceMethod('listTenantMemberRoleBindings');

    let bindings;
    try {
      bindings = await authService.listTenantMemberRoleBindings({
        tenantId: activeTenantId,
        membershipId
      });
    } catch (error) {
      if (error instanceof AuthProblemError) {
        const mappedError = error.errorCode === 'AUTH-404-TENANT-MEMBERSHIP-NOT-FOUND'
          ? tenantMemberErrors.membershipNotFound()
          : error;
        addAuditEvent({
          type: 'tenant.member.roles.read.rejected',
          requestId: resolvedRequestId,
          operatorUserId,
          detail: 'tenant member role binding read rejected',
          metadata: {
            tenant_id: activeTenantId,
            membership_id: membershipId,
            error_code: mappedError.errorCode
          }
        });
        throw mappedError;
      }
      addAuditEvent({
        type: 'tenant.member.roles.read.rejected',
        requestId: resolvedRequestId,
        operatorUserId,
        detail: 'tenant member role binding read dependency unavailable',
        metadata: {
          tenant_id: activeTenantId,
          membership_id: membershipId,
          error_code: 'AUTH-503-TENANT-MEMBER-DEPENDENCY-UNAVAILABLE'
        }
      });
      throw tenantMemberErrors.dependencyUnavailable();
    }

    const rawResolvedMembershipId =
      Object.prototype.hasOwnProperty.call(bindings || {}, 'membership_id')
        ? bindings?.membership_id
        : bindings?.membershipId;
    const resolvedMembershipId = normalizeStrictRequiredString(rawResolvedMembershipId);
    const normalizedRoleIds = normalizeStrictRoleIdsFromBindings({
      bindings,
      minCount: 0,
      maxCount: MAX_MEMBER_ROLE_BINDINGS
    });
    if (!normalizedRoleIds) {
      addAuditEvent({
        type: 'tenant.member.roles.read.rejected',
        requestId: resolvedRequestId,
        operatorUserId,
        detail: 'tenant member role binding read returned malformed payload',
        metadata: {
          tenant_id: activeTenantId,
          membership_id: membershipId,
          error_code: 'AUTH-503-TENANT-MEMBER-DEPENDENCY-UNAVAILABLE'
        }
      });
      throw tenantMemberErrors.dependencyUnavailable();
    }
    if (resolvedMembershipId !== membershipId) {
      addAuditEvent({
        type: 'tenant.member.roles.read.rejected',
        requestId: resolvedRequestId,
        operatorUserId,
        detail: 'tenant member role binding read returned mismatched membership',
        metadata: {
          tenant_id: activeTenantId,
          membership_id: membershipId,
          error_code: 'AUTH-503-TENANT-MEMBER-DEPENDENCY-UNAVAILABLE'
        }
      });
      throw tenantMemberErrors.dependencyUnavailable();
    }

    addAuditEvent({
      type: 'tenant.member.roles.read.succeeded',
      requestId: resolvedRequestId,
      operatorUserId,
      detail: 'tenant member role bindings listed',
      metadata: {
        tenant_id: activeTenantId,
        membership_id: membershipId,
        role_count: normalizedRoleIds.length
      }
    });

    return {
      membership_id: membershipId,
      role_ids: normalizedRoleIds,
      request_id: resolvedRequestId
    };
  };

  const replaceMemberRoles = async ({
    requestId,
    accessToken,
    params = {},
    payload = {},
    authorizationContext = null
  }) => {
    const resolvedRequestId = String(requestId || '').trim() || 'request_id_unset';
    const parsedInput = parseReplaceMemberRolesInput({
      params,
      payload
    });

    let operatorContext;
    try {
      operatorContext = await resolveOperatorContext({
        requestId: resolvedRequestId,
        accessToken,
        authorizationContext,
        permissionCode: TENANT_MEMBER_OPERATE_PERMISSION_CODE
      });
    } catch (error) {
      const mappedError = mapOperatorContextError(error);
      addAuditEvent({
        type: 'tenant.member.roles.update.rejected',
        requestId: resolvedRequestId,
        operatorUserId: 'unknown',
        detail: 'operator authorization context invalid',
        metadata: {
          tenant_id: null,
          membership_id: parsedInput.membershipId,
          error_code: mappedError.errorCode
        }
      });
      throw mappedError;
    }

    const { operatorUserId, operatorSessionId, activeTenantId } = operatorContext;
    assertAuthServiceMethod('replaceTenantMemberRoleBindings');

    let bindings;
    try {
      bindings = await authService.replaceTenantMemberRoleBindings({
        requestId: resolvedRequestId,
        tenantId: activeTenantId,
        membershipId: parsedInput.membershipId,
        roleIds: parsedInput.roleIds,
        operatorUserId,
        operatorSessionId
      });
    } catch (error) {
      if (error instanceof AuthProblemError) {
        const mappedError = error.errorCode === 'AUTH-404-TENANT-MEMBERSHIP-NOT-FOUND'
          ? tenantMemberErrors.membershipNotFound()
          : error;
        addAuditEvent({
          type: 'tenant.member.roles.update.rejected',
          requestId: resolvedRequestId,
          operatorUserId,
          detail: 'tenant member role binding update rejected',
          metadata: {
            tenant_id: activeTenantId,
            membership_id: parsedInput.membershipId,
            error_code: mappedError.errorCode
          }
        });
        throw mappedError;
      }
      addAuditEvent({
        type: 'tenant.member.roles.update.rejected',
        requestId: resolvedRequestId,
        operatorUserId,
        detail: 'tenant member role binding update dependency unavailable',
        metadata: {
          tenant_id: activeTenantId,
          membership_id: parsedInput.membershipId,
          error_code: 'AUTH-503-TENANT-MEMBER-DEPENDENCY-UNAVAILABLE'
        }
      });
      throw tenantMemberErrors.dependencyUnavailable();
    }

    const rawResolvedMembershipId =
      Object.prototype.hasOwnProperty.call(bindings || {}, 'membership_id')
        ? bindings?.membership_id
        : bindings?.membershipId;
    const resolvedMembershipId = normalizeStrictRequiredString(rawResolvedMembershipId);
    const normalizedRoleIds = normalizeStrictRoleIdsFromBindings({
      bindings,
      minCount: 1,
      maxCount: MAX_MEMBER_ROLE_BINDINGS
    });
    if (!normalizedRoleIds) {
      addAuditEvent({
        type: 'tenant.member.roles.update.rejected',
        requestId: resolvedRequestId,
        operatorUserId,
        detail: 'tenant member role binding update returned malformed payload',
        metadata: {
          tenant_id: activeTenantId,
          membership_id: parsedInput.membershipId,
          error_code: 'AUTH-503-TENANT-MEMBER-DEPENDENCY-UNAVAILABLE'
        }
      });
      throw tenantMemberErrors.dependencyUnavailable();
    }
    if (resolvedMembershipId !== parsedInput.membershipId) {
      addAuditEvent({
        type: 'tenant.member.roles.update.rejected',
        requestId: resolvedRequestId,
        operatorUserId,
        detail: 'tenant member role binding update returned mismatched membership',
        metadata: {
          tenant_id: activeTenantId,
          membership_id: parsedInput.membershipId,
          error_code: 'AUTH-503-TENANT-MEMBER-DEPENDENCY-UNAVAILABLE'
        }
      });
      throw tenantMemberErrors.dependencyUnavailable();
    }
    const expectedRoleIds = [...parsedInput.roleIds].sort((left, right) =>
      left.localeCompare(right)
    );
    const resolvedSortedRoleIds = [...normalizedRoleIds].sort((left, right) =>
      left.localeCompare(right)
    );
    const hasRoleBindingMismatch = (
      expectedRoleIds.length !== resolvedSortedRoleIds.length
      || expectedRoleIds.some(
        (roleId, index) => roleId !== resolvedSortedRoleIds[index]
      )
    );
    if (hasRoleBindingMismatch) {
      addAuditEvent({
        type: 'tenant.member.roles.update.rejected',
        requestId: resolvedRequestId,
        operatorUserId,
        detail: 'tenant member role binding update returned mismatched role set',
        metadata: {
          tenant_id: activeTenantId,
          membership_id: parsedInput.membershipId,
          error_code: 'AUTH-503-TENANT-MEMBER-DEPENDENCY-UNAVAILABLE'
        }
      });
      throw tenantMemberErrors.dependencyUnavailable();
    }

    addAuditEvent({
      type: 'tenant.member.roles.update.succeeded',
      requestId: resolvedRequestId,
      operatorUserId,
      detail: 'tenant member role bindings replaced',
      metadata: {
        tenant_id: activeTenantId,
        membership_id: parsedInput.membershipId,
        role_count: normalizedRoleIds.length
      }
    });

    return {
      membership_id: parsedInput.membershipId,
      role_ids: normalizedRoleIds,
      request_id: resolvedRequestId
    };
  };

  return {
    listMembers,
    createMember,
    updateMemberStatus,
    getMemberRoles,
    replaceMemberRoles,
    _internals: {
      auditTrail,
      authService
    }
  };
};

module.exports = { createTenantMemberService };
