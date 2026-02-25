const { log } = require('../../../../../common/logger');
const { AuthProblemError } = require('../../../../../shared-kernel/auth/auth-problem-error');
const {
  resolveRoutePreauthorizedContext
} = require('../../../../../shared-kernel/auth/route-authz');
const {
  TENANT_USER_VIEW_PERMISSION_CODE,
  TENANT_USER_OPERATE_PERMISSION_CODE,
  TENANT_USER_SCOPE
} = require('../constants');

const CONTROL_CHAR_PATTERN = /[\u0000-\u001F\u007F]/;
const MAX_STATUS_REASON_LENGTH = 256;
const MAX_MEMBERSHIP_ID_LENGTH = 64;
const MAX_MEMBER_ROLE_BINDINGS = 5;
const MAX_ROLE_ID_LENGTH = 64;
const MAX_MEMBER_DISPLAY_NAME_LENGTH = 64;
const MAX_MEMBER_DEPARTMENT_NAME_LENGTH = 128;
const MAX_AUDIT_TRAIL_ENTRIES = 200;
const DEFAULT_MEMBER_LIST_PAGE = 1;
const DEFAULT_MEMBER_LIST_PAGE_SIZE = 50;
const MAX_MEMBER_LIST_PAGE_SIZE = 200;
const MEMBERSHIP_ID_PATTERN = /^[^\s\u0000-\u001F\u007F]{1,64}$/;
const ROLE_ID_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/;
const MAINLAND_PHONE_PATTERN = /^1\d{10}$/;
const CREATE_MEMBER_ALLOWED_FIELDS = new Set(['phone']);
const UPDATE_MEMBER_STATUS_ALLOWED_FIELDS = new Set(['status', 'reason']);
const UPDATE_MEMBER_PROFILE_ALLOWED_FIELDS = new Set([
  'display_name',
  'department_name'
]);
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

const normalizeOptionalMemberDisplayName = (value) => {
  if (value === null || value === undefined) {
    return null;
  }
  if (typeof value !== 'string') {
    return null;
  }
  const normalized = normalizeRequiredString(value);
  if (!normalized) {
    return null;
  }
  return normalized;
};

const normalizeOptionalMemberDepartmentName = (value) => {
  if (value === null || value === undefined) {
    return null;
  }
  if (typeof value !== 'string') {
    return null;
  }
  const normalized = normalizeRequiredString(value);
  if (!normalized) {
    return null;
  }
  return normalized;
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

const isValidOptionalStrictMemberDisplayName = (value) => {
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
  if (normalized.length > MAX_MEMBER_DISPLAY_NAME_LENGTH) {
    return false;
  }
  return !CONTROL_CHAR_PATTERN.test(normalized);
};

const isValidOptionalStrictMemberDepartmentName = (value) => {
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
  if (normalized.length > MAX_MEMBER_DEPARTMENT_NAME_LENGTH) {
    return false;
  }
  return !CONTROL_CHAR_PATTERN.test(normalized);
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

const tenantUserProblem = ({
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

const tenantUserErrors = {
  invalidPayload: (detail = '请求参数不完整或格式错误') =>
    tenantUserProblem({
      status: 400,
      title: 'Bad Request',
      detail,
      errorCode: 'AUTH-400-INVALID-PAYLOAD'
    }),

  forbidden: () =>
    tenantUserProblem({
      status: 403,
      title: 'Forbidden',
      detail: '当前操作无权限',
      errorCode: 'AUTH-403-FORBIDDEN'
    }),

  noDomainAccess: () =>
    tenantUserProblem({
      status: 403,
      title: 'Forbidden',
      detail: '当前入口无可用访问域权限',
      errorCode: 'AUTH-403-NO-DOMAIN'
    }),

  membershipNotFound: () =>
    tenantUserProblem({
      status: 404,
      title: 'Not Found',
      detail: '目标成员关系不存在',
      errorCode: 'AUTH-404-TENANT-MEMBERSHIP-NOT-FOUND',
      extensions: {
        retryable: false
      }
    }),

  dependencyUnavailable: () =>
    tenantUserProblem({
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
  error instanceof AuthProblemError ? error : tenantUserErrors.dependencyUnavailable();

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
    expectedScope: TENANT_USER_SCOPE,
    expectedEntryDomain: TENANT_USER_SCOPE
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
    throw tenantUserErrors.invalidPayload();
  }
  const unknownPayloadKeys = Object.keys(payload).filter(
    (key) => !CREATE_MEMBER_ALLOWED_FIELDS.has(key)
  );
  if (unknownPayloadKeys.length > 0) {
    throw tenantUserErrors.invalidPayload();
  }
  if (!Object.prototype.hasOwnProperty.call(payload, 'phone')) {
    throw tenantUserErrors.invalidPayload('phone 为必填字段');
  }
  if (typeof payload.phone !== 'string') {
    throw tenantUserErrors.invalidPayload('phone 格式错误');
  }
  const phone = normalizeRequiredString(payload.phone);
  if (!isValidMainlandPhone(phone)) {
    throw tenantUserErrors.invalidPayload('phone 格式错误');
  }
  return {
    phone
  };
};

const parseMembershipIdFromParams = (params = {}) => {
  const rawMembershipId = params.membership_id;
  if (typeof rawMembershipId !== 'string') {
    throw tenantUserErrors.invalidPayload('membership_id 不能为空');
  }
  const trimmedMembershipId = normalizeRequiredString(rawMembershipId);
  if (!trimmedMembershipId) {
    throw tenantUserErrors.invalidPayload('membership_id 不能为空');
  }
  if (rawMembershipId !== trimmedMembershipId) {
    throw tenantUserErrors.invalidPayload('membership_id 不能包含前后空白字符');
  }
  const membershipId = trimmedMembershipId.toLowerCase();
  if (membershipId.length > MAX_MEMBERSHIP_ID_LENGTH) {
    throw tenantUserErrors.invalidPayload(
      `membership_id 长度不能超过 ${MAX_MEMBERSHIP_ID_LENGTH}`
    );
  }
  if (CONTROL_CHAR_PATTERN.test(membershipId)) {
    throw tenantUserErrors.invalidPayload('membership_id 不能包含控制字符');
  }
  if (!isValidMembershipId(membershipId)) {
    throw tenantUserErrors.invalidPayload('membership_id 格式错误');
  }
  return membershipId;
};

const parseUpdateMemberStatusInput = ({ params = {}, payload = {} } = {}) => {
  const membershipId = parseMembershipIdFromParams(params);
  if (!isPlainObject(payload)) {
    throw tenantUserErrors.invalidPayload();
  }
  const unknownPayloadKeys = Object.keys(payload).filter(
    (key) => !UPDATE_MEMBER_STATUS_ALLOWED_FIELDS.has(key)
  );
  if (unknownPayloadKeys.length > 0) {
    throw tenantUserErrors.invalidPayload();
  }
  if (!Object.prototype.hasOwnProperty.call(payload, 'status')) {
    throw tenantUserErrors.invalidPayload('status 为必填字段');
  }
  if (typeof payload.status !== 'string') {
    throw tenantUserErrors.invalidPayload('status 必须为字符串');
  }
  const nextStatus = normalizeMemberStatus(payload.status);
  if (!VALID_MEMBER_STATUS.has(nextStatus)) {
    throw tenantUserErrors.invalidPayload('status 必须为 active、disabled 或 left');
  }

  let reason = null;
  if (Object.prototype.hasOwnProperty.call(payload, 'reason')) {
    if (typeof payload.reason !== 'string') {
      throw tenantUserErrors.invalidPayload('reason 必须为字符串');
    }
    const normalizedReason = normalizeRequiredString(payload.reason);
    if (!normalizedReason) {
      throw tenantUserErrors.invalidPayload('reason 不能为空字符串');
    }
    if (CONTROL_CHAR_PATTERN.test(normalizedReason)) {
      throw tenantUserErrors.invalidPayload('reason 不能包含控制字符');
    }
    if (normalizedReason.length > MAX_STATUS_REASON_LENGTH) {
      throw tenantUserErrors.invalidPayload(
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

const parseUpdateMemberProfileInput = ({ params = {}, payload = {} } = {}) => {
  const membershipId = parseMembershipIdFromParams(params);
  if (!isPlainObject(payload)) {
    throw tenantUserErrors.invalidPayload();
  }
  const unknownPayloadKeys = Object.keys(payload).filter(
    (key) => !UPDATE_MEMBER_PROFILE_ALLOWED_FIELDS.has(key)
  );
  if (unknownPayloadKeys.length > 0) {
    throw tenantUserErrors.invalidPayload();
  }
  if (!Object.prototype.hasOwnProperty.call(payload, 'display_name')) {
    throw tenantUserErrors.invalidPayload('display_name 为必填字段');
  }
  if (typeof payload.display_name !== 'string') {
    throw tenantUserErrors.invalidPayload('display_name 必须为字符串');
  }
  const displayName = normalizeRequiredString(payload.display_name);
  if (!displayName) {
    throw tenantUserErrors.invalidPayload('display_name 不能为空');
  }
  if (CONTROL_CHAR_PATTERN.test(displayName)) {
    throw tenantUserErrors.invalidPayload('display_name 不能包含控制字符');
  }
  if (displayName.length > MAX_MEMBER_DISPLAY_NAME_LENGTH) {
    throw tenantUserErrors.invalidPayload(
      `display_name 长度不能超过 ${MAX_MEMBER_DISPLAY_NAME_LENGTH}`
    );
  }

  const departmentNameProvided = Object.prototype.hasOwnProperty.call(
    payload,
    'department_name'
  );
  let departmentName = null;
  if (departmentNameProvided) {
    if (payload.department_name === null) {
      departmentName = null;
    } else if (typeof payload.department_name !== 'string') {
      throw tenantUserErrors.invalidPayload('department_name 必须为字符串或 null');
    } else {
      const normalizedDepartmentName = normalizeRequiredString(
        payload.department_name
      );
      if (!normalizedDepartmentName) {
        throw tenantUserErrors.invalidPayload('department_name 不能为纯空白');
      }
      if (CONTROL_CHAR_PATTERN.test(normalizedDepartmentName)) {
        throw tenantUserErrors.invalidPayload('department_name 不能包含控制字符');
      }
      if (
        normalizedDepartmentName.length
        > MAX_MEMBER_DEPARTMENT_NAME_LENGTH
      ) {
        throw tenantUserErrors.invalidPayload(
          `department_name 长度不能超过 ${MAX_MEMBER_DEPARTMENT_NAME_LENGTH}`
        );
      }
      departmentName = normalizedDepartmentName;
    }
  }

  return {
    membershipId,
    displayName,
    departmentNameProvided,
    departmentName
  };
};

const parseReplaceMemberRolesInput = ({ params = {}, payload = {} } = {}) => {
  const membershipId = parseMembershipIdFromParams(params);
  if (!isPlainObject(payload)) {
    throw tenantUserErrors.invalidPayload();
  }
  const unknownPayloadKeys = Object.keys(payload).filter(
    (key) => !REPLACE_MEMBER_ROLES_ALLOWED_FIELDS.has(key)
  );
  if (unknownPayloadKeys.length > 0) {
    throw tenantUserErrors.invalidPayload('请求参数不完整或格式错误');
  }
  if (!Object.prototype.hasOwnProperty.call(payload, 'role_ids')) {
    throw tenantUserErrors.invalidPayload('role_ids 为必填字段');
  }
  if (!Array.isArray(payload.role_ids)) {
    throw tenantUserErrors.invalidPayload('role_ids 必须为数组');
  }
  if (
    payload.role_ids.length === 0
    || payload.role_ids.length > MAX_MEMBER_ROLE_BINDINGS
  ) {
    throw tenantUserErrors.invalidPayload(
      `role_ids 数量必须在 1 到 ${MAX_MEMBER_ROLE_BINDINGS} 之间`
    );
  }
  const dedupedRoleIds = new Map();
  for (const roleId of payload.role_ids) {
    if (typeof roleId !== 'string') {
      throw tenantUserErrors.invalidPayload('role_ids 仅允许字符串');
    }
    const normalizedRoleId = roleId.trim().toLowerCase();
    if (!normalizedRoleId) {
      throw tenantUserErrors.invalidPayload('role_ids 不能为空字符串');
    }
    if (roleId !== roleId.trim()) {
      throw tenantUserErrors.invalidPayload('role_ids 不能包含前后空白字符');
    }
    if (normalizedRoleId.length > MAX_ROLE_ID_LENGTH) {
      throw tenantUserErrors.invalidPayload(
        `role_ids 中元素长度不能超过 ${MAX_ROLE_ID_LENGTH}`
      );
    }
    if (CONTROL_CHAR_PATTERN.test(normalizedRoleId)) {
      throw tenantUserErrors.invalidPayload('role_ids 不能包含控制字符');
    }
    if (!ROLE_ID_PATTERN.test(normalizedRoleId)) {
      throw tenantUserErrors.invalidPayload('role_ids 格式错误');
    }
    if (dedupedRoleIds.has(normalizedRoleId)) {
      throw tenantUserErrors.invalidPayload('role_ids 不允许重复');
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
    throw tenantUserErrors.invalidPayload(`${field} 必须为正整数`);
  }
  const normalized = String(rawValue).trim();
  if (!/^\d+$/.test(normalized)) {
    throw tenantUserErrors.invalidPayload(`${field} 必须为正整数`);
  }
  const parsed = Number.parseInt(normalized, 10);
  if (!Number.isFinite(parsed) || parsed < min || parsed > max) {
    throw tenantUserErrors.invalidPayload(
      `${field} 必须在 ${min} 到 ${max} 之间`
    );
  }
  return parsed;
};

const parseListMembersQuery = (query = {}) => {
  if (!isPlainObject(query)) {
    throw tenantUserErrors.invalidPayload('查询参数格式错误');
  }
  const unknownQueryKeys = Object.keys(query).filter(
    (key) => !LIST_MEMBER_ALLOWED_FIELDS.has(key)
  );
  if (unknownQueryKeys.length > 0) {
    throw tenantUserErrors.invalidPayload('查询参数不支持');
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
  const rawDisplayName = resolveRawMemberField(
    source,
    'displayName',
    'display_name'
  ) ?? null;
  const rawDepartmentName = resolveRawMemberField(
    source,
    'departmentName',
    'department_name'
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
    display_name: normalizeOptionalMemberDisplayName(rawDisplayName),
    department_name: normalizeOptionalMemberDepartmentName(rawDepartmentName),
    joined_at: normalizeOptionalDateTime(rawJoinedAt),
    left_at: normalizeOptionalDateTime(rawLeftAt)
  };
};

const isValidNormalizedMemberRecordFromRaw = ({
  member = {},
  rawMember = {},
  activeTenantId = '',
  expectedStatus = null,
  expectedMembershipId = '',
  expectedUserId = '',
  expectedPhone = '',
  expectedDisplayName = null,
  expectedDepartmentName = undefined
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
  const rawDisplayName = resolveRawMemberField(
    rawMember,
    'displayName',
    'display_name'
  ) ?? null;
  const rawDepartmentName = resolveRawMemberField(
    rawMember,
    'departmentName',
    'department_name'
  ) ?? null;
  const normalizedExpectedStatus = expectedStatus === null
    ? null
    : normalizeMemberStatus(expectedStatus);
  const normalizedExpectedMembershipId = normalizeRequiredString(
    expectedMembershipId
  ).toLowerCase();
  const normalizedExpectedUserId = normalizeRequiredString(expectedUserId);
  const normalizedExpectedPhone = normalizeRequiredString(expectedPhone);
  const normalizedExpectedDisplayName = (
    expectedDisplayName === null || expectedDisplayName === undefined
  )
    ? null
    : normalizeRequiredString(expectedDisplayName);
  const hasExpectedDepartmentName = expectedDepartmentName !== undefined;
  const normalizedExpectedDepartmentName = hasExpectedDepartmentName
    ? normalizeOptionalMemberDepartmentName(expectedDepartmentName)
    : undefined;
  const normalizedRawDisplayName = normalizeOptionalMemberDisplayName(
    rawDisplayName
  );
  const normalizedRawDepartmentName = normalizeOptionalMemberDepartmentName(
    rawDepartmentName
  );

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
      !normalizedExpectedMembershipId
      || String(member?.membership_id || '') === normalizedExpectedMembershipId
    )
    && (
      !normalizedExpectedUserId
      || String(member?.user_id || '') === normalizedExpectedUserId
    )
    && (
      !normalizedExpectedPhone
      || String(member?.phone || '') === normalizedExpectedPhone
    )
    && (
      normalizedExpectedDisplayName === null
      || String(member?.display_name || '') === normalizedExpectedDisplayName
    )
    && (
      !hasExpectedDepartmentName
      || String(member?.department_name ?? '')
      === String(normalizedExpectedDepartmentName ?? '')
    )
    && String(member?.display_name ?? '')
    === String(normalizedRawDisplayName ?? '')
    && String(member?.department_name ?? '')
    === String(normalizedRawDepartmentName ?? '')
    && isValidOptionalStrictMemberDisplayName(rawDisplayName)
    && isValidOptionalStrictMemberDepartmentName(rawDepartmentName)
    && isValidOptionalStrictTenantName(rawTenantName)
    && isValidOptionalStrictDateTime(rawJoinedAt)
    && isValidOptionalStrictDateTime(rawLeftAt)
  );
};

const createTenantUserService = ({ authService } = {}) => {
  const auditTrail = [];

  const addAuditEvent = ({
    type,
    requestId,
    operatorUserId = 'unknown',
    detail,
    metadata = {}
  }) => {
    const event = {
      type: String(type || '').trim() || 'tenant.user.unknown',
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
      throw tenantUserErrors.dependencyUnavailable();
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
      scope: TENANT_USER_SCOPE,
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
      throw tenantUserErrors.noDomainAccess();
    }
    if (
      !isResolvedOperatorIdentifier(operatorUserId)
      || !isResolvedOperatorIdentifier(operatorSessionId)
    ) {
      throw tenantUserErrors.forbidden();
    }

    return {
      operatorUserId,
      operatorSessionId,
      activeTenantId
    };
  };

  const listUsers = async ({
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
        permissionCode: TENANT_USER_VIEW_PERMISSION_CODE
      });
    } catch (error) {
      const mappedError = mapOperatorContextError(error);
      addAuditEvent({
        type: 'tenant.user.list.rejected',
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
    assertAuthServiceMethod('listTenantUsers');
    let members = [];
    try {
      members = await authService.listTenantUsers({
        requestId: resolvedRequestId,
        tenantId: activeTenantId,
        page: listQuery.page,
        pageSize: listQuery.pageSize,
        authorizationContext
      });
    } catch (error) {
      if (error instanceof AuthProblemError) {
        addAuditEvent({
          type: 'tenant.user.list.rejected',
          requestId: resolvedRequestId,
          operatorUserId,
          detail: 'tenant user listing rejected',
          metadata: {
            tenant_id: activeTenantId,
            error_code: error.errorCode
          }
        });
        throw error;
      }
      addAuditEvent({
        type: 'tenant.user.list.rejected',
        requestId: resolvedRequestId,
        operatorUserId,
        detail: 'tenant user listing dependency unavailable',
        metadata: {
          tenant_id: activeTenantId,
          error_code: 'AUTH-503-TENANT-MEMBER-DEPENDENCY-UNAVAILABLE'
        }
      });
      throw tenantUserErrors.dependencyUnavailable();
    }

    if (!Array.isArray(members)) {
      addAuditEvent({
        type: 'tenant.user.list.rejected',
        requestId: resolvedRequestId,
        operatorUserId,
        detail: 'tenant user listing returned malformed payload',
        metadata: {
          tenant_id: activeTenantId,
          error_code: 'AUTH-503-TENANT-MEMBER-DEPENDENCY-UNAVAILABLE'
        }
      });
      throw tenantUserErrors.dependencyUnavailable();
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
        type: 'tenant.user.list.rejected',
        requestId: resolvedRequestId,
        operatorUserId,
        detail: 'tenant user listing returned malformed relationship record',
        metadata: {
          tenant_id: activeTenantId,
          error_code: 'AUTH-503-TENANT-MEMBER-DEPENDENCY-UNAVAILABLE'
        }
      });
      throw tenantUserErrors.dependencyUnavailable();
    }
    const hasCrossTenantUser = normalizedMembers.some(
      (member) => member.tenant_id !== activeTenantId
    );
    if (hasCrossTenantUser) {
      addAuditEvent({
        type: 'tenant.user.list.rejected',
        requestId: resolvedRequestId,
        operatorUserId,
        detail: 'tenant user listing returned inconsistent tenant relationship',
        metadata: {
          tenant_id: activeTenantId,
          error_code: 'AUTH-503-TENANT-MEMBER-DEPENDENCY-UNAVAILABLE'
        }
      });
      throw tenantUserErrors.dependencyUnavailable();
    }

    addAuditEvent({
      type: 'tenant.user.listed',
      requestId: resolvedRequestId,
      operatorUserId,
      detail: 'tenant users listed',
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

  const createUser = async ({
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
        permissionCode: TENANT_USER_OPERATE_PERMISSION_CODE
      });
    } catch (error) {
      const mappedError = mapOperatorContextError(error);
      addAuditEvent({
        type: 'tenant.user.create.rejected',
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
    assertAuthServiceMethod('findTenantUsershipByUserAndTenantId');

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
          entry_domain: TENANT_USER_SCOPE,
          active_tenant_id: activeTenantId
        }
      });
    } catch (error) {
      if (error instanceof AuthProblemError) {
        addAuditEvent({
          type: 'tenant.user.create.rejected',
          requestId: resolvedRequestId,
          operatorUserId,
          detail: 'tenant user provisioning rejected',
          metadata: {
            tenant_id: activeTenantId,
            phone: maskedPhone,
            error_code: error.errorCode
          }
        });
        throw error;
      }
      addAuditEvent({
        type: 'tenant.user.create.rejected',
        requestId: resolvedRequestId,
        operatorUserId,
        detail: 'tenant user provisioning dependency unavailable',
        metadata: {
          tenant_id: activeTenantId,
          phone: maskedPhone,
          error_code: 'AUTH-503-TENANT-MEMBER-DEPENDENCY-UNAVAILABLE'
        }
      });
      throw tenantUserErrors.dependencyUnavailable();
    }

    const targetUserId = normalizeRequiredString(provisionedUser?.user_id);
    if (!targetUserId) {
      addAuditEvent({
        type: 'tenant.user.create.rejected',
        requestId: resolvedRequestId,
        operatorUserId,
        detail: 'tenant user provisioning returned incomplete user identity',
        metadata: {
          tenant_id: activeTenantId,
          phone: maskedPhone,
          error_code: 'AUTH-503-TENANT-MEMBER-DEPENDENCY-UNAVAILABLE'
        }
      });
      throw tenantUserErrors.dependencyUnavailable();
    }
    const hasCreatedUserFlag = typeof provisionedUser?.created_user === 'boolean';
    const hasReusedExistingUserFlag = typeof provisionedUser?.reused_existing_user === 'boolean';
    if (!hasCreatedUserFlag || !hasReusedExistingUserFlag) {
      addAuditEvent({
        type: 'tenant.user.create.rejected',
        requestId: resolvedRequestId,
        operatorUserId,
        detail: 'tenant user provisioning returned incomplete identity reuse flags',
        metadata: {
          tenant_id: activeTenantId,
          phone: maskedPhone,
          target_user_id: targetUserId,
          error_code: 'AUTH-503-TENANT-MEMBER-DEPENDENCY-UNAVAILABLE'
        }
      });
      throw tenantUserErrors.dependencyUnavailable();
    }
    const createdUser = provisionedUser.created_user;
    const reusedExistingUser = provisionedUser.reused_existing_user;
    if (createdUser === reusedExistingUser) {
      addAuditEvent({
        type: 'tenant.user.create.rejected',
        requestId: resolvedRequestId,
        operatorUserId,
        detail: 'tenant user provisioning returned inconsistent identity reuse flags',
        metadata: {
          tenant_id: activeTenantId,
          phone: maskedPhone,
          target_user_id: targetUserId,
          error_code: 'AUTH-503-TENANT-MEMBER-DEPENDENCY-UNAVAILABLE'
        }
      });
      throw tenantUserErrors.dependencyUnavailable();
    }

    let membership = null;
    try {
      membership = await authService.findTenantUsershipByUserAndTenantId({
        userId: targetUserId,
        tenantId: activeTenantId
      });
    } catch (error) {
      if (error instanceof AuthProblemError) {
        addAuditEvent({
          type: 'tenant.user.create.rejected',
          requestId: resolvedRequestId,
          operatorUserId,
          detail: 'tenant user lookup rejected',
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
        type: 'tenant.user.create.rejected',
        requestId: resolvedRequestId,
        operatorUserId,
        detail: 'tenant user lookup dependency unavailable',
        metadata: {
          tenant_id: activeTenantId,
          phone: maskedPhone,
          target_user_id: targetUserId,
          error_code: 'AUTH-503-TENANT-MEMBER-DEPENDENCY-UNAVAILABLE'
        }
      });
      throw tenantUserErrors.dependencyUnavailable();
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
        type: 'tenant.user.create.rejected',
        requestId: resolvedRequestId,
        operatorUserId,
        detail: 'tenant user lookup returned inconsistent relationship',
        metadata: {
          tenant_id: activeTenantId,
          phone: maskedPhone,
          target_user_id: targetUserId,
          error_code: 'AUTH-503-TENANT-MEMBER-DEPENDENCY-UNAVAILABLE'
        }
      });
      throw tenantUserErrors.dependencyUnavailable();
    }

    addAuditEvent({
      type:
        createdUser
          ? 'tenant.user.created'
          : 'tenant.user.identity_reused',
      requestId: resolvedRequestId,
      operatorUserId,
      detail:
        createdUser
          ? 'tenant user created with new user identity'
          : 'tenant user created by reusing existing user identity',
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

  const updateUserStatus = async ({
    requestId,
    accessToken,
    params = {},
    payload = {},
    traceparent = null,
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
        permissionCode: TENANT_USER_OPERATE_PERMISSION_CODE
      });
    } catch (error) {
      const mappedError = mapOperatorContextError(error);
      addAuditEvent({
        type: 'tenant.user.status.rejected',
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
    assertAuthServiceMethod('updateTenantUserStatus');

    let updatedMembership = null;
    try {
      updatedMembership = await authService.updateTenantUserStatus({
        requestId: resolvedRequestId,
        traceparent,
        accessToken,
        membershipId: parsedInput.membershipId,
        nextStatus: parsedInput.nextStatus,
        reason: parsedInput.reason,
        authorizationContext,
        authorizedRoute: {
          user_id: operatorUserId,
          session_id: operatorSessionId,
          entry_domain: TENANT_USER_SCOPE,
          active_tenant_id: activeTenantId
        }
      });
    } catch (error) {
      if (error instanceof AuthProblemError) {
        addAuditEvent({
          type: 'tenant.user.status.rejected',
          requestId: resolvedRequestId,
          operatorUserId,
          detail: 'tenant user status update rejected',
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
        type: 'tenant.user.status.rejected',
        requestId: resolvedRequestId,
        operatorUserId,
        detail: 'tenant user status update dependency unavailable',
        metadata: {
          tenant_id: activeTenantId,
          membership_id: parsedInput.membershipId,
          next_status: parsedInput.nextStatus,
          error_code: 'AUTH-503-TENANT-MEMBER-DEPENDENCY-UNAVAILABLE'
        }
      });
      throw tenantUserErrors.dependencyUnavailable();
    }

    if (!updatedMembership) {
      throw tenantUserErrors.membershipNotFound();
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
        type: 'tenant.user.status.rejected',
        requestId: resolvedRequestId,
        operatorUserId,
        detail: 'tenant user status update returned inconsistent relationship',
        metadata: {
          tenant_id: activeTenantId,
          membership_id: parsedInput.membershipId,
          next_status: parsedInput.nextStatus,
          error_code: 'AUTH-503-TENANT-MEMBER-DEPENDENCY-UNAVAILABLE'
        }
      });
      throw tenantUserErrors.dependencyUnavailable();
    }

    addAuditEvent({
      type: 'tenant.user.status.updated',
      requestId: resolvedRequestId,
      operatorUserId,
      detail: 'tenant user status updated',
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

  const getUserDetail = async ({
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
        permissionCode: TENANT_USER_VIEW_PERMISSION_CODE
      });
    } catch (error) {
      const mappedError = mapOperatorContextError(error);
      addAuditEvent({
        type: 'tenant.user.profile.read.rejected',
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
    assertAuthServiceMethod('findTenantUsershipByMembershipIdAndTenantId');

    let membership;
    try {
      membership = await authService.findTenantUsershipByMembershipIdAndTenantId({
        membershipId,
        tenantId: activeTenantId
      });
    } catch (error) {
      if (error instanceof AuthProblemError) {
        const mappedError = error.errorCode === 'AUTH-404-TENANT-MEMBERSHIP-NOT-FOUND'
          ? tenantUserErrors.membershipNotFound()
          : error;
        addAuditEvent({
          type: 'tenant.user.profile.read.rejected',
          requestId: resolvedRequestId,
          operatorUserId,
          detail: 'tenant user profile detail read rejected',
          metadata: {
            tenant_id: activeTenantId,
            membership_id: membershipId,
            error_code: mappedError.errorCode
          }
        });
        throw mappedError;
      }
      addAuditEvent({
        type: 'tenant.user.profile.read.rejected',
        requestId: resolvedRequestId,
        operatorUserId,
        detail: 'tenant user profile detail read dependency unavailable',
        metadata: {
          tenant_id: activeTenantId,
          membership_id: membershipId,
          error_code: 'AUTH-503-TENANT-MEMBER-DEPENDENCY-UNAVAILABLE'
        }
      });
      throw tenantUserErrors.dependencyUnavailable();
    }

    if (!membership) {
      addAuditEvent({
        type: 'tenant.user.profile.read.rejected',
        requestId: resolvedRequestId,
        operatorUserId,
        detail: 'tenant user profile detail not found',
        metadata: {
          tenant_id: activeTenantId,
          membership_id: membershipId,
          error_code: 'AUTH-404-TENANT-MEMBERSHIP-NOT-FOUND'
        }
      });
      throw tenantUserErrors.membershipNotFound();
    }

    const normalizedMembership = normalizeMemberRecord(membership || {});
    if (
      !isValidNormalizedMemberRecordFromRaw({
        member: normalizedMembership,
        rawMember: membership || {},
        activeTenantId,
        expectedMembershipId: membershipId
      })
    ) {
      addAuditEvent({
        type: 'tenant.user.profile.read.rejected',
        requestId: resolvedRequestId,
        operatorUserId,
        detail: 'tenant user profile detail returned malformed payload',
        metadata: {
          tenant_id: activeTenantId,
          membership_id: membershipId,
          error_code: 'AUTH-503-TENANT-MEMBER-DEPENDENCY-UNAVAILABLE'
        }
      });
      throw tenantUserErrors.dependencyUnavailable();
    }

    addAuditEvent({
      type: 'tenant.user.profile.read.succeeded',
      requestId: resolvedRequestId,
      operatorUserId,
      detail: 'tenant user profile detail fetched',
      metadata: {
        tenant_id: activeTenantId,
        membership_id: membershipId,
        has_display_name: normalizedMembership.display_name !== null,
        has_department_name: normalizedMembership.department_name !== null
      }
    });

    return {
      ...normalizedMembership,
      request_id: resolvedRequestId
    };
  };

  const updateUserProfile = async ({
    requestId,
    accessToken,
    params = {},
    payload = {},
    authorizationContext = null
  }) => {
    const resolvedRequestId = String(requestId || '').trim() || 'request_id_unset';
    const parsedInput = parseUpdateMemberProfileInput({
      params,
      payload
    });

    let operatorContext;
    try {
      operatorContext = await resolveOperatorContext({
        requestId: resolvedRequestId,
        accessToken,
        authorizationContext,
        permissionCode: TENANT_USER_OPERATE_PERMISSION_CODE
      });
    } catch (error) {
      const mappedError = mapOperatorContextError(error);
      addAuditEvent({
        type: 'tenant.user.profile.update.rejected',
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
    assertAuthServiceMethod('updateTenantUserProfile');

    let updatedMembership = null;
    try {
      updatedMembership = await authService.updateTenantUserProfile({
        requestId: resolvedRequestId,
        accessToken,
        membershipId: parsedInput.membershipId,
        tenantId: activeTenantId,
        displayName: parsedInput.displayName,
        departmentNameProvided: parsedInput.departmentNameProvided,
        ...(parsedInput.departmentNameProvided
          ? { departmentName: parsedInput.departmentName }
          : {}),
        authorizationContext,
        authorizedRoute: {
          user_id: operatorUserId,
          session_id: operatorSessionId,
          entry_domain: TENANT_USER_SCOPE,
          active_tenant_id: activeTenantId
        }
      });
    } catch (error) {
      if (error instanceof AuthProblemError) {
        const mappedError = error.errorCode === 'AUTH-404-TENANT-MEMBERSHIP-NOT-FOUND'
          ? tenantUserErrors.membershipNotFound()
          : error;
        addAuditEvent({
          type: 'tenant.user.profile.update.rejected',
          requestId: resolvedRequestId,
          operatorUserId,
          detail: 'tenant user profile update rejected',
          metadata: {
            tenant_id: activeTenantId,
            membership_id: parsedInput.membershipId,
            error_code: mappedError.errorCode
          }
        });
        throw mappedError;
      }
      addAuditEvent({
        type: 'tenant.user.profile.update.rejected',
        requestId: resolvedRequestId,
        operatorUserId,
        detail: 'tenant user profile update dependency unavailable',
        metadata: {
          tenant_id: activeTenantId,
          membership_id: parsedInput.membershipId,
          error_code: 'AUTH-503-TENANT-MEMBER-DEPENDENCY-UNAVAILABLE'
        }
      });
      throw tenantUserErrors.dependencyUnavailable();
    }

    if (!updatedMembership) {
      addAuditEvent({
        type: 'tenant.user.profile.update.rejected',
        requestId: resolvedRequestId,
        operatorUserId,
        detail: 'tenant user profile update target membership not found',
        metadata: {
          tenant_id: activeTenantId,
          membership_id: parsedInput.membershipId,
          error_code: 'AUTH-404-TENANT-MEMBERSHIP-NOT-FOUND'
        }
      });
      throw tenantUserErrors.membershipNotFound();
    }

    const normalizedMembership = normalizeMemberRecord(updatedMembership || {});
    const expectedDepartmentName = parsedInput.departmentNameProvided
      ? parsedInput.departmentName
      : undefined;
    if (
      !isValidNormalizedMemberRecordFromRaw({
        member: normalizedMembership,
        rawMember: updatedMembership || {},
        activeTenantId,
        expectedMembershipId: parsedInput.membershipId,
        expectedDisplayName: parsedInput.displayName,
        expectedDepartmentName
      })
    ) {
      addAuditEvent({
        type: 'tenant.user.profile.update.rejected',
        requestId: resolvedRequestId,
        operatorUserId,
        detail: 'tenant user profile update returned malformed payload',
        metadata: {
          tenant_id: activeTenantId,
          membership_id: parsedInput.membershipId,
          error_code: 'AUTH-503-TENANT-MEMBER-DEPENDENCY-UNAVAILABLE'
        }
      });
      throw tenantUserErrors.dependencyUnavailable();
    }

    addAuditEvent({
      type: 'tenant.user.profile.updated',
      requestId: resolvedRequestId,
      operatorUserId,
      detail: 'tenant user profile updated',
      metadata: {
        tenant_id: activeTenantId,
        membership_id: parsedInput.membershipId,
        changed_fields: parsedInput.departmentNameProvided
          ? ['display_name', 'department_name']
          : ['display_name']
      }
    });

    return {
      ...normalizedMembership,
      request_id: resolvedRequestId
    };
  };

  const getUserRoles = async ({
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
        permissionCode: TENANT_USER_VIEW_PERMISSION_CODE
      });
    } catch (error) {
      const mappedError = mapOperatorContextError(error);
      addAuditEvent({
        type: 'tenant.user.roles.read.rejected',
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
    assertAuthServiceMethod('listTenantUserRoleBindings');

    let bindings;
    try {
      bindings = await authService.listTenantUserRoleBindings({
        tenantId: activeTenantId,
        membershipId
      });
    } catch (error) {
      if (error instanceof AuthProblemError) {
        const mappedError = error.errorCode === 'AUTH-404-TENANT-MEMBERSHIP-NOT-FOUND'
          ? tenantUserErrors.membershipNotFound()
          : error;
        addAuditEvent({
          type: 'tenant.user.roles.read.rejected',
          requestId: resolvedRequestId,
          operatorUserId,
          detail: 'tenant user role binding read rejected',
          metadata: {
            tenant_id: activeTenantId,
            membership_id: membershipId,
            error_code: mappedError.errorCode
          }
        });
        throw mappedError;
      }
      addAuditEvent({
        type: 'tenant.user.roles.read.rejected',
        requestId: resolvedRequestId,
        operatorUserId,
        detail: 'tenant user role binding read dependency unavailable',
        metadata: {
          tenant_id: activeTenantId,
          membership_id: membershipId,
          error_code: 'AUTH-503-TENANT-MEMBER-DEPENDENCY-UNAVAILABLE'
        }
      });
      throw tenantUserErrors.dependencyUnavailable();
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
        type: 'tenant.user.roles.read.rejected',
        requestId: resolvedRequestId,
        operatorUserId,
        detail: 'tenant user role binding read returned malformed payload',
        metadata: {
          tenant_id: activeTenantId,
          membership_id: membershipId,
          error_code: 'AUTH-503-TENANT-MEMBER-DEPENDENCY-UNAVAILABLE'
        }
      });
      throw tenantUserErrors.dependencyUnavailable();
    }
    if (resolvedMembershipId !== membershipId) {
      addAuditEvent({
        type: 'tenant.user.roles.read.rejected',
        requestId: resolvedRequestId,
        operatorUserId,
        detail: 'tenant user role binding read returned mismatched membership',
        metadata: {
          tenant_id: activeTenantId,
          membership_id: membershipId,
          error_code: 'AUTH-503-TENANT-MEMBER-DEPENDENCY-UNAVAILABLE'
        }
      });
      throw tenantUserErrors.dependencyUnavailable();
    }

    addAuditEvent({
      type: 'tenant.user.roles.read.succeeded',
      requestId: resolvedRequestId,
      operatorUserId,
      detail: 'tenant user role bindings listed',
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

  const replaceUserRoles = async ({
    requestId,
    accessToken,
    params = {},
    payload = {},
    traceparent = null,
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
        permissionCode: TENANT_USER_OPERATE_PERMISSION_CODE
      });
    } catch (error) {
      const mappedError = mapOperatorContextError(error);
      addAuditEvent({
        type: 'tenant.user.roles.update.rejected',
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
    assertAuthServiceMethod('replaceTenantUserRoleBindings');

    let bindings;
    try {
      bindings = await authService.replaceTenantUserRoleBindings({
        requestId: resolvedRequestId,
        traceparent,
        tenantId: activeTenantId,
        membershipId: parsedInput.membershipId,
        roleIds: parsedInput.roleIds,
        operatorUserId,
        operatorSessionId
      });
    } catch (error) {
      if (error instanceof AuthProblemError) {
        const mappedError = error.errorCode === 'AUTH-404-TENANT-MEMBERSHIP-NOT-FOUND'
          ? tenantUserErrors.membershipNotFound()
          : error;
        addAuditEvent({
          type: 'tenant.user.roles.update.rejected',
          requestId: resolvedRequestId,
          operatorUserId,
          detail: 'tenant user role binding update rejected',
          metadata: {
            tenant_id: activeTenantId,
            membership_id: parsedInput.membershipId,
            error_code: mappedError.errorCode
          }
        });
        throw mappedError;
      }
      addAuditEvent({
        type: 'tenant.user.roles.update.rejected',
        requestId: resolvedRequestId,
        operatorUserId,
        detail: 'tenant user role binding update dependency unavailable',
        metadata: {
          tenant_id: activeTenantId,
          membership_id: parsedInput.membershipId,
          error_code: 'AUTH-503-TENANT-MEMBER-DEPENDENCY-UNAVAILABLE'
        }
      });
      throw tenantUserErrors.dependencyUnavailable();
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
        type: 'tenant.user.roles.update.rejected',
        requestId: resolvedRequestId,
        operatorUserId,
        detail: 'tenant user role binding update returned malformed payload',
        metadata: {
          tenant_id: activeTenantId,
          membership_id: parsedInput.membershipId,
          error_code: 'AUTH-503-TENANT-MEMBER-DEPENDENCY-UNAVAILABLE'
        }
      });
      throw tenantUserErrors.dependencyUnavailable();
    }
    if (resolvedMembershipId !== parsedInput.membershipId) {
      addAuditEvent({
        type: 'tenant.user.roles.update.rejected',
        requestId: resolvedRequestId,
        operatorUserId,
        detail: 'tenant user role binding update returned mismatched membership',
        metadata: {
          tenant_id: activeTenantId,
          membership_id: parsedInput.membershipId,
          error_code: 'AUTH-503-TENANT-MEMBER-DEPENDENCY-UNAVAILABLE'
        }
      });
      throw tenantUserErrors.dependencyUnavailable();
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
        type: 'tenant.user.roles.update.rejected',
        requestId: resolvedRequestId,
        operatorUserId,
        detail: 'tenant user role binding update returned mismatched role set',
        metadata: {
          tenant_id: activeTenantId,
          membership_id: parsedInput.membershipId,
          error_code: 'AUTH-503-TENANT-MEMBER-DEPENDENCY-UNAVAILABLE'
        }
      });
      throw tenantUserErrors.dependencyUnavailable();
    }

    addAuditEvent({
      type: 'tenant.user.roles.update.succeeded',
      requestId: resolvedRequestId,
      operatorUserId,
      detail: 'tenant user role bindings replaced',
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
    listUsers,
    createUser,
    updateUserStatus,
    getUserDetail,
    updateUserProfile,
    getUserRoles,
    replaceUserRoles,
    _internals: {
      auditTrail,
      authService
    }
  };
};

module.exports = { createTenantUserService };
