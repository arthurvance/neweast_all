const { log } = require('../../../../../common/logger');
const { AuthProblemError } = require('../../../../../shared-kernel/auth/auth-problem-error');
const {
  toPlatformPermissionSnapshotFromCodes
} = require('../../../../../modules/auth/permission-catalog');
const {
  resolveRoutePreauthorizedContext
} = require('../../../../../shared-kernel/auth/route-authz');
const {
  PLATFORM_USER_VIEW_PERMISSION_CODE,
  PLATFORM_USER_OPERATE_PERMISSION_CODE,
  PLATFORM_USER_SCOPE
} = require('../constants');

const CONTROL_CHAR_PATTERN = /[\u0000-\u001F\u007F]/;
const MAX_STATUS_REASON_LENGTH = 256;
const MAX_USER_ID_LENGTH = 64;
const MAX_USER_PHONE_LENGTH = 32;
const MAX_QUERY_KEYWORD_LENGTH = 64;
const MAX_QUERY_NAME_LENGTH = 64;
const MAX_QUERY_PHONE_LENGTH = 32;
const MAX_USER_DISPLAY_NAME_LENGTH = 64;
const MAX_USER_DEPARTMENT_NAME_LENGTH = 128;
const MAX_ROLE_ID_LENGTH = 64;
const MAX_ROLE_CODE_LENGTH = 64;
const MAX_ROLE_NAME_LENGTH = 128;
const MAX_CREATE_USER_ROLE_IDS = 5;
const MAX_QUERY_PAGE_SIZE = 100;
const MAX_AUDIT_TRAIL_ENTRIES = 200;
const CREATE_USER_ALLOWED_FIELDS = new Set([
  'phone',
  'name',
  'department',
  'role_ids'
]);
const UPDATE_USER_ALLOWED_FIELDS = new Set([
  'name',
  'department',
  'role_ids'
]);
const UPDATE_USER_STATUS_ALLOWED_FIELDS = new Set(['user_id', 'status', 'reason']);
const LIST_USER_ALLOWED_QUERY_FIELDS = new Set([
  'page',
  'page_size',
  'status',
  'keyword',
  'phone',
  'name',
  'created_at_start',
  'created_at_end'
]);
const GET_USER_ALLOWED_PARAM_FIELDS = new Set(['user_id']);
const UPDATE_USER_ALLOWED_PARAM_FIELDS = new Set(['user_id']);
const SOFT_DELETE_USER_ALLOWED_PARAM_FIELDS = new Set(['user_id']);
const VALID_USER_STATUSES = new Set(['active', 'disabled']);
const VALID_ROLE_STATUSES = new Set(['active', 'disabled']);
const ROLE_ID_ADDRESSABLE_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/;

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

const normalizeOptionalString = (candidate) => {
  if (candidate === null || candidate === undefined) {
    return null;
  }
  if (typeof candidate !== 'string') {
    return null;
  }
  const normalized = candidate.trim();
  return normalized || null;
};

const toIsoTimestamp = (candidate) => {
  if (candidate === null || candidate === undefined) {
    return '';
  }
  if (candidate instanceof Date) {
    return Number.isNaN(candidate.getTime()) ? '' : candidate.toISOString();
  }
  const normalized = String(candidate || '').trim();
  if (!normalized) {
    return '';
  }
  const parsedDate = new Date(normalized);
  if (Number.isNaN(parsedDate.getTime())) {
    return '';
  }
  return parsedDate.toISOString();
};

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

const maskKeywordForAudit = (keyword) => {
  const normalizedKeyword = String(keyword || '').trim();
  if (!normalizedKeyword) {
    return null;
  }
  const maskedPhone = maskPhone(normalizedKeyword);
  if (maskedPhone) {
    return maskedPhone;
  }
  if (normalizedKeyword.length <= 2) {
    return `${normalizedKeyword[0] || '*'}*`;
  }
  if (normalizedKeyword.length <= 6) {
    return `${normalizedKeyword.slice(0, 1)}***${normalizedKeyword.slice(-1)}`;
  }
  return `${normalizedKeyword.slice(0, 2)}***${normalizedKeyword.slice(-2)}`;
};

const normalizeUserStatus = (status) => {
  const normalizedStatus = String(status || '').trim().toLowerCase();
  if (normalizedStatus === 'enabled') {
    return 'active';
  }
  return normalizedStatus;
};
const normalizeRoleStatus = (status) => {
  const normalizedStatus = String(status || '').trim().toLowerCase();
  if (normalizedStatus === 'enabled') {
    return 'active';
  }
  return normalizedStatus;
};
const normalizeRoleId = (roleId) =>
  String(roleId || '').trim().toLowerCase();

const isResolvedOperatorIdentifier = (value) => {
  const normalized = String(value || '').trim();
  return normalized.length > 0 && normalized.toLowerCase() !== 'unknown';
};

const resolveAuthorizedOperatorContext = ({
  authorizationContext = null,
  expectedPermissionCode = PLATFORM_USER_OPERATE_PERMISSION_CODE
} = {}) => {
  const preauthorizedContext = resolveRoutePreauthorizedContext({
    authorizationContext,
    expectedPermissionCode,
    expectedScope: PLATFORM_USER_SCOPE,
    expectedEntryDomain: PLATFORM_USER_SCOPE
  });
  if (!preauthorizedContext) {
    return null;
  }
  return {
    operatorUserId: preauthorizedContext.userId,
    operatorSessionId: preauthorizedContext.sessionId
  };
};

const userProblem = ({ status, title, detail, errorCode, extensions = {} }) =>
  new AuthProblemError({
    status,
    title,
    detail,
    errorCode,
    extensions
  });

const userErrors = {
  invalidPayload: (detail = '请求参数不完整或格式错误') =>
    userProblem({
      status: 400,
      title: 'Bad Request',
      detail,
      errorCode: 'USR-400-INVALID-PAYLOAD'
    }),

  forbidden: () =>
    userProblem({
      status: 403,
      title: 'Forbidden',
      detail: '当前操作无权限',
      errorCode: 'AUTH-403-FORBIDDEN'
    }),

  userNotFound: () =>
    userProblem({
      status: 404,
      title: 'Not Found',
      detail: '目标平台用户不存在或无 platform 域访问',
      errorCode: 'USR-404-USER-NOT-FOUND',
      extensions: {
        retryable: false
      }
    }),

  platformSnapshotDegraded: ({ reason = 'db-deadlock' } = {}) =>
    userProblem({
      status: 503,
      title: 'Service Unavailable',
      detail: '平台权限同步暂时不可用，请稍后重试',
      errorCode: 'AUTH-503-PLATFORM-SNAPSHOT-DEGRADED',
      extensions: {
        retryable: true,
        degradation_reason: String(reason || 'db-deadlock').trim() || 'db-deadlock'
      }
    }),

  dependencyUnavailable: () =>
    userProblem({
      status: 503,
      title: 'Service Unavailable',
      detail: '平台用户治理依赖暂不可用，请稍后重试',
      errorCode: 'USR-503-DEPENDENCY-UNAVAILABLE',
      extensions: {
        retryable: true
      }
    })
};

const mapOperatorContextError = (error) =>
  error instanceof AuthProblemError ? error : userErrors.dependencyUnavailable();

const parseStrictPositiveInteger = ({
  value,
  field,
  max = Number.MAX_SAFE_INTEGER
}) => {
  const normalizedRaw = String(value ?? '').trim();
  if (!/^\d+$/.test(normalizedRaw)) {
    throw userErrors.invalidPayload(`${field} 必须为正整数`);
  }
  const parsed = Number(normalizedRaw);
  if (
    !Number.isInteger(parsed)
    || parsed <= 0
    || parsed > max
  ) {
    throw userErrors.invalidPayload(`${field} 必须为正整数`);
  }
  return parsed;
};

const parseListUserQuery = (query) => {
  if (!isPlainObject(query)) {
    throw userErrors.invalidPayload();
  }
  const unknownQueryKeys = Object.keys(query).filter(
    (key) => !LIST_USER_ALLOWED_QUERY_FIELDS.has(key)
  );
  if (unknownQueryKeys.length > 0) {
    throw userErrors.invalidPayload('请求参数不完整或格式错误');
  }

  const page = Object.prototype.hasOwnProperty.call(query, 'page')
    ? parseStrictPositiveInteger({
      value: query.page,
      field: 'page'
    })
    : 1;
  const pageSize = Object.prototype.hasOwnProperty.call(query, 'page_size')
    ? parseStrictPositiveInteger({
      value: query.page_size,
      field: 'page_size',
      max: MAX_QUERY_PAGE_SIZE
    })
    : 20;

  let status = null;
  if (Object.prototype.hasOwnProperty.call(query, 'status')) {
    if (typeof query.status !== 'string') {
      throw userErrors.invalidPayload('status 必须为 active 或 disabled');
    }
    const normalizedStatus = normalizeUserStatus(query.status);
    if (!VALID_USER_STATUSES.has(normalizedStatus)) {
      throw userErrors.invalidPayload('status 必须为 active 或 disabled');
    }
    status = normalizedStatus;
  }

  let keyword = null;
  if (Object.prototype.hasOwnProperty.call(query, 'keyword')) {
    if (typeof query.keyword !== 'string') {
      throw userErrors.invalidPayload('keyword 必须为字符串');
    }
    const normalizedKeyword = query.keyword.trim();
    if (normalizedKeyword.length > MAX_QUERY_KEYWORD_LENGTH) {
      throw userErrors.invalidPayload(
        `keyword 长度不能超过 ${MAX_QUERY_KEYWORD_LENGTH}`
      );
    }
    if (CONTROL_CHAR_PATTERN.test(normalizedKeyword)) {
      throw userErrors.invalidPayload('keyword 不能包含控制字符');
    }
    keyword = normalizedKeyword || null;
  }

  let phone = null;
  if (Object.prototype.hasOwnProperty.call(query, 'phone')) {
    if (typeof query.phone !== 'string') {
      throw userErrors.invalidPayload('phone 必须为字符串');
    }
    const normalizedPhone = query.phone.trim();
    if (CONTROL_CHAR_PATTERN.test(normalizedPhone)) {
      throw userErrors.invalidPayload('phone 不能包含控制字符');
    }
    if (normalizedPhone.length > MAX_QUERY_PHONE_LENGTH) {
      throw userErrors.invalidPayload(
        `phone 长度不能超过 ${MAX_QUERY_PHONE_LENGTH}`
      );
    }
    phone = normalizedPhone || null;
  }

  let name = null;
  if (Object.prototype.hasOwnProperty.call(query, 'name')) {
    if (typeof query.name !== 'string') {
      throw userErrors.invalidPayload('name 必须为字符串');
    }
    const normalizedName = query.name.trim();
    if (CONTROL_CHAR_PATTERN.test(normalizedName)) {
      throw userErrors.invalidPayload('name 不能包含控制字符');
    }
    if (normalizedName.length > MAX_QUERY_NAME_LENGTH) {
      throw userErrors.invalidPayload(
        `name 长度不能超过 ${MAX_QUERY_NAME_LENGTH}`
      );
    }
    name = normalizedName || null;
  }

  let createdAtStart = null;
  if (Object.prototype.hasOwnProperty.call(query, 'created_at_start')) {
    if (typeof query.created_at_start !== 'string') {
      throw userErrors.invalidPayload('created_at_start 必须为字符串');
    }
    const normalizedCreatedAtStart = query.created_at_start.trim();
    if (normalizedCreatedAtStart) {
      const parsedCreatedAtStart = toIsoTimestamp(normalizedCreatedAtStart);
      if (!parsedCreatedAtStart) {
        throw userErrors.invalidPayload('created_at_start 必须为合法时间');
      }
      createdAtStart = parsedCreatedAtStart;
    }
  }

  let createdAtEnd = null;
  if (Object.prototype.hasOwnProperty.call(query, 'created_at_end')) {
    if (typeof query.created_at_end !== 'string') {
      throw userErrors.invalidPayload('created_at_end 必须为字符串');
    }
    const normalizedCreatedAtEnd = query.created_at_end.trim();
    if (normalizedCreatedAtEnd) {
      const parsedCreatedAtEnd = toIsoTimestamp(normalizedCreatedAtEnd);
      if (!parsedCreatedAtEnd) {
        throw userErrors.invalidPayload('created_at_end 必须为合法时间');
      }
      createdAtEnd = parsedCreatedAtEnd;
    }
  }

  if (
    createdAtStart
    && createdAtEnd
    && new Date(createdAtStart).getTime() > new Date(createdAtEnd).getTime()
  ) {
    throw userErrors.invalidPayload('created_at_start 不能晚于 created_at_end');
  }

  return {
    page,
    pageSize,
    status,
    keyword,
    phone,
    name,
    createdAtStart,
    createdAtEnd
  };
};

const parseGetUserParams = (params) => {
  if (!isPlainObject(params)) {
    throw userErrors.invalidPayload();
  }
  const unknownParamKeys = Object.keys(params).filter(
    (key) => !GET_USER_ALLOWED_PARAM_FIELDS.has(key)
  );
  if (unknownParamKeys.length > 0) {
    throw userErrors.invalidPayload('请求参数不完整或格式错误');
  }
  if (!Object.prototype.hasOwnProperty.call(params, 'user_id')) {
    throw userErrors.invalidPayload('user_id 不能为空');
  }
  if (typeof params.user_id !== 'string') {
    throw userErrors.invalidPayload('user_id 必须为字符串');
  }
  const userId = normalizeRequiredString(params.user_id);
  if (!userId) {
    throw userErrors.invalidPayload('user_id 不能为空');
  }
  if (CONTROL_CHAR_PATTERN.test(userId)) {
    throw userErrors.invalidPayload('user_id 不能包含控制字符');
  }
  if (userId.length > MAX_USER_ID_LENGTH) {
    throw userErrors.invalidPayload(`user_id 长度不能超过 ${MAX_USER_ID_LENGTH}`);
  }
  return {
    userId
  };
};

const parseUpdateUserParams = (params) => {
  if (!isPlainObject(params)) {
    throw userErrors.invalidPayload();
  }
  const unknownParamKeys = Object.keys(params).filter(
    (key) => !UPDATE_USER_ALLOWED_PARAM_FIELDS.has(key)
  );
  if (unknownParamKeys.length > 0) {
    throw userErrors.invalidPayload('请求参数不完整或格式错误');
  }
  if (!Object.prototype.hasOwnProperty.call(params, 'user_id')) {
    throw userErrors.invalidPayload('user_id 不能为空');
  }
  if (typeof params.user_id !== 'string') {
    throw userErrors.invalidPayload('user_id 必须为字符串');
  }
  const userId = normalizeRequiredString(params.user_id);
  if (!userId) {
    throw userErrors.invalidPayload('user_id 不能为空');
  }
  if (CONTROL_CHAR_PATTERN.test(userId)) {
    throw userErrors.invalidPayload('user_id 不能包含控制字符');
  }
  if (userId.length > MAX_USER_ID_LENGTH) {
    throw userErrors.invalidPayload(`user_id 长度不能超过 ${MAX_USER_ID_LENGTH}`);
  }
  return {
    userId
  };
};

const parseCreateUserPayload = (payload) => {
  if (!isPlainObject(payload)) {
    throw userErrors.invalidPayload();
  }
  const unknownPayloadKeys = Object.keys(payload).filter(
    (key) => !CREATE_USER_ALLOWED_FIELDS.has(key)
  );
  if (unknownPayloadKeys.length > 0) {
    throw userErrors.invalidPayload('请求参数不完整或格式错误');
  }
  if (
    !Object.prototype.hasOwnProperty.call(payload, 'phone')
    || !Object.prototype.hasOwnProperty.call(payload, 'name')
  ) {
    throw userErrors.invalidPayload();
  }
  if (typeof payload.phone !== 'string') {
    throw userErrors.invalidPayload('phone 必须为字符串');
  }
  if (typeof payload.name !== 'string') {
    throw userErrors.invalidPayload('name 必须为字符串');
  }
  const phone = payload.phone.trim();
  if (!/^1\d{10}$/.test(phone)) {
    throw userErrors.invalidPayload('phone 必须为 11 位手机号');
  }

  const name = payload.name.trim();
  if (!name) {
    throw userErrors.invalidPayload('name 不能为空');
  }
  if (
    name.length > MAX_USER_DISPLAY_NAME_LENGTH
    || CONTROL_CHAR_PATTERN.test(name)
  ) {
    throw userErrors.invalidPayload(
      `name 长度不能超过 ${MAX_USER_DISPLAY_NAME_LENGTH}`
    );
  }

  let department = null;
  if (Object.prototype.hasOwnProperty.call(payload, 'department')) {
    if (payload.department === null || payload.department === undefined) {
      department = null;
    } else if (typeof payload.department !== 'string') {
      throw userErrors.invalidPayload('department 必须为字符串或 null');
    } else {
      const normalizedDepartment = payload.department.trim();
      if (!normalizedDepartment) {
        department = null;
      } else if (
        normalizedDepartment.length > MAX_USER_DEPARTMENT_NAME_LENGTH
        || CONTROL_CHAR_PATTERN.test(normalizedDepartment)
      ) {
        throw userErrors.invalidPayload(
          `department 长度不能超过 ${MAX_USER_DEPARTMENT_NAME_LENGTH}`
        );
      } else {
        department = normalizedDepartment;
      }
    }
  }

  let roleIds = [];
  if (Object.prototype.hasOwnProperty.call(payload, 'role_ids')) {
    if (!Array.isArray(payload.role_ids)) {
      throw userErrors.invalidPayload('role_ids 必须为数组');
    }
    if (payload.role_ids.length > MAX_CREATE_USER_ROLE_IDS) {
      throw userErrors.invalidPayload(
        `role_ids 数量不能超过 ${MAX_CREATE_USER_ROLE_IDS}`
      );
    }
    const dedupedRoleIds = new Map();
    for (const roleId of payload.role_ids) {
      if (typeof roleId !== 'string') {
        throw userErrors.invalidPayload('role_ids 仅允许字符串');
      }
      const normalizedRoleId = normalizeRoleId(roleId);
      if (!normalizedRoleId) {
        throw userErrors.invalidPayload('role_ids 不能包含空值');
      }
      if (
        normalizedRoleId.length > MAX_ROLE_ID_LENGTH
        || CONTROL_CHAR_PATTERN.test(normalizedRoleId)
      ) {
        throw userErrors.invalidPayload(
          `role_ids 值长度不能超过 ${MAX_ROLE_ID_LENGTH}`
        );
      }
      if (!ROLE_ID_ADDRESSABLE_PATTERN.test(normalizedRoleId)) {
        throw userErrors.invalidPayload(
          'role_ids 仅允许字母、数字、点、下划线和中划线，且必须以字母或数字开头'
        );
      }
      dedupedRoleIds.set(normalizedRoleId, normalizedRoleId);
    }
    roleIds = [...dedupedRoleIds.values()];
  }

  return {
    phone,
    name,
    department,
    roleIds
  };
};

const parseUpdateUserPayload = (payload) => {
  if (!isPlainObject(payload)) {
    throw userErrors.invalidPayload();
  }
  const unknownPayloadKeys = Object.keys(payload).filter(
    (key) => !UPDATE_USER_ALLOWED_FIELDS.has(key)
  );
  if (unknownPayloadKeys.length > 0) {
    throw userErrors.invalidPayload('请求参数不完整或格式错误');
  }

  if (!Object.prototype.hasOwnProperty.call(payload, 'name')) {
    throw userErrors.invalidPayload();
  }
  if (typeof payload.name !== 'string') {
    throw userErrors.invalidPayload('name 必须为字符串');
  }
  const name = payload.name.trim();
  if (!name) {
    throw userErrors.invalidPayload('name 不能为空');
  }
  if (
    name.length > MAX_USER_DISPLAY_NAME_LENGTH
    || CONTROL_CHAR_PATTERN.test(name)
  ) {
    throw userErrors.invalidPayload(
      `name 长度不能超过 ${MAX_USER_DISPLAY_NAME_LENGTH}`
    );
  }

  let department = null;
  if (Object.prototype.hasOwnProperty.call(payload, 'department')) {
    if (payload.department === null || payload.department === undefined) {
      department = null;
    } else if (typeof payload.department !== 'string') {
      throw userErrors.invalidPayload('department 必须为字符串或 null');
    } else {
      const normalizedDepartment = payload.department.trim();
      if (!normalizedDepartment) {
        department = null;
      } else if (
        normalizedDepartment.length > MAX_USER_DEPARTMENT_NAME_LENGTH
        || CONTROL_CHAR_PATTERN.test(normalizedDepartment)
      ) {
        throw userErrors.invalidPayload(
          `department 长度不能超过 ${MAX_USER_DEPARTMENT_NAME_LENGTH}`
        );
      } else {
        department = normalizedDepartment;
      }
    }
  }

  let roleIds = null;
  if (Object.prototype.hasOwnProperty.call(payload, 'role_ids')) {
    if (!Array.isArray(payload.role_ids)) {
      throw userErrors.invalidPayload('role_ids 必须为数组');
    }
    if (payload.role_ids.length > MAX_CREATE_USER_ROLE_IDS) {
      throw userErrors.invalidPayload(
        `role_ids 数量不能超过 ${MAX_CREATE_USER_ROLE_IDS}`
      );
    }
    const dedupedRoleIds = new Map();
    for (const roleId of payload.role_ids) {
      if (typeof roleId !== 'string') {
        throw userErrors.invalidPayload('role_ids 仅允许字符串');
      }
      const normalizedRoleId = normalizeRoleId(roleId);
      if (!normalizedRoleId) {
        throw userErrors.invalidPayload('role_ids 不能包含空值');
      }
      if (
        normalizedRoleId.length > MAX_ROLE_ID_LENGTH
        || CONTROL_CHAR_PATTERN.test(normalizedRoleId)
      ) {
        throw userErrors.invalidPayload(
          `role_ids 值长度不能超过 ${MAX_ROLE_ID_LENGTH}`
        );
      }
      if (!ROLE_ID_ADDRESSABLE_PATTERN.test(normalizedRoleId)) {
        throw userErrors.invalidPayload(
          'role_ids 仅允许字母、数字、点、下划线和中划线，且必须以字母或数字开头'
        );
      }
      dedupedRoleIds.set(normalizedRoleId, normalizedRoleId);
    }
    roleIds = [...dedupedRoleIds.values()];
  }

  return {
    name,
    department,
    roleIds
  };
};

const parseUpdateUserStatusPayload = (payload) => {
  if (!isPlainObject(payload)) {
    throw userErrors.invalidPayload();
  }
  const unknownPayloadKeys = Object.keys(payload).filter(
    (key) => !UPDATE_USER_STATUS_ALLOWED_FIELDS.has(key)
  );
  if (unknownPayloadKeys.length > 0) {
    throw userErrors.invalidPayload('请求参数不完整或格式错误');
  }

  const hasUserId = Object.prototype.hasOwnProperty.call(payload, 'user_id');
  const hasStatus = Object.prototype.hasOwnProperty.call(payload, 'status');
  if (!hasUserId || !hasStatus) {
    throw userErrors.invalidPayload();
  }

  if (typeof payload.user_id !== 'string') {
    throw userErrors.invalidPayload('user_id 必须为字符串');
  }
  if (typeof payload.status !== 'string') {
    throw userErrors.invalidPayload('status 必须为字符串');
  }

  const userId = normalizeRequiredString(payload.user_id);
  const nextStatus = normalizeUserStatus(payload.status);
  if (!userId) {
    throw userErrors.invalidPayload('user_id 不能为空');
  }
  if (!VALID_USER_STATUSES.has(nextStatus)) {
    throw userErrors.invalidPayload('status 必须为 active 或 disabled');
  }

  let reason = null;
  if (Object.prototype.hasOwnProperty.call(payload, 'reason')) {
    if (typeof payload.reason !== 'string') {
      throw userErrors.invalidPayload('reason 必须为字符串');
    }
    const normalizedReason = normalizeRequiredString(payload.reason);
    if (!normalizedReason) {
      throw userErrors.invalidPayload('reason 不能为空字符串');
    }
    if (CONTROL_CHAR_PATTERN.test(normalizedReason)) {
      throw userErrors.invalidPayload('reason 不能包含控制字符');
    }
    if (normalizedReason.length > MAX_STATUS_REASON_LENGTH) {
      throw userErrors.invalidPayload(
        `reason 长度不能超过 ${MAX_STATUS_REASON_LENGTH}`
      );
    }
    reason = normalizedReason;
  }

  return {
    userId,
    nextStatus,
    reason
  };
};

const parseSoftDeleteUserParams = (params) => {
  if (!isPlainObject(params)) {
    throw userErrors.invalidPayload();
  }
  const unknownParamKeys = Object.keys(params).filter(
    (key) => !SOFT_DELETE_USER_ALLOWED_PARAM_FIELDS.has(key)
  );
  if (unknownParamKeys.length > 0) {
    throw userErrors.invalidPayload('请求参数不完整或格式错误');
  }
  if (!Object.prototype.hasOwnProperty.call(params, 'user_id')) {
    throw userErrors.invalidPayload('user_id 不能为空');
  }
  if (typeof params.user_id !== 'string') {
    throw userErrors.invalidPayload('user_id 必须为字符串');
  }
  const userId = normalizeRequiredString(params.user_id);
  if (!userId) {
    throw userErrors.invalidPayload('user_id 不能为空');
  }
  if (CONTROL_CHAR_PATTERN.test(userId)) {
    throw userErrors.invalidPayload('user_id 不能包含控制字符');
  }
  if (userId.length > MAX_USER_ID_LENGTH) {
    throw userErrors.invalidPayload(`user_id 长度不能超过 ${MAX_USER_ID_LENGTH}`);
  }
  return {
    userId
  };
};

const normalizeUserRoleReadModel = (candidate) => {
  if (!isPlainObject(candidate)) {
    throw userErrors.dependencyUnavailable();
  }
  const roleId = normalizeRoleId(candidate.role_id ?? candidate.roleId);
  if (
    !roleId
    || roleId.length > MAX_ROLE_ID_LENGTH
    || CONTROL_CHAR_PATTERN.test(roleId)
  ) {
    throw userErrors.dependencyUnavailable();
  }
  const code = normalizeOptionalString(candidate.code);
  if (
    code !== null
    && (
      code.length > MAX_ROLE_CODE_LENGTH
      || CONTROL_CHAR_PATTERN.test(code)
    )
  ) {
    throw userErrors.dependencyUnavailable();
  }
  const name = normalizeOptionalString(candidate.name);
  if (
    name !== null
    && (
      name.length > MAX_ROLE_NAME_LENGTH
      || CONTROL_CHAR_PATTERN.test(name)
    )
  ) {
    throw userErrors.dependencyUnavailable();
  }
  const status = normalizeRoleStatus(candidate.status ?? candidate.role_status ?? candidate.roleStatus);
  if (status && !VALID_ROLE_STATUSES.has(status)) {
    throw userErrors.dependencyUnavailable();
  }
  return {
    role_id: roleId,
    code,
    name,
    status: VALID_ROLE_STATUSES.has(status) ? status : 'disabled'
  };
};

const createPlatformUserService = ({ authService } = {}) => {
  const auditTrail = [];

  const addAuditEvent = ({
    type,
    requestId,
    operatorUserId = 'unknown',
    targetUserId = null,
    detail,
    metadata = {}
  }) => {
    const event = {
      type: String(type || '').trim() || 'platform.user.unknown',
      at: new Date().toISOString(),
      request_id: String(requestId || '').trim() || 'request_id_unset',
      operator_user_id: String(operatorUserId || '').trim() || 'unknown',
      target_user_id: targetUserId ? String(targetUserId) : null,
      detail: String(detail || '').trim(),
      ...metadata
    };
    auditTrail.push(event);
    if (auditTrail.length > MAX_AUDIT_TRAIL_ENTRIES) {
      auditTrail.splice(0, auditTrail.length - MAX_AUDIT_TRAIL_ENTRIES);
    }
    log('info', 'Platform user audit event', event);
  };

  const assertAuthServiceMethod = (methodName) => {
    if (!authService || typeof authService[methodName] !== 'function') {
      throw userErrors.dependencyUnavailable();
    }
  };

  const resolveAuthStore = () => authService?._internals?.authStore || null;

  const assertAuthStoreMethod = (methodName) => {
    const authStore = resolveAuthStore();
    if (!authStore || typeof authStore[methodName] !== 'function') {
      throw userErrors.dependencyUnavailable();
    }
    return authStore;
  };

  const normalizeUserReadModel = (candidate) => {
    if (!isPlainObject(candidate)) {
      throw userErrors.dependencyUnavailable();
    }
    const userId = normalizeRequiredString(
      candidate.user_id ?? candidate.userId
    );
    const status = normalizeUserStatus(
      candidate.status ?? candidate.platform_status ?? candidate.platformStatus
    );
    const phoneRaw = candidate.phone ?? candidate.phone_number ?? candidate.phoneNumber;
    const phone = typeof phoneRaw === 'string' ? phoneRaw.trim() : '';
    const name = normalizeOptionalString(
      candidate.name ?? candidate.display_name ?? candidate.displayName
    );
    const department = normalizeOptionalString(
      candidate.department ?? candidate.department_name ?? candidate.departmentName
    );
    const rolesRaw = Array.isArray(candidate.roles) ? candidate.roles : [];
    const createdAt = toIsoTimestamp(
      candidate.created_at ?? candidate.createdAt
    );
    if (!userId || userId.length > MAX_USER_ID_LENGTH || CONTROL_CHAR_PATTERN.test(userId)) {
      throw userErrors.dependencyUnavailable();
    }
    if (!VALID_USER_STATUSES.has(status)) {
      throw userErrors.dependencyUnavailable();
    }
    if (
      !phone
      || phone.length > MAX_USER_PHONE_LENGTH
      || CONTROL_CHAR_PATTERN.test(phone)
    ) {
      throw userErrors.dependencyUnavailable();
    }
    if (
      name !== null
      && (
        name.length > MAX_USER_DISPLAY_NAME_LENGTH
        || CONTROL_CHAR_PATTERN.test(name)
      )
    ) {
      throw userErrors.dependencyUnavailable();
    }
    if (
      department !== null
      && (
        department.length > MAX_USER_DEPARTMENT_NAME_LENGTH
        || CONTROL_CHAR_PATTERN.test(department)
      )
    ) {
      throw userErrors.dependencyUnavailable();
    }
    if (!createdAt) {
      throw userErrors.dependencyUnavailable();
    }
    const roles = rolesRaw
      .map((role) => normalizeUserRoleReadModel(role))
      .sort((left, right) => String(left.role_id).localeCompare(String(right.role_id)));
    return {
      user_id: userId,
      phone,
      name,
      department,
      status,
      created_at: createdAt,
      roles
    };
  };

  const resolveOperatorContext = async ({
    requestId,
    accessToken,
    authorizationContext = null,
    expectedPermissionCode = PLATFORM_USER_OPERATE_PERMISSION_CODE
  }) => {
    const preAuthorizedOperatorContext =
      resolveAuthorizedOperatorContext({
        authorizationContext,
        expectedPermissionCode
      });
    let operatorUserId = preAuthorizedOperatorContext?.operatorUserId || 'unknown';
    let operatorSessionId = preAuthorizedOperatorContext?.operatorSessionId || 'unknown';
    if (!preAuthorizedOperatorContext) {
      assertAuthServiceMethod('authorizeRoute');
      const authorized = await authService.authorizeRoute({
        requestId,
        accessToken,
        permissionCode: expectedPermissionCode,
        scope: PLATFORM_USER_SCOPE,
        authorizationContext
      });
      operatorUserId = String(authorized?.user_id || '').trim() || 'unknown';
      operatorSessionId = String(authorized?.session_id || '').trim() || 'unknown';
    }
    if (
      !isResolvedOperatorIdentifier(operatorUserId)
      || !isResolvedOperatorIdentifier(operatorSessionId)
    ) {
      throw userErrors.forbidden();
    }
    return {
      operatorUserId,
      operatorSessionId
    };
  };

  const replaceUserRolesAndSyncSnapshot = async ({
    userId,
    roleIds = []
  }) => {
    const normalizedRoleIds = Array.isArray(roleIds) ? roleIds : [];
    const permissionCodesByRoleId = new Map(
      normalizedRoleIds.map((roleId) => [roleId, []])
    );
    if (normalizedRoleIds.length > 0) {
      const authStoreForRoleCatalog = assertAuthStoreMethod('listPlatformRoleCatalogEntries');
      const roleCatalogEntries = await authStoreForRoleCatalog.listPlatformRoleCatalogEntries({
        scope: PLATFORM_USER_SCOPE,
        tenantId: null
      });
      if (!Array.isArray(roleCatalogEntries)) {
        throw userErrors.dependencyUnavailable();
      }
      const enabledRoleIdSet = new Set();
      for (const roleCatalogEntry of roleCatalogEntries) {
        const catalogRoleId = normalizeRoleId(
          roleCatalogEntry?.roleId ?? roleCatalogEntry?.role_id
        );
        const catalogRoleStatus = normalizeRoleStatus(roleCatalogEntry?.status);
        if (
          catalogRoleId
          && VALID_ROLE_STATUSES.has(catalogRoleStatus)
          && catalogRoleStatus === 'active'
        ) {
          enabledRoleIdSet.add(catalogRoleId);
        }
      }
      const hasInvalidRoleIds = normalizedRoleIds.some(
        (roleId) => !enabledRoleIdSet.has(roleId)
      );
      if (hasInvalidRoleIds) {
        throw userErrors.invalidPayload('role_ids 包含不存在或已禁用角色');
      }

      const authStoreForRoleGrants = assertAuthStoreMethod('listPlatformRolePermissionGrantsByRoleIds');
      const grants = await authStoreForRoleGrants.listPlatformRolePermissionGrantsByRoleIds({
        roleIds: normalizedRoleIds
      });
      if (!Array.isArray(grants)) {
        throw userErrors.dependencyUnavailable();
      }
      for (const grant of grants) {
        const grantRoleId = normalizeRoleId(grant?.roleId ?? grant?.role_id);
        const grantPermissionCodes = Array.isArray(grant?.permissionCodes)
          ? grant.permissionCodes
          : Array.isArray(grant?.permission_codes)
            ? grant.permission_codes
            : null;
        if (!grantRoleId || !permissionCodesByRoleId.has(grantRoleId) || !grantPermissionCodes) {
          throw userErrors.dependencyUnavailable();
        }
        permissionCodesByRoleId.set(
          grantRoleId,
          [...new Set(
            grantPermissionCodes
              .map((permissionCode) => String(permissionCode || '').trim().toLowerCase())
              .filter((permissionCode) => permissionCode.length > 0)
          )]
        );
      }
    }

    const rolesForPersistence = normalizedRoleIds.map((roleId) => ({
      role_id: roleId,
      status: 'active',
      permission: toPlatformPermissionSnapshotFromCodes(
        permissionCodesByRoleId.get(roleId) || []
      )
    }));
    const authStoreForRoleFacts = assertAuthStoreMethod('replacePlatformRolesAndSyncSnapshot');
    const roleFactSyncResult = await authStoreForRoleFacts.replacePlatformRolesAndSyncSnapshot({
      userId,
      roles: rolesForPersistence
    });
    const roleFactSyncReason = String(roleFactSyncResult?.reason || '').trim().toLowerCase();
    if (roleFactSyncReason === 'invalid-user-id') {
      throw userErrors.userNotFound();
    }
    if (roleFactSyncReason === 'db-deadlock' || roleFactSyncReason === 'concurrent-role-facts-update') {
      throw userErrors.platformSnapshotDegraded({
        reason: roleFactSyncReason
      });
    }
    if (roleFactSyncReason !== 'ok') {
      throw userErrors.platformSnapshotDegraded({
        reason: roleFactSyncReason || 'unknown'
      });
    }
  };

  const listUsers = async ({
    requestId,
    accessToken,
    query = {},
    authorizationContext = null
  }) => {
    const resolvedRequestId = String(requestId || '').trim() || 'request_id_unset';
    let parsedQuery;
    try {
      parsedQuery = parseListUserQuery(query);
    } catch (error) {
      addAuditEvent({
        type: 'platform.user.list.rejected',
        requestId: resolvedRequestId,
        operatorUserId: 'unknown',
        detail: 'query validation failed',
        metadata: {
          error_code: error?.errorCode || userErrors.invalidPayload().errorCode
        }
      });
      throw error;
    }

    let operatorContext;
    try {
      operatorContext = await resolveOperatorContext({
        requestId: resolvedRequestId,
        accessToken,
        authorizationContext,
        expectedPermissionCode: PLATFORM_USER_VIEW_PERMISSION_CODE
      });
    } catch (error) {
      const mappedError = mapOperatorContextError(error);
      addAuditEvent({
        type: 'platform.user.list.rejected',
        requestId: resolvedRequestId,
        operatorUserId: 'unknown',
        detail: 'operator authorization context invalid',
        metadata: {
          error_code: mappedError.errorCode
        }
      });
      throw mappedError;
    }

    const { operatorUserId } = operatorContext;
    let result;
    try {
      const authStore = assertAuthStoreMethod('listPlatformUsers');
      result = await authStore.listPlatformUsers({
        page: parsedQuery.page,
        pageSize: parsedQuery.pageSize,
        status: parsedQuery.status,
        keyword: parsedQuery.keyword,
        phone: parsedQuery.phone,
        name: parsedQuery.name,
        createdAtStart: parsedQuery.createdAtStart,
        createdAtEnd: parsedQuery.createdAtEnd
      });
    } catch (error) {
      if (error instanceof AuthProblemError) {
        addAuditEvent({
          type: 'platform.user.list.rejected',
          requestId: resolvedRequestId,
          operatorUserId,
          detail: 'platform user list dependency rejected',
          metadata: {
            error_code: error.errorCode
          }
        });
        throw error;
      }
      addAuditEvent({
        type: 'platform.user.list.rejected',
        requestId: resolvedRequestId,
        operatorUserId,
        detail: 'platform user list dependency unavailable',
        metadata: {
          error_code: 'USR-503-DEPENDENCY-UNAVAILABLE'
        }
      });
      throw userErrors.dependencyUnavailable();
    }

    const total = Number(result?.total);
    if (!Array.isArray(result?.items) || !Number.isInteger(total) || total < 0) {
      addAuditEvent({
        type: 'platform.user.list.rejected',
        requestId: resolvedRequestId,
        operatorUserId,
        detail: 'platform user list dependency returned invalid payload',
        metadata: {
          error_code: 'USR-503-DEPENDENCY-UNAVAILABLE',
          upstream_error_code: 'PLATFORM-USER-LIST-RESULT-INVALID'
        }
      });
      throw userErrors.dependencyUnavailable();
    }

    let items;
    try {
      items = result.items.map((item) => normalizeUserReadModel(item));
    } catch (_error) {
      addAuditEvent({
        type: 'platform.user.list.rejected',
        requestId: resolvedRequestId,
        operatorUserId,
        detail: 'platform user list dependency returned invalid item schema',
        metadata: {
          error_code: 'USR-503-DEPENDENCY-UNAVAILABLE',
          upstream_error_code: 'PLATFORM-USER-LIST-ITEM-INVALID'
        }
      });
      throw userErrors.dependencyUnavailable();
    }

    addAuditEvent({
      type: 'platform.user.listed',
      requestId: resolvedRequestId,
      operatorUserId,
      detail: 'platform users listed',
      metadata: {
        total,
        page: parsedQuery.page,
        page_size: parsedQuery.pageSize,
        result_count: items.length,
        status: parsedQuery.status,
        keyword: maskKeywordForAudit(parsedQuery.keyword),
        phone: maskPhone(parsedQuery.phone),
        name: maskKeywordForAudit(parsedQuery.name),
        created_at_start: parsedQuery.createdAtStart,
        created_at_end: parsedQuery.createdAtEnd
      }
    });

    return {
      items,
      total,
      page: parsedQuery.page,
      page_size: parsedQuery.pageSize,
      request_id: resolvedRequestId
    };
  };

  const getUser = async ({
    requestId,
    accessToken,
    params = {},
    authorizationContext = null
  }) => {
    const resolvedRequestId = String(requestId || '').trim() || 'request_id_unset';
    let parsedParams;
    try {
      parsedParams = parseGetUserParams(params);
    } catch (error) {
      addAuditEvent({
        type: 'platform.user.get.rejected',
        requestId: resolvedRequestId,
        operatorUserId: 'unknown',
        detail: 'path parameter validation failed',
        metadata: {
          error_code: error?.errorCode || userErrors.invalidPayload().errorCode
        }
      });
      throw error;
    }

    let operatorContext;
    try {
      operatorContext = await resolveOperatorContext({
        requestId: resolvedRequestId,
        accessToken,
        authorizationContext,
        expectedPermissionCode: PLATFORM_USER_VIEW_PERMISSION_CODE
      });
    } catch (error) {
      const mappedError = mapOperatorContextError(error);
      addAuditEvent({
        type: 'platform.user.get.rejected',
        requestId: resolvedRequestId,
        operatorUserId: 'unknown',
        targetUserId: parsedParams.userId,
        detail: 'operator authorization context invalid',
        metadata: {
          error_code: mappedError.errorCode
        }
      });
      throw mappedError;
    }

    const { operatorUserId } = operatorContext;
    let foundUser = null;
    try {
      const authStore = assertAuthStoreMethod('getPlatformUserById');
      foundUser = await authStore.getPlatformUserById({
        userId: parsedParams.userId
      });
    } catch (error) {
      if (error instanceof AuthProblemError) {
        addAuditEvent({
          type: 'platform.user.get.rejected',
          requestId: resolvedRequestId,
          operatorUserId,
          targetUserId: parsedParams.userId,
          detail: 'platform user read dependency rejected',
          metadata: {
            error_code: error.errorCode
          }
        });
        throw error;
      }
      addAuditEvent({
        type: 'platform.user.get.rejected',
        requestId: resolvedRequestId,
        operatorUserId,
        targetUserId: parsedParams.userId,
        detail: 'platform user read dependency unavailable',
        metadata: {
          error_code: 'USR-503-DEPENDENCY-UNAVAILABLE'
        }
      });
      throw userErrors.dependencyUnavailable();
    }

    if (!foundUser) {
      addAuditEvent({
        type: 'platform.user.get.rejected',
        requestId: resolvedRequestId,
        operatorUserId,
        targetUserId: parsedParams.userId,
        detail: 'target user not found',
        metadata: {
          error_code: 'USR-404-USER-NOT-FOUND'
        }
      });
      throw userErrors.userNotFound();
    }

    let normalizedUser;
    try {
      normalizedUser = normalizeUserReadModel(foundUser);
    } catch (_error) {
      addAuditEvent({
        type: 'platform.user.get.rejected',
        requestId: resolvedRequestId,
        operatorUserId,
        targetUserId: parsedParams.userId,
        detail: 'platform user read dependency returned invalid payload',
        metadata: {
          error_code: 'USR-503-DEPENDENCY-UNAVAILABLE',
          upstream_error_code: 'PLATFORM-USER-GET-RESULT-INVALID'
        }
      });
      throw userErrors.dependencyUnavailable();
    }

    addAuditEvent({
      type: 'platform.user.got',
      requestId: resolvedRequestId,
      operatorUserId,
      targetUserId: normalizedUser.user_id,
      detail: 'platform user detail loaded',
      metadata: {
        status: normalizedUser.status
      }
    });

    return {
      ...normalizedUser,
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
    const requestedPhone = String(payload?.phone || '').trim() || null;
    const maskedRequestedPhone = maskPhone(requestedPhone);

    let parsedPayload;
    try {
      parsedPayload = parseCreateUserPayload(payload);
    } catch (error) {
      addAuditEvent({
        type: 'platform.user.create.rejected',
        requestId: resolvedRequestId,
        operatorUserId: 'unknown',
        detail: 'payload validation failed',
        metadata: {
          target_user_id: null,
          phone: maskedRequestedPhone,
          error_code: error?.errorCode || userErrors.invalidPayload().errorCode
        }
      });
      throw error;
    }

    let operatorContext;
    try {
      operatorContext = await resolveOperatorContext({
        requestId: resolvedRequestId,
        accessToken,
        authorizationContext
      });
    } catch (error) {
      const mappedError = mapOperatorContextError(error);
      addAuditEvent({
        type: 'platform.user.create.rejected',
        requestId: resolvedRequestId,
        operatorUserId: 'unknown',
        detail: 'operator authorization context invalid',
        metadata: {
          error_code: mappedError.errorCode
        }
      });
      throw mappedError;
    }
    const { operatorUserId, operatorSessionId } = operatorContext;

    assertAuthServiceMethod('provisionPlatformUserByPhone');
    let provisionedUser = null;
    try {
      provisionedUser = await authService.provisionPlatformUserByPhone({
        requestId: resolvedRequestId,
        accessToken,
        payload: {
          phone: parsedPayload.phone
        },
        authorizationContext,
        authorizedRoute: {
          user_id: operatorUserId,
          session_id: operatorSessionId,
          entry_domain: PLATFORM_USER_SCOPE,
          active_tenant_id: null
        }
      });
    } catch (error) {
      if (error instanceof AuthProblemError) {
        addAuditEvent({
          type: 'platform.user.create.rejected',
          requestId: resolvedRequestId,
          operatorUserId,
          detail: 'platform user provisioning rejected',
          metadata: {
            target_user_id: null,
            phone: maskedRequestedPhone,
            error_code: error.errorCode
          }
        });
        throw error;
      }
      addAuditEvent({
        type: 'platform.user.create.rejected',
        requestId: resolvedRequestId,
        operatorUserId,
        detail: 'platform user provisioning dependency unavailable',
        metadata: {
          target_user_id: null,
          phone: maskedRequestedPhone,
          error_code: 'USR-503-DEPENDENCY-UNAVAILABLE'
        }
      });
      throw userErrors.dependencyUnavailable();
    }

    const resolvedUserId = String(provisionedUser?.user_id || '').trim();
    if (!resolvedUserId) {
      addAuditEvent({
        type: 'platform.user.create.rejected',
        requestId: resolvedRequestId,
        operatorUserId,
        detail: 'platform user provisioning dependency returned invalid payload',
        metadata: {
          target_user_id: null,
          phone: maskedRequestedPhone,
          error_code: 'USR-503-DEPENDENCY-UNAVAILABLE',
          upstream_error_code: 'PLATFORM-USER-PROVISION-RESULT-MISSING-USER-ID'
        }
      });
      throw userErrors.dependencyUnavailable();
    }

    const authStoreForProfile = assertAuthStoreMethod('upsertPlatformUserProfile');
    try {
      await authStoreForProfile.upsertPlatformUserProfile({
        userId: resolvedUserId,
        name: parsedPayload.name,
        department: parsedPayload.department
      });
    } catch (error) {
      const mappedError = error instanceof AuthProblemError
        ? error
        : userErrors.dependencyUnavailable();
      addAuditEvent({
        type: 'platform.user.create.rejected',
        requestId: resolvedRequestId,
        operatorUserId,
        targetUserId: resolvedUserId,
        detail: 'platform user profile upsert rejected',
        metadata: {
          phone: maskPhone(parsedPayload.phone),
          error_code: mappedError.errorCode || 'USR-503-DEPENDENCY-UNAVAILABLE',
          upstream_error_code: String(error?.errorCode || error?.code || 'unknown')
        }
      });
      throw mappedError;
    }

    const normalizedRoleIds = parsedPayload.roleIds;
    try {
      await replaceUserRolesAndSyncSnapshot({
        userId: resolvedUserId,
        roleIds: normalizedRoleIds
      });
    } catch (error) {
      const mappedError = error instanceof AuthProblemError
        ? error
        : userErrors.dependencyUnavailable();
      addAuditEvent({
        type: 'platform.user.create.rejected',
        requestId: resolvedRequestId,
        operatorUserId,
        targetUserId: resolvedUserId,
        detail: 'platform user role facts sync rejected',
        metadata: {
          phone: maskPhone(parsedPayload.phone),
          error_code: mappedError.errorCode || 'USR-503-DEPENDENCY-UNAVAILABLE',
          upstream_error_code: String(error?.errorCode || error?.code || 'unknown')
        }
      });
      throw mappedError;
    }

    addAuditEvent({
      type:
        provisionedUser?.created_user === true
          ? 'platform.user.created'
          : 'platform.user.reused',
      requestId: resolvedRequestId,
      operatorUserId,
      targetUserId: resolvedUserId,
      detail:
        provisionedUser?.created_user === true
          ? 'platform user created'
          : 'platform user reused',
      metadata: {
        phone: maskedRequestedPhone,
        created_user: Boolean(provisionedUser?.created_user),
        reused_existing_user: Boolean(provisionedUser?.reused_existing_user),
        role_count: normalizedRoleIds.length
      }
    });

    return {
      user_id: resolvedUserId,
      created_user: Boolean(provisionedUser?.created_user),
      reused_existing_user: Boolean(provisionedUser?.reused_existing_user),
      request_id: resolvedRequestId
    };
  };

  const updateUser = async ({
    requestId,
    accessToken,
    params = {},
    payload = {},
    traceparent = null,
    authorizationContext = null
  }) => {
    const resolvedRequestId = String(requestId || '').trim() || 'request_id_unset';
    const normalizedTraceparent = String(traceparent || '').trim() || null;
    const requestedUserId = String(params?.user_id || '').trim() || null;

    let operatorContext;
    try {
      operatorContext = await resolveOperatorContext({
        requestId: resolvedRequestId,
        accessToken,
        authorizationContext
      });
    } catch (error) {
      const mappedError = mapOperatorContextError(error);
      addAuditEvent({
        type: 'platform.user.update.rejected',
        requestId: resolvedRequestId,
        operatorUserId: 'unknown',
        targetUserId: requestedUserId,
        detail: 'operator authorization context invalid',
        metadata: {
          error_code: mappedError.errorCode
        }
      });
      throw mappedError;
    }
    const { operatorUserId } = operatorContext;

    let parsedParams;
    try {
      parsedParams = parseUpdateUserParams(params);
    } catch (error) {
      if (error instanceof AuthProblemError) {
        addAuditEvent({
          type: 'platform.user.update.rejected',
          requestId: resolvedRequestId,
          operatorUserId,
          targetUserId: requestedUserId,
          detail: 'path parameter validation failed',
          metadata: {
            error_code: error.errorCode
          }
        });
      }
      throw error;
    }

    let parsedPayload;
    try {
      parsedPayload = parseUpdateUserPayload(payload);
    } catch (error) {
      if (error instanceof AuthProblemError) {
        addAuditEvent({
          type: 'platform.user.update.rejected',
          requestId: resolvedRequestId,
          operatorUserId,
          targetUserId: parsedParams.userId,
          detail: 'payload validation failed',
          metadata: {
            error_code: error.errorCode
          }
        });
      }
      throw error;
    }

    let previousUser;
    try {
      const authStoreForRead = assertAuthStoreMethod('getPlatformUserById');
      const existingUser = await authStoreForRead.getPlatformUserById({
        userId: parsedParams.userId
      });
      if (!existingUser) {
        throw userErrors.userNotFound();
      }
      previousUser = normalizeUserReadModel(existingUser);
    } catch (error) {
      const mappedError = error instanceof AuthProblemError
        ? error
        : userErrors.dependencyUnavailable();
      addAuditEvent({
        type: 'platform.user.update.rejected',
        requestId: resolvedRequestId,
        operatorUserId,
        targetUserId: parsedParams.userId,
        detail: mappedError.errorCode === 'USR-404-USER-NOT-FOUND'
          ? 'target user not found'
          : 'platform user read dependency unavailable before update',
        metadata: {
          error_code: mappedError.errorCode || 'USR-503-DEPENDENCY-UNAVAILABLE',
          upstream_error_code: String(error?.errorCode || error?.code || 'unknown')
        }
      });
      throw mappedError;
    }

    if (Array.isArray(parsedPayload.roleIds)) {
      try {
        await replaceUserRolesAndSyncSnapshot({
          userId: parsedParams.userId,
          roleIds: parsedPayload.roleIds
        });
      } catch (error) {
        const mappedError = error instanceof AuthProblemError
          ? error
          : userErrors.dependencyUnavailable();
        addAuditEvent({
          type: 'platform.user.update.rejected',
          requestId: resolvedRequestId,
          operatorUserId,
          targetUserId: parsedParams.userId,
          detail: 'platform user role facts sync rejected',
          metadata: {
            phone: maskPhone(previousUser.phone),
            error_code: mappedError.errorCode || 'USR-503-DEPENDENCY-UNAVAILABLE',
            upstream_error_code: String(error?.errorCode || error?.code || 'unknown')
          }
        });
        throw mappedError;
      }
    }

    try {
      const authStoreForProfile = assertAuthStoreMethod('upsertPlatformUserProfile');
      await authStoreForProfile.upsertPlatformUserProfile({
        userId: parsedParams.userId,
        name: parsedPayload.name,
        department: parsedPayload.department
      });
    } catch (error) {
      const mappedError = error instanceof AuthProblemError
        ? error
        : userErrors.dependencyUnavailable();
      addAuditEvent({
        type: 'platform.user.update.rejected',
        requestId: resolvedRequestId,
        operatorUserId,
        targetUserId: parsedParams.userId,
        detail: 'platform user profile upsert rejected',
        metadata: {
          phone: maskPhone(previousUser.phone),
          error_code: mappedError.errorCode || 'USR-503-DEPENDENCY-UNAVAILABLE',
          upstream_error_code: String(error?.errorCode || error?.code || 'unknown')
        }
      });
      throw mappedError;
    }

    let updatedUser;
    try {
      const authStoreForRead = assertAuthStoreMethod('getPlatformUserById');
      const currentUser = await authStoreForRead.getPlatformUserById({
        userId: parsedParams.userId
      });
      if (!currentUser) {
        throw userErrors.userNotFound();
      }
      updatedUser = normalizeUserReadModel(currentUser);
    } catch (error) {
      const mappedError = error instanceof AuthProblemError
        ? error
        : userErrors.dependencyUnavailable();
      addAuditEvent({
        type: 'platform.user.update.rejected',
        requestId: resolvedRequestId,
        operatorUserId,
        targetUserId: parsedParams.userId,
        detail: mappedError.errorCode === 'USR-404-USER-NOT-FOUND'
          ? 'target user not found after update'
          : 'platform user read dependency unavailable after update',
        metadata: {
          phone: maskPhone(previousUser.phone),
          error_code: mappedError.errorCode || 'USR-503-DEPENDENCY-UNAVAILABLE',
          upstream_error_code: String(error?.errorCode || error?.code || 'unknown')
        }
      });
      throw mappedError;
    }

    const previousRoleIds = previousUser.roles.map((role) => role.role_id).join(',');
    const currentRoleIds = updatedUser.roles.map((role) => role.role_id).join(',');
    const isNoOp = (
      previousUser.name === updatedUser.name
      && previousUser.department === updatedUser.department
      && previousRoleIds === currentRoleIds
    );
    addAuditEvent({
      type: 'platform.user.updated',
      requestId: resolvedRequestId,
      operatorUserId,
      targetUserId: parsedParams.userId,
      detail: isNoOp
        ? 'platform user update treated as no-op'
        : 'platform user updated',
      metadata: {
        phone: maskPhone(updatedUser.phone),
        previous_phone: maskPhone(previousUser.phone),
        role_count: updatedUser.roles.length,
        traceparent: normalizedTraceparent
      }
    });

    return {
      ...updatedUser,
      request_id: resolvedRequestId
    };
  };

  const updateUserStatus = async ({
    requestId,
    accessToken,
    payload = {},
    traceparent = null,
    authorizationContext = null
  }) => {
    const resolvedRequestId = String(requestId || '').trim() || 'request_id_unset';
    const requestedUserId = String(payload?.user_id || '').trim() || null;
    const requestedNextStatus = normalizeUserStatus(payload?.status);
    let operatorContext;
    try {
      operatorContext = await resolveOperatorContext({
        requestId: resolvedRequestId,
        accessToken,
        authorizationContext
      });
    } catch (error) {
      const mappedError = mapOperatorContextError(error);
      addAuditEvent({
        type: 'platform.user.status.rejected',
        requestId: resolvedRequestId,
        operatorUserId: 'unknown',
        targetUserId: requestedUserId,
        detail: 'operator authorization context invalid',
        metadata: {
          previous_status: null,
          next_status: requestedNextStatus || null,
          error_code: mappedError.errorCode
        }
      });
      throw mappedError;
    }
    const { operatorUserId, operatorSessionId } = operatorContext;

    let parsedPayload;
    try {
      parsedPayload = parseUpdateUserStatusPayload(payload);
    } catch (error) {
      if (error instanceof AuthProblemError) {
        addAuditEvent({
          type: 'platform.user.status.rejected',
          requestId: resolvedRequestId,
          operatorUserId,
          targetUserId: requestedUserId,
          detail: 'payload validation failed',
          metadata: {
            previous_status: null,
            next_status: requestedNextStatus || null,
            error_code: error.errorCode
          }
        });
      }
      throw error;
    }

    assertAuthServiceMethod('updatePlatformUserStatus');
    let statusUpdateResult;
    try {
      statusUpdateResult = await authService.updatePlatformUserStatus({
        requestId: resolvedRequestId,
        traceparent,
        userId: parsedPayload.userId,
        nextStatus: parsedPayload.nextStatus,
        operatorUserId,
        operatorSessionId,
        reason: parsedPayload.reason
      });
    } catch (error) {
      const mappedError = (() => {
        if (error instanceof AuthProblemError) {
          if (Number(error.status) === 404) {
            return userErrors.userNotFound();
          }
          return error;
        }
        return userErrors.dependencyUnavailable();
      })();
      const mappedErrorCode = String(mappedError?.errorCode || '').trim();
      addAuditEvent({
        type: 'platform.user.status.rejected',
        requestId: resolvedRequestId,
        operatorUserId,
        targetUserId: parsedPayload.userId,
        detail:
          mappedErrorCode === 'USR-404-USER-NOT-FOUND'
            ? 'target user not found'
            : mappedError === error
              ? 'platform user status rejected by auth domain'
              : 'platform user status dependency unavailable',
        metadata: {
          previous_status: null,
          next_status: parsedPayload.nextStatus,
          error_code: mappedErrorCode || 'USR-503-DEPENDENCY-UNAVAILABLE',
          upstream_error_code: String(error?.errorCode || error?.code || '').trim() || 'unknown'
        }
      });
      throw mappedError;
    }

    if (!statusUpdateResult) {
      addAuditEvent({
        type: 'platform.user.status.rejected',
        requestId: resolvedRequestId,
        operatorUserId,
        targetUserId: parsedPayload.userId,
        detail: 'target user not found',
        metadata: {
          previous_status: null,
          next_status: parsedPayload.nextStatus,
          error_code: 'USR-404-USER-NOT-FOUND'
        }
      });
      throw userErrors.userNotFound();
    }

    const resolvedResultUserId = String(statusUpdateResult.user_id || '').trim();
    if (
      !resolvedResultUserId
      || resolvedResultUserId !== parsedPayload.userId
    ) {
      addAuditEvent({
        type: 'platform.user.status.rejected',
        requestId: resolvedRequestId,
        operatorUserId,
        targetUserId: parsedPayload.userId,
        detail: 'platform user status dependency returned mismatched target user',
        metadata: {
          previous_status: null,
          next_status: parsedPayload.nextStatus,
          error_code: 'AUTH-503-PLATFORM-SNAPSHOT-DEGRADED',
          upstream_error_code: 'PLATFORM-USER-STATUS-RESULT-TARGET-MISMATCH',
          upstream_target_user_id: resolvedResultUserId || null
        }
      });
      throw userErrors.platformSnapshotDegraded({
        reason: 'platform-user-status-target-mismatch'
      });
    }

    const previousStatus = normalizeUserStatus(statusUpdateResult.previous_status);
    const currentStatus = normalizeUserStatus(statusUpdateResult.current_status);
    if (
      !VALID_USER_STATUSES.has(previousStatus)
      || !VALID_USER_STATUSES.has(currentStatus)
    ) {
      addAuditEvent({
        type: 'platform.user.status.rejected',
        requestId: resolvedRequestId,
        operatorUserId,
        targetUserId: parsedPayload.userId,
        detail: 'platform user status dependency returned invalid state',
        metadata: {
          previous_status: previousStatus || null,
          next_status: parsedPayload.nextStatus,
          error_code: 'AUTH-503-PLATFORM-SNAPSHOT-DEGRADED',
          upstream_error_code: 'PLATFORM-USER-STATUS-RESULT-INVALID'
        }
      });
      throw userErrors.platformSnapshotDegraded({
        reason: 'platform-user-status-result-invalid'
      });
    }

    const isNoOp = previousStatus === currentStatus;
    addAuditEvent({
      type: 'platform.user.status.updated',
      requestId: resolvedRequestId,
      operatorUserId,
      targetUserId: resolvedResultUserId,
      detail: isNoOp
        ? 'platform user status update treated as no-op'
        : 'platform user status updated',
      metadata: {
        previous_status: previousStatus,
        next_status: currentStatus
      }
    });

    return {
      user_id: resolvedResultUserId,
      previous_status: previousStatus,
      current_status: currentStatus,
      request_id: resolvedRequestId
    };
  };

  const softDeleteUser = async ({
    requestId,
    accessToken,
    params = {},
    traceparent = null,
    authorizationContext = null
  }) => {
    const resolvedRequestId = String(requestId || '').trim() || 'request_id_unset';
    const requestedUserId = String(params?.user_id || '').trim() || null;
    let operatorContext;
    try {
      operatorContext = await resolveOperatorContext({
        requestId: resolvedRequestId,
        accessToken,
        authorizationContext
      });
    } catch (error) {
      const mappedError = mapOperatorContextError(error);
      addAuditEvent({
        type: 'platform.user.soft_delete.rejected',
        requestId: resolvedRequestId,
        operatorUserId: 'unknown',
        targetUserId: requestedUserId,
        detail: 'operator authorization context invalid',
        metadata: {
          previous_status: null,
          current_status: null,
          error_code: mappedError.errorCode
        }
      });
      throw mappedError;
    }
    const { operatorUserId, operatorSessionId } = operatorContext;

    let parsedParams;
    try {
      parsedParams = parseSoftDeleteUserParams(params);
    } catch (error) {
      if (error instanceof AuthProblemError) {
        addAuditEvent({
          type: 'platform.user.soft_delete.rejected',
          requestId: resolvedRequestId,
          operatorUserId,
          targetUserId: requestedUserId,
          detail: 'path parameter validation failed',
          metadata: {
            previous_status: null,
            current_status: null,
            error_code: error.errorCode
          }
        });
      }
      throw error;
    }

    assertAuthServiceMethod('softDeleteUser');
    let softDeleteResult;
    try {
      softDeleteResult = await authService.softDeleteUser({
        requestId: resolvedRequestId,
        traceparent,
        userId: parsedParams.userId,
        operatorUserId,
        operatorSessionId
      });
    } catch (error) {
      const mappedError = (() => {
        if (error instanceof AuthProblemError) {
          if (Number(error.status) === 404) {
            return userErrors.userNotFound();
          }
          return error;
        }
        return userErrors.dependencyUnavailable();
      })();
      const mappedErrorCode = String(mappedError?.errorCode || '').trim();
      addAuditEvent({
        type: 'platform.user.soft_delete.rejected',
        requestId: resolvedRequestId,
        operatorUserId,
        targetUserId: parsedParams.userId,
        detail:
          mappedErrorCode === 'USR-404-USER-NOT-FOUND'
            ? 'target user not found'
            : mappedError === error
              ? 'platform user soft-delete rejected by auth domain'
              : 'platform user soft-delete dependency unavailable',
        metadata: {
          previous_status: null,
          current_status: null,
          error_code: mappedErrorCode || 'USR-503-DEPENDENCY-UNAVAILABLE',
          upstream_error_code: String(error?.errorCode || error?.code || '').trim() || 'unknown'
        }
      });
      throw mappedError;
    }

    if (!softDeleteResult) {
      addAuditEvent({
        type: 'platform.user.soft_delete.rejected',
        requestId: resolvedRequestId,
        operatorUserId,
        targetUserId: parsedParams.userId,
        detail: 'target user not found',
        metadata: {
          previous_status: null,
          current_status: null,
          error_code: 'USR-404-USER-NOT-FOUND'
        }
      });
      throw userErrors.userNotFound();
    }

    const resolvedResultUserId = String(softDeleteResult.user_id || '').trim();
    if (
      !resolvedResultUserId
      || resolvedResultUserId !== parsedParams.userId
    ) {
      addAuditEvent({
        type: 'platform.user.soft_delete.rejected',
        requestId: resolvedRequestId,
        operatorUserId,
        targetUserId: parsedParams.userId,
        detail: 'platform user soft-delete dependency returned mismatched target user',
        metadata: {
          previous_status: null,
          current_status: null,
          error_code: 'AUTH-503-PLATFORM-SNAPSHOT-DEGRADED',
          upstream_error_code: 'PLATFORM-USER-SOFT-DELETE-RESULT-TARGET-MISMATCH',
          upstream_target_user_id: resolvedResultUserId || null
        }
      });
      throw userErrors.platformSnapshotDegraded({
        reason: 'platform-user-soft-delete-target-mismatch'
      });
    }

    const previousStatus = normalizeUserStatus(softDeleteResult.previous_status);
    const currentStatus = normalizeUserStatus(softDeleteResult.current_status);
    const revokedSessionCount = softDeleteResult.revoked_session_count;
    const revokedRefreshTokenCount = softDeleteResult.revoked_refresh_token_count;
    const hasInvalidResult = (
      !VALID_USER_STATUSES.has(previousStatus)
      || !VALID_USER_STATUSES.has(currentStatus)
      || currentStatus !== 'disabled'
      || !Number.isInteger(revokedSessionCount)
      || revokedSessionCount < 0
      || !Number.isInteger(revokedRefreshTokenCount)
      || revokedRefreshTokenCount < 0
    );
    if (hasInvalidResult) {
      addAuditEvent({
        type: 'platform.user.soft_delete.rejected',
        requestId: resolvedRequestId,
        operatorUserId,
        targetUserId: parsedParams.userId,
        detail: 'platform user soft-delete dependency returned invalid state',
        metadata: {
          previous_status: previousStatus || null,
          current_status: currentStatus || null,
          error_code: 'AUTH-503-PLATFORM-SNAPSHOT-DEGRADED',
          upstream_error_code: 'PLATFORM-USER-SOFT-DELETE-RESULT-INVALID'
        }
      });
      throw userErrors.platformSnapshotDegraded({
        reason: 'platform-user-soft-delete-result-invalid'
      });
    }

    const isNoOp = (
      previousStatus === currentStatus
      && revokedSessionCount === 0
      && revokedRefreshTokenCount === 0
    );
    addAuditEvent({
      type: 'platform.user.soft_deleted',
      requestId: resolvedRequestId,
      operatorUserId,
      targetUserId: resolvedResultUserId,
      detail: isNoOp
        ? 'platform user soft-delete treated as no-op'
        : 'platform user soft-deleted and global sessions revoked',
      metadata: {
        previous_status: previousStatus,
        current_status: currentStatus,
        revoked_session_count: revokedSessionCount,
        revoked_refresh_token_count: revokedRefreshTokenCount
      }
    });

    return {
      user_id: resolvedResultUserId,
      previous_status: previousStatus,
      current_status: currentStatus,
      revoked_session_count: revokedSessionCount,
      revoked_refresh_token_count: revokedRefreshTokenCount,
      request_id: resolvedRequestId
    };
  };

  return {
    listUsers,
    getUser,
    createUser,
    updateUser,
    updateUserStatus,
    softDeleteUser,
    _internals: {
      auditTrail,
      authService
    }
  };
};

module.exports = {
  createPlatformUserService
};
