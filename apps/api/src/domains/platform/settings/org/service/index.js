const { randomUUID } = require('node:crypto');
const { log } = require('../../../../../common/logger');
const { AuthProblemError } = require('../../../../../shared-kernel/auth/auth-problem-error');
const {
  resolveRoutePreauthorizedContext
} = require('../../../../../shared-kernel/auth/route-authz');
const {
  PLATFORM_ORG_VIEW_PERMISSION_CODE,
  PLATFORM_ORG_OPERATE_PERMISSION_CODE,
  PLATFORM_ORG_SCOPE
} = require('../constants');

const MYSQL_DUP_ENTRY_ERRNO = 1062;
const MYSQL_DATA_TOO_LONG_ERRNO = 1406;
const OWNER_PHONE_PATTERN = /^1\d{10}$/;
const CONTROL_CHAR_PATTERN = /[\u0000-\u001F\u007F]/;
const WHITESPACE_PATTERN = /\s/;
const MAX_ORG_NAME_LENGTH = 128;
const MAX_ORG_ID_LENGTH = 64;
const MAX_OWNER_NAME_LENGTH = 64;
const MAX_OWNER_PHONE_LENGTH = 32;
const MAX_STATUS_REASON_LENGTH = 256;
const MAX_AUDIT_TRAIL_ENTRIES = 200;
const MAX_ORG_STATUS_CASCADE_COUNT = 100000;
const MAX_QUERY_PAGE_SIZE = 100;
const MAX_QUERY_ORG_NAME_LENGTH = 128;
const MAX_QUERY_OWNER_LENGTH = 64;
const CREATE_ORG_ALLOWED_FIELDS = new Set([
  'org_name',
  'initial_owner_name',
  'initial_owner_phone'
]);
const UPDATE_ORG_STATUS_ALLOWED_FIELDS = new Set(['org_id', 'status', 'reason']);
const OWNER_TRANSFER_ALLOWED_FIELDS = new Set(['org_id', 'new_owner_phone', 'reason']);
const LIST_ORG_ALLOWED_QUERY_FIELDS = new Set([
  'page',
  'page_size',
  'org_name',
  'owner',
  'status',
  'created_at_start',
  'created_at_end'
]);
const VALID_ORG_STATUSES = new Set(['active', 'disabled']);
const MAX_UNKNOWN_PAYLOAD_KEYS_IN_DETAIL = 8;
const MAX_UNKNOWN_PAYLOAD_KEY_LENGTH_IN_DETAIL = 64;
const MAX_UNKNOWN_PAYLOAD_DETAIL_LENGTH = 280;
const OWNER_TRANSFER_ACCEPTED_ERROR_CODE = 'ORG-200-OWNER-TRANSFER-ACCEPTED';

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

const normalizeOrgStatus = (candidate) => {
  const normalized = String(candidate || '').trim().toLowerCase();
  if (normalized === 'enabled') {
    return 'active';
  }
  return normalized;
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

const sanitizeUnknownPayloadKeyForDetail = (key) => {
  const normalized = String(key || '')
    .replace(/[\u0000-\u001F\u007F]+/g, ' ')
    .trim();
  if (!normalized) {
    return '(unknown)';
  }
  if (normalized.length <= MAX_UNKNOWN_PAYLOAD_KEY_LENGTH_IN_DETAIL) {
    return normalized;
  }
  return `${normalized.slice(0, MAX_UNKNOWN_PAYLOAD_KEY_LENGTH_IN_DETAIL)}...`;
};

const formatUnknownPayloadKeysDetail = (unknownPayloadKeys = []) => {
  const sortedUnknownPayloadKeys = [...unknownPayloadKeys].sort();
  const unknownPayloadKeysPreview = sortedUnknownPayloadKeys
    .slice(0, MAX_UNKNOWN_PAYLOAD_KEYS_IN_DETAIL)
    .map((key) => sanitizeUnknownPayloadKeyForDetail(key))
    .join(', ');
  const unknownPayloadKeysSuffix = sortedUnknownPayloadKeys.length
    > MAX_UNKNOWN_PAYLOAD_KEYS_IN_DETAIL
    ? ` 等 ${sortedUnknownPayloadKeys.length} 个字段`
    : '';
  const detail = `包含未支持字段: ${unknownPayloadKeysPreview}${unknownPayloadKeysSuffix}`;
  if (detail.length <= MAX_UNKNOWN_PAYLOAD_DETAIL_LENGTH) {
    return detail;
  }
  return `${detail.slice(0, MAX_UNKNOWN_PAYLOAD_DETAIL_LENGTH - 3)}...`;
};

const isResolvedOperatorIdentifier = (value) => {
  const normalized = String(value || '').trim();
  return normalized.length > 0 && normalized.toLowerCase() !== 'unknown';
};

const resolveAuthorizedOperatorContext = ({
  authorizationContext = null,
  expectedPermissionCode = PLATFORM_ORG_OPERATE_PERMISSION_CODE
} = {}) => {
  const preauthorizedContext = resolveRoutePreauthorizedContext({
    authorizationContext,
    expectedPermissionCode,
    expectedScope: PLATFORM_ORG_SCOPE,
    expectedEntryDomain: PLATFORM_ORG_SCOPE
  });
  if (!preauthorizedContext) {
    return null;
  }
  return {
    operatorUserId: preauthorizedContext.userId,
    operatorSessionId: preauthorizedContext.sessionId
  };
};

const isDuplicateEntryError = (error) =>
  String(error?.code || '').trim().toUpperCase() === 'ER_DUP_ENTRY'
  || Number(error?.errno || 0) === MYSQL_DUP_ENTRY_ERRNO;

const isDataTooLongError = (error) =>
  String(error?.code || '').trim().toUpperCase() === 'ER_DATA_TOO_LONG'
  || Number(error?.errno || 0) === MYSQL_DATA_TOO_LONG_ERRNO;

const orgProblem = ({ status, title, detail, errorCode, extensions = {} }) =>
  new AuthProblemError({
    status,
    title,
    detail,
    errorCode,
    extensions
  });

const toOwnerTransferContractExtensions = ({
  orgId = null,
  oldOwnerUserId = null,
  newOwnerUserId = null,
  resultStatus = 'rejected',
  retryable = false
} = {}) => ({
  retryable: Boolean(retryable),
  org_id: orgId ? String(orgId).trim() : null,
  old_owner_user_id: oldOwnerUserId ? String(oldOwnerUserId).trim() : null,
  new_owner_user_id: newOwnerUserId ? String(newOwnerUserId).trim() : null,
  result_status: String(resultStatus || 'rejected').trim() || 'rejected'
});

const withOwnerTransferContractProblem = ({
  problem,
  orgId = null,
  oldOwnerUserId = null,
  newOwnerUserId = null,
  resultStatus = null,
  retryable = null
} = {}) => {
  if (!(problem instanceof AuthProblemError)) {
    return orgProblem({
      status: 503,
      title: 'Service Unavailable',
      detail: '组织治理依赖暂不可用，请稍后重试',
      errorCode: 'ORG-503-DEPENDENCY-UNAVAILABLE',
      extensions: toOwnerTransferContractExtensions({
        orgId,
        oldOwnerUserId,
        newOwnerUserId,
        resultStatus: resultStatus || 'rejected',
        retryable: retryable === null || retryable === undefined ? true : retryable
      })
    });
  }

  const baseExtensions = isPlainObject(problem.extensions) ? problem.extensions : {};
  return orgProblem({
    status: Number(problem.status) || 503,
    title: String(problem.title || 'Service Unavailable'),
    detail: String(problem.detail || '组织治理依赖暂不可用，请稍后重试'),
    errorCode:
      String(problem.errorCode || 'ORG-503-DEPENDENCY-UNAVAILABLE').trim()
      || 'ORG-503-DEPENDENCY-UNAVAILABLE',
    extensions: {
      ...baseExtensions,
      ...toOwnerTransferContractExtensions({
        orgId: baseExtensions.org_id ?? orgId,
        oldOwnerUserId: baseExtensions.old_owner_user_id ?? oldOwnerUserId,
        newOwnerUserId: baseExtensions.new_owner_user_id ?? newOwnerUserId,
        resultStatus: baseExtensions.result_status ?? resultStatus ?? 'rejected',
        retryable: retryable ?? baseExtensions.retryable ?? false
      })
    }
  });
};

const orgErrors = {
  invalidPayload: (detail = '请求参数不完整或格式错误') =>
    orgProblem({
      status: 400,
      title: 'Bad Request',
      detail,
      errorCode: 'ORG-400-INVALID-PAYLOAD'
    }),

  initialOwnerPhoneRequired: () =>
    orgProblem({
      status: 400,
      title: 'Bad Request',
      detail: '创建组织必须提供 initial_owner_phone',
      errorCode: 'ORG-400-INITIAL-OWNER-PHONE-REQUIRED'
    }),

  initialOwnerNameRequired: () =>
    orgProblem({
      status: 400,
      title: 'Bad Request',
      detail: '创建组织必须提供 initial_owner_name',
      errorCode: 'ORG-400-INITIAL-OWNER-NAME-REQUIRED'
    }),

  forbidden: () =>
    orgProblem({
      status: 403,
      title: 'Forbidden',
      detail: '当前操作无权限',
      errorCode: 'AUTH-403-FORBIDDEN'
    }),

  orgConflict: () =>
    orgProblem({
      status: 409,
      title: 'Conflict',
      detail: '组织名称已存在，请重新输入',
      errorCode: 'ORG-409-ORG-CONFLICT',
      extensions: {
        retryable: false
      }
    }),

  orgNotFound: () =>
    orgProblem({
      status: 404,
      title: 'Not Found',
      detail: '目标组织不存在',
      errorCode: 'ORG-404-ORG-NOT-FOUND',
      extensions: {
        retryable: false
      }
    }),

  ownerTransferOrgNotActive: ({
    orgId = null,
    oldOwnerUserId = null,
    newOwnerUserId = null
  } = {}) =>
    orgProblem({
      status: 409,
      title: 'Conflict',
      detail: '目标组织当前不可发起负责人变更，请先启用后重试',
      errorCode: 'ORG-409-ORG-NOT-ACTIVE',
      extensions: toOwnerTransferContractExtensions({
        orgId,
        oldOwnerUserId,
        newOwnerUserId,
        resultStatus: 'rejected',
        retryable: false
      })
    }),

  ownerTransferNewOwnerNotFound: ({
    orgId = null,
    oldOwnerUserId = null
  } = {}) =>
    orgProblem({
      status: 404,
      title: 'Not Found',
      detail: '候选新负责人不存在',
      errorCode: 'ORG-404-NEW-OWNER-NOT-FOUND',
      extensions: toOwnerTransferContractExtensions({
        orgId,
        oldOwnerUserId,
        newOwnerUserId: null,
        resultStatus: 'rejected',
        retryable: false
      })
    }),

  ownerTransferNewOwnerInactive: ({
    orgId = null,
    oldOwnerUserId = null,
    newOwnerUserId = null
  } = {}) =>
    orgProblem({
      status: 409,
      title: 'Conflict',
      detail: '候选新负责人状态不可用，请确认激活后重试',
      errorCode: 'ORG-409-NEW-OWNER-INACTIVE',
      extensions: toOwnerTransferContractExtensions({
        orgId,
        oldOwnerUserId,
        newOwnerUserId,
        resultStatus: 'rejected',
        retryable: false
      })
    }),

  ownerTransferSameOwner: ({
    orgId = null,
    oldOwnerUserId = null
  } = {}) =>
    orgProblem({
      status: 409,
      title: 'Conflict',
      detail: '新负责人不能与当前负责人相同',
      errorCode: 'ORG-409-OWNER-TRANSFER-SAME-OWNER',
      extensions: toOwnerTransferContractExtensions({
        orgId,
        oldOwnerUserId,
        newOwnerUserId: oldOwnerUserId,
        resultStatus: 'rejected',
        retryable: false
      })
    }),

  ownerTransferConflict: ({
    orgId = null,
    oldOwnerUserId = null,
    newOwnerUserId = null
  } = {}) =>
    orgProblem({
      status: 409,
      title: 'Conflict',
      detail: 'sys_admin 变更请求处理中，请稍后重试',
      errorCode: 'ORG-409-OWNER-TRANSFER-CONFLICT',
      extensions: toOwnerTransferContractExtensions({
        orgId,
        oldOwnerUserId,
        newOwnerUserId,
        resultStatus: 'conflict',
        retryable: true
      })
    }),

  dependencyUnavailable: () =>
    orgProblem({
      status: 503,
      title: 'Service Unavailable',
      detail: '组织治理依赖暂不可用，请稍后重试',
      errorCode: 'ORG-503-DEPENDENCY-UNAVAILABLE',
      extensions: {
        retryable: true
      }
    })
};

const parseCreateOrgPayload = (payload) => {
  if (!isPlainObject(payload)) {
    throw orgErrors.invalidPayload();
  }

  const unknownPayloadKeys = Object.keys(payload).filter(
    (key) => !CREATE_ORG_ALLOWED_FIELDS.has(key)
  );
  if (unknownPayloadKeys.length > 0) {
    throw orgErrors.invalidPayload(formatUnknownPayloadKeysDetail(unknownPayloadKeys));
  }

  const hasOrgName = Object.prototype.hasOwnProperty.call(payload, 'org_name');
  const hasInitialOwnerName = Object.prototype.hasOwnProperty.call(
    payload,
    'initial_owner_name'
  );
  const hasInitialOwnerPhone = Object.prototype.hasOwnProperty.call(
    payload,
    'initial_owner_phone'
  );

  if (!hasInitialOwnerPhone) {
    throw orgErrors.initialOwnerPhoneRequired();
  }
  if (!hasOrgName) {
    throw orgErrors.invalidPayload('创建组织必须提供 org_name');
  }
  if (!hasInitialOwnerName) {
    throw orgErrors.initialOwnerNameRequired();
  }

  if (typeof payload.org_name !== 'string') {
    throw orgErrors.invalidPayload('org_name 必须为字符串');
  }
  if (typeof payload.initial_owner_name !== 'string') {
    throw orgErrors.invalidPayload('initial_owner_name 必须为字符串');
  }
  if (typeof payload.initial_owner_phone !== 'string') {
    throw orgErrors.invalidPayload('initial_owner_phone 格式错误');
  }

  const orgName = normalizeRequiredString(payload.org_name);
  const ownerName = normalizeRequiredString(payload.initial_owner_name);
  const ownerPhoneInput = payload.initial_owner_phone;
  const ownerPhoneRaw = normalizeRequiredString(ownerPhoneInput);

  if (!ownerPhoneRaw) {
    throw orgErrors.initialOwnerPhoneRequired();
  }
  if (ownerPhoneInput !== ownerPhoneRaw) {
    throw orgErrors.invalidPayload('initial_owner_phone 格式错误');
  }
  if (!orgName) {
    throw orgErrors.invalidPayload('创建组织必须提供 org_name');
  }
  if (!ownerName) {
    throw orgErrors.initialOwnerNameRequired();
  }
  if (CONTROL_CHAR_PATTERN.test(orgName)) {
    throw orgErrors.invalidPayload('org_name 不能包含控制字符');
  }
  if (CONTROL_CHAR_PATTERN.test(ownerName)) {
    throw orgErrors.invalidPayload('initial_owner_name 不能包含控制字符');
  }
  if (orgName.length > MAX_ORG_NAME_LENGTH) {
    throw orgErrors.invalidPayload(`org_name 长度不能超过 ${MAX_ORG_NAME_LENGTH}`);
  }
  if (ownerName.length > MAX_OWNER_NAME_LENGTH) {
    throw orgErrors.invalidPayload(
      `initial_owner_name 长度不能超过 ${MAX_OWNER_NAME_LENGTH}`
    );
  }
  if (!OWNER_PHONE_PATTERN.test(ownerPhoneRaw)) {
    throw orgErrors.invalidPayload('initial_owner_phone 格式错误');
  }

  return {
    orgName,
    ownerName,
    ownerPhone: ownerPhoneRaw
  };
};

const parseUpdateOrgStatusPayload = (payload) => {
  if (!isPlainObject(payload)) {
    throw orgErrors.invalidPayload();
  }

  const unknownPayloadKeys = Object.keys(payload).filter(
    (key) => !UPDATE_ORG_STATUS_ALLOWED_FIELDS.has(key)
  );
  if (unknownPayloadKeys.length > 0) {
    throw orgErrors.invalidPayload(formatUnknownPayloadKeysDetail(unknownPayloadKeys));
  }

  const hasOrgId = Object.prototype.hasOwnProperty.call(payload, 'org_id');
  const hasStatus = Object.prototype.hasOwnProperty.call(payload, 'status');
  if (!hasOrgId || !hasStatus) {
    throw orgErrors.invalidPayload();
  }

  if (typeof payload.org_id !== 'string') {
    throw orgErrors.invalidPayload('org_id 必须为字符串');
  }
  if (typeof payload.status !== 'string') {
    throw orgErrors.invalidPayload('status 必须为字符串');
  }

  const orgId = normalizeRequiredString(payload.org_id);
  const nextStatus = normalizeRequiredString(payload.status).toLowerCase();
  if (!orgId) {
    throw orgErrors.invalidPayload('org_id 不能为空');
  }
  if (!VALID_ORG_STATUSES.has(nextStatus)) {
    throw orgErrors.invalidPayload('status 必须为 active 或 disabled');
  }

  let reason = null;
  if (Object.prototype.hasOwnProperty.call(payload, 'reason')) {
    if (typeof payload.reason !== 'string') {
      throw orgErrors.invalidPayload('reason 必须为字符串');
    }
    const normalizedReason = normalizeRequiredString(payload.reason);
    if (!normalizedReason) {
      throw orgErrors.invalidPayload('reason 不能为空字符串');
    }
    if (CONTROL_CHAR_PATTERN.test(normalizedReason)) {
      throw orgErrors.invalidPayload('reason 不能包含控制字符');
    }
    if (normalizedReason.length > MAX_STATUS_REASON_LENGTH) {
      throw orgErrors.invalidPayload(
        `reason 长度不能超过 ${MAX_STATUS_REASON_LENGTH}`
      );
    }
    reason = normalizedReason;
  }

  return {
    orgId,
    nextStatus,
    reason
  };
};

const parseOwnerTransferPayload = (payload) => {
  if (!isPlainObject(payload)) {
    throw orgErrors.invalidPayload();
  }

  const unknownPayloadKeys = Object.keys(payload).filter(
    (key) => !OWNER_TRANSFER_ALLOWED_FIELDS.has(key)
  );
  if (unknownPayloadKeys.length > 0) {
    throw orgErrors.invalidPayload(formatUnknownPayloadKeysDetail(unknownPayloadKeys));
  }

  const hasOrgId = Object.prototype.hasOwnProperty.call(payload, 'org_id');
  const hasNewOwnerPhone = Object.prototype.hasOwnProperty.call(
    payload,
    'new_owner_phone'
  );
  if (!hasOrgId || !hasNewOwnerPhone) {
    throw orgErrors.invalidPayload();
  }

  if (typeof payload.org_id !== 'string') {
    throw orgErrors.invalidPayload('org_id 必须为字符串');
  }
  if (typeof payload.new_owner_phone !== 'string') {
    throw orgErrors.invalidPayload('new_owner_phone 格式错误');
  }

  const orgIdRaw = payload.org_id;
  const orgId = normalizeRequiredString(orgIdRaw);
  const newOwnerPhoneInput = payload.new_owner_phone;
  const newOwnerPhone = normalizeRequiredString(newOwnerPhoneInput);
  if (!orgId) {
    throw orgErrors.invalidPayload('org_id 不能为空');
  }
  if (orgIdRaw !== orgId) {
    throw orgErrors.invalidPayload('org_id 不能包含前后空白');
  }
  if (CONTROL_CHAR_PATTERN.test(orgId)) {
    throw orgErrors.invalidPayload('org_id 不能包含控制字符');
  }
  if (WHITESPACE_PATTERN.test(orgId)) {
    throw orgErrors.invalidPayload('org_id 不能包含空白字符');
  }
  if (orgId.length > MAX_ORG_ID_LENGTH) {
    throw orgErrors.invalidPayload(`org_id 长度不能超过 ${MAX_ORG_ID_LENGTH}`);
  }
  if (!newOwnerPhone) {
    throw orgErrors.invalidPayload('new_owner_phone 格式错误');
  }
  if (newOwnerPhoneInput !== newOwnerPhone) {
    throw orgErrors.invalidPayload('new_owner_phone 格式错误');
  }
  if (!OWNER_PHONE_PATTERN.test(newOwnerPhone)) {
    throw orgErrors.invalidPayload('new_owner_phone 格式错误');
  }

  let reason = null;
  if (Object.prototype.hasOwnProperty.call(payload, 'reason')) {
    if (typeof payload.reason !== 'string') {
      throw orgErrors.invalidPayload('reason 必须为字符串');
    }
    const reasonInput = payload.reason;
    const normalizedReason = normalizeRequiredString(reasonInput);
    if (!normalizedReason) {
      throw orgErrors.invalidPayload('reason 不能为空字符串');
    }
    if (reasonInput !== normalizedReason) {
      throw orgErrors.invalidPayload('reason 不能包含前后空白');
    }
    if (CONTROL_CHAR_PATTERN.test(normalizedReason)) {
      throw orgErrors.invalidPayload('reason 不能包含控制字符');
    }
    if (normalizedReason.length > MAX_STATUS_REASON_LENGTH) {
      throw orgErrors.invalidPayload(
        `reason 长度不能超过 ${MAX_STATUS_REASON_LENGTH}`
      );
    }
    reason = normalizedReason;
  }

  return {
    orgId,
    newOwnerPhone,
    reason
  };
};

const resolveRequestedOwnerTransferOrgId = (payload = {}) => {
  if (!isPlainObject(payload) || typeof payload.org_id !== 'string') {
    return null;
  }
  const orgIdRaw = payload.org_id;
  const normalizedOrgId = orgIdRaw.trim();
  if (
    !normalizedOrgId
    || normalizedOrgId !== orgIdRaw
    || normalizedOrgId.length > MAX_ORG_ID_LENGTH
    || WHITESPACE_PATTERN.test(normalizedOrgId)
    || CONTROL_CHAR_PATTERN.test(normalizedOrgId)
  ) {
    return null;
  }
  return normalizedOrgId;
};

const toNormalizedOrgStatusCascadeCount = ({
  value,
  field
} = {}) => {
  if (value === null || value === undefined) {
    return 0;
  }
  if (
    typeof value !== 'number'
    || !Number.isInteger(value)
    || value < 0
  ) {
    const error = new Error('org status cascade count invalid');
    error.code = 'ORG-STATUS-CASCADE-COUNT-INVALID';
    error.field = String(field || '').trim() || 'unknown';
    throw error;
  }
  return Math.min(value, MAX_ORG_STATUS_CASCADE_COUNT);
};

const parseStrictPositiveInteger = ({
  value,
  field,
  max = Number.MAX_SAFE_INTEGER
}) => {
  const normalizedRaw = String(value ?? '').trim();
  if (!/^\d+$/.test(normalizedRaw)) {
    throw orgErrors.invalidPayload(`${field} 必须为正整数`);
  }
  const parsed = Number(normalizedRaw);
  if (
    !Number.isInteger(parsed)
    || parsed <= 0
    || parsed > max
  ) {
    throw orgErrors.invalidPayload(`${field} 必须为正整数`);
  }
  return parsed;
};

const parseListOrgQuery = (query) => {
  if (!isPlainObject(query)) {
    throw orgErrors.invalidPayload();
  }
  const unknownQueryKeys = Object.keys(query).filter(
    (key) => !LIST_ORG_ALLOWED_QUERY_FIELDS.has(key)
  );
  if (unknownQueryKeys.length > 0) {
    throw orgErrors.invalidPayload('请求参数不完整或格式错误');
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

  let orgName = null;
  if (Object.prototype.hasOwnProperty.call(query, 'org_name')) {
    if (typeof query.org_name !== 'string') {
      throw orgErrors.invalidPayload('org_name 必须为字符串');
    }
    const normalizedOrgName = query.org_name.trim();
    if (CONTROL_CHAR_PATTERN.test(normalizedOrgName)) {
      throw orgErrors.invalidPayload('org_name 不能包含控制字符');
    }
    if (normalizedOrgName.length > MAX_QUERY_ORG_NAME_LENGTH) {
      throw orgErrors.invalidPayload(
        `org_name 长度不能超过 ${MAX_QUERY_ORG_NAME_LENGTH}`
      );
    }
    orgName = normalizedOrgName || null;
  }

  let owner = null;
  if (Object.prototype.hasOwnProperty.call(query, 'owner')) {
    if (typeof query.owner !== 'string') {
      throw orgErrors.invalidPayload('owner 必须为字符串');
    }
    const normalizedOwner = query.owner.trim();
    if (CONTROL_CHAR_PATTERN.test(normalizedOwner)) {
      throw orgErrors.invalidPayload('owner 不能包含控制字符');
    }
    if (normalizedOwner.length > MAX_QUERY_OWNER_LENGTH) {
      throw orgErrors.invalidPayload(
        `owner 长度不能超过 ${MAX_QUERY_OWNER_LENGTH}`
      );
    }
    owner = normalizedOwner || null;
  }

  let status = null;
  if (Object.prototype.hasOwnProperty.call(query, 'status')) {
    if (typeof query.status !== 'string') {
      throw orgErrors.invalidPayload('status 必须为 active 或 disabled');
    }
    const normalizedStatus = normalizeOrgStatus(query.status);
    if (!VALID_ORG_STATUSES.has(normalizedStatus)) {
      throw orgErrors.invalidPayload('status 必须为 active 或 disabled');
    }
    status = normalizedStatus;
  }

  let createdAtStart = null;
  if (Object.prototype.hasOwnProperty.call(query, 'created_at_start')) {
    if (typeof query.created_at_start !== 'string') {
      throw orgErrors.invalidPayload('created_at_start 必须为字符串');
    }
    const normalizedCreatedAtStart = query.created_at_start.trim();
    if (normalizedCreatedAtStart) {
      const parsedCreatedAtStart = toIsoTimestamp(normalizedCreatedAtStart);
      if (!parsedCreatedAtStart) {
        throw orgErrors.invalidPayload('created_at_start 必须为合法时间');
      }
      createdAtStart = parsedCreatedAtStart;
    }
  }

  let createdAtEnd = null;
  if (Object.prototype.hasOwnProperty.call(query, 'created_at_end')) {
    if (typeof query.created_at_end !== 'string') {
      throw orgErrors.invalidPayload('created_at_end 必须为字符串');
    }
    const normalizedCreatedAtEnd = query.created_at_end.trim();
    if (normalizedCreatedAtEnd) {
      const parsedCreatedAtEnd = toIsoTimestamp(normalizedCreatedAtEnd);
      if (!parsedCreatedAtEnd) {
        throw orgErrors.invalidPayload('created_at_end 必须为合法时间');
      }
      createdAtEnd = parsedCreatedAtEnd;
    }
  }

  if (
    createdAtStart
    && createdAtEnd
    && new Date(createdAtStart).getTime() > new Date(createdAtEnd).getTime()
  ) {
    throw orgErrors.invalidPayload('created_at_start 不能晚于 created_at_end');
  }

  return {
    page,
    pageSize,
    orgName,
    owner,
    status,
    createdAtStart,
    createdAtEnd
  };
};

const normalizeOrgListItem = (candidate) => {
  if (!isPlainObject(candidate)) {
    throw orgErrors.dependencyUnavailable();
  }

  const orgId = normalizeRequiredString(candidate.org_id ?? candidate.orgId);
  const orgName = normalizeRequiredString(candidate.org_name ?? candidate.orgName);
  const ownerName = normalizeOptionalString(
    candidate.owner_name
      ?? candidate.ownerName
      ?? candidate.display_name
      ?? candidate.displayName
  );
  const ownerPhone = normalizeRequiredString(
    candidate.owner_phone
      ?? candidate.ownerPhone
      ?? candidate.phone
  );
  const status = normalizeOrgStatus(candidate.status);
  const createdAt = toIsoTimestamp(
    candidate.created_at ?? candidate.createdAt
  );

  if (
    !orgId
    || orgId.length > MAX_ORG_ID_LENGTH
    || CONTROL_CHAR_PATTERN.test(orgId)
    || WHITESPACE_PATTERN.test(orgId)
  ) {
    throw orgErrors.dependencyUnavailable();
  }
  if (
    !orgName
    || orgName.length > MAX_ORG_NAME_LENGTH
    || CONTROL_CHAR_PATTERN.test(orgName)
  ) {
    throw orgErrors.dependencyUnavailable();
  }
  if (
    ownerName !== null
    && (
      ownerName.length > MAX_OWNER_NAME_LENGTH
      || CONTROL_CHAR_PATTERN.test(ownerName)
    )
  ) {
    throw orgErrors.dependencyUnavailable();
  }
  if (
    !ownerPhone
    || ownerPhone.length > MAX_OWNER_PHONE_LENGTH
    || CONTROL_CHAR_PATTERN.test(ownerPhone)
  ) {
    throw orgErrors.dependencyUnavailable();
  }
  if (!VALID_ORG_STATUSES.has(status)) {
    throw orgErrors.dependencyUnavailable();
  }
  if (!createdAt) {
    throw orgErrors.dependencyUnavailable();
  }

  return {
    org_id: orgId,
    org_name: orgName,
    owner_name: ownerName,
    owner_phone: ownerPhone,
    status,
    created_at: createdAt
  };
};

const createPlatformOrgService = ({ authService } = {}) => {
  const auditTrail = [];
  const ownerTransferLocksByOrgId = new Map();
  const hasExternalOwnerTransferLockAcquire =
    authService && typeof authService.acquireOwnerTransferLock === 'function';
  const hasExternalOwnerTransferLockRelease =
    authService && typeof authService.releaseOwnerTransferLock === 'function';
  const useExternalOwnerTransferLockBackend =
    hasExternalOwnerTransferLockAcquire && hasExternalOwnerTransferLockRelease;

  if (
    authService
    && hasExternalOwnerTransferLockAcquire !== hasExternalOwnerTransferLockRelease
  ) {
    log(
      'warn',
      'Owner transfer lock backend partially configured; falling back to in-process lock backend',
      {
        has_acquire_owner_transfer_lock: hasExternalOwnerTransferLockAcquire,
        has_release_owner_transfer_lock: hasExternalOwnerTransferLockRelease
      }
    );
  }

  const addAuditEvent = ({
    type,
    requestId,
    operatorUserId = 'unknown',
    orgId = null,
    detail,
    metadata = {}
  }) => {
    const event = {
      type: String(type || '').trim() || 'org.unknown',
      at: new Date().toISOString(),
      request_id: String(requestId || '').trim() || 'request_id_unset',
      operator_user_id: String(operatorUserId || '').trim() || 'unknown',
      org_id: orgId ? String(orgId) : null,
      detail: String(detail || '').trim(),
      ...metadata
    };
    auditTrail.push(event);
    if (auditTrail.length > MAX_AUDIT_TRAIL_ENTRIES) {
      auditTrail.splice(0, auditTrail.length - MAX_AUDIT_TRAIL_ENTRIES);
    }
    log('info', 'Platform org audit event', event);
  };

  const assertAuthServiceMethod = (methodName) => {
    if (!authService || typeof authService[methodName] !== 'function') {
      throw orgErrors.dependencyUnavailable();
    }
  };

  const resolveAuthStore = () => authService?._internals?.authStore || null;

  const assertAuthStoreMethod = (methodName) => {
    const authStore = resolveAuthStore();
    if (!authStore || typeof authStore[methodName] !== 'function') {
      throw orgErrors.dependencyUnavailable();
    }
    return authStore;
  };

  const acquireOwnerTransferLock = async ({
    orgId,
    requestId,
    operatorUserId
  }) => {
    const normalizedOrgId = String(orgId || '').trim();
    if (!normalizedOrgId) {
      return false;
    }
    if (useExternalOwnerTransferLockBackend) {
      return (
        await authService.acquireOwnerTransferLock({
          orgId: normalizedOrgId,
          requestId,
          operatorUserId,
          timeoutSeconds: 0
        })
      ) === true;
    }
    if (ownerTransferLocksByOrgId.has(normalizedOrgId)) {
      return false;
    }
    ownerTransferLocksByOrgId.set(normalizedOrgId, {
      request_id: String(requestId || '').trim() || 'request_id_unset',
      operator_user_id: String(operatorUserId || '').trim() || 'unknown',
      started_at: new Date().toISOString()
    });
    return true;
  };

  const releaseOwnerTransferLock = async (orgId) => {
    const normalizedOrgId = String(orgId || '').trim();
    if (!normalizedOrgId) {
      return false;
    }
    if (useExternalOwnerTransferLockBackend) {
      return (
        await authService.releaseOwnerTransferLock({
          orgId: normalizedOrgId
        })
      ) === true;
    }
    return ownerTransferLocksByOrgId.delete(normalizedOrgId);
  };

  const mapOwnerTransferValidationProblem = ({
    error,
    orgId = null,
    oldOwnerUserId = null,
    newOwnerUserId = null
  } = {}) => {
    const errorExtensions = isPlainObject(error?.extensions) ? error.extensions : {};
    const resolvedOrgId = errorExtensions.org_id ?? orgId;
    const resolvedOldOwnerUserId =
      errorExtensions.old_owner_user_id ?? oldOwnerUserId;
    const resolvedNewOwnerUserId =
      errorExtensions.new_owner_user_id ?? newOwnerUserId;
    let mappedProblem = null;
    if (error instanceof AuthProblemError) {
      const normalizedErrorCode = String(error.errorCode || '').trim();
      if (normalizedErrorCode === 'AUTH-400-INVALID-PAYLOAD') {
        mappedProblem = orgErrors.invalidPayload();
      } else if (normalizedErrorCode === 'AUTH-404-ORG-NOT-FOUND') {
        mappedProblem = orgErrors.orgNotFound();
      } else if (normalizedErrorCode === 'AUTH-404-USER-NOT-FOUND') {
        mappedProblem = orgErrors.ownerTransferNewOwnerNotFound({
          orgId: resolvedOrgId,
          oldOwnerUserId: resolvedOldOwnerUserId
        });
      } else if (normalizedErrorCode === 'AUTH-409-ORG-NOT-ACTIVE') {
        mappedProblem = orgErrors.ownerTransferOrgNotActive({
          orgId: resolvedOrgId,
          oldOwnerUserId: resolvedOldOwnerUserId,
          newOwnerUserId: resolvedNewOwnerUserId
        });
      } else if (
        normalizedErrorCode === 'AUTH-409-OWNER-TRANSFER-TARGET-USER-INACTIVE'
      ) {
        mappedProblem = orgErrors.ownerTransferNewOwnerInactive({
          orgId: resolvedOrgId,
          oldOwnerUserId: resolvedOldOwnerUserId,
          newOwnerUserId: resolvedNewOwnerUserId
        });
      } else if (normalizedErrorCode === 'AUTH-409-OWNER-TRANSFER-SAME-OWNER') {
        mappedProblem = orgErrors.ownerTransferSameOwner({
          orgId: resolvedOrgId,
          oldOwnerUserId: resolvedOldOwnerUserId
        });
      } else if (normalizedErrorCode === 'AUTH-409-OWNER-TRANSFER-CONFLICT') {
        mappedProblem = orgErrors.ownerTransferConflict({
          orgId: resolvedOrgId,
          oldOwnerUserId: resolvedOldOwnerUserId,
          newOwnerUserId: resolvedNewOwnerUserId
        });
      }
    }

    const fallbackProblem = mappedProblem || orgErrors.dependencyUnavailable();
    const fallbackErrorCode = String(fallbackProblem.errorCode || '').trim();
    return withOwnerTransferContractProblem({
      problem: fallbackProblem,
      orgId: resolvedOrgId,
      oldOwnerUserId: resolvedOldOwnerUserId,
      newOwnerUserId: resolvedNewOwnerUserId,
      resultStatus:
        fallbackErrorCode === 'ORG-409-OWNER-TRANSFER-CONFLICT'
          ? 'conflict'
          : 'rejected'
    });
  };

  const mapOwnerIdentityBootstrapProblem = (error) => {
    if (!(error instanceof AuthProblemError)) {
      return null;
    }
    const normalizedStatus = Number(error.status);
    if (normalizedStatus === 409) {
      return orgErrors.orgConflict();
    }
    if (normalizedStatus === 503) {
      const fallbackDependencyProblem = orgErrors.dependencyUnavailable();
      const resolvedDetail = String(error.detail || '').trim();
      const upstreamExtensions = isPlainObject(error.extensions) ? error.extensions : {};
      const retryable = typeof upstreamExtensions.retryable === 'boolean'
        ? upstreamExtensions.retryable
        : true;
      return orgProblem({
        status: 503,
        title: String(error.title || fallbackDependencyProblem.title),
        detail: resolvedDetail || fallbackDependencyProblem.detail,
        errorCode: fallbackDependencyProblem.errorCode,
        extensions: {
          retryable
        }
      });
    }
    return orgErrors.dependencyUnavailable();
  };

  const rollbackOwnerIdentityIfNeeded = async ({
    requestId,
    operatorUserId,
    ownerIdentity,
    reason = 'unknown'
  }) => {
    if (!ownerIdentity || ownerIdentity.created_user !== true) {
      return true;
    }
    const ownerUserId = String(ownerIdentity.user_id || '').trim();
    if (!ownerUserId) {
      return true;
    }

    try {
      await authService.rollbackProvisionedUserIdentity({
        requestId,
        userId: ownerUserId
      });
      return true;
    } catch (rollbackError) {
      log(
        'warn',
        'Failed to rollback newly created owner identity after org creation failure',
        {
          request_id: String(requestId || '').trim() || 'request_id_unset',
          operator_user_id: String(operatorUserId || '').trim() || 'unknown',
          owner_user_id: ownerUserId,
          reason: String(reason || '').trim() || 'unknown',
          rollback_error: String(rollbackError?.message || 'unknown')
        }
      );
      return false;
    }
  };

  const resolveOperatorContext = async ({
    requestId,
    accessToken,
    authorizationContext = null,
    expectedPermissionCode = PLATFORM_ORG_OPERATE_PERMISSION_CODE
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
        scope: PLATFORM_ORG_SCOPE,
        authorizationContext
      });
      operatorUserId =
        String(authorized?.user_id || '').trim() || 'unknown';
      operatorSessionId =
        String(authorized?.session_id || '').trim() || 'unknown';
    }
    if (
      !isResolvedOperatorIdentifier(operatorUserId)
      || !isResolvedOperatorIdentifier(operatorSessionId)
    ) {
      throw orgErrors.forbidden();
    }
    return {
      operatorUserId,
      operatorSessionId
    };
  };

  const listOrgs = async ({
    requestId,
    accessToken,
    query = {},
    authorizationContext = null
  }) => {
    const resolvedRequestId = String(requestId || '').trim() || 'request_id_unset';
    let parsedQuery;
    try {
      parsedQuery = parseListOrgQuery(query);
    } catch (error) {
      addAuditEvent({
        type: 'org.list.rejected',
        requestId: resolvedRequestId,
        operatorUserId: 'unknown',
        detail: 'query validation failed',
        metadata: {
          error_code: error?.errorCode || orgErrors.invalidPayload().errorCode
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
        expectedPermissionCode: PLATFORM_ORG_VIEW_PERMISSION_CODE
      });
    } catch (error) {
      const mappedError =
        error instanceof AuthProblemError ? error : orgErrors.forbidden();
      addAuditEvent({
        type: 'org.list.rejected',
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
      const authStore = assertAuthStoreMethod('listPlatformOrgs');
      result = await authStore.listPlatformOrgs({
        page: parsedQuery.page,
        pageSize: parsedQuery.pageSize,
        orgName: parsedQuery.orgName,
        owner: parsedQuery.owner,
        status: parsedQuery.status,
        createdAtStart: parsedQuery.createdAtStart,
        createdAtEnd: parsedQuery.createdAtEnd
      });
    } catch (error) {
      if (error instanceof AuthProblemError) {
        addAuditEvent({
          type: 'org.list.rejected',
          requestId: resolvedRequestId,
          operatorUserId,
          detail: 'organization list dependency rejected',
          metadata: {
            error_code: error.errorCode
          }
        });
        throw error;
      }
      addAuditEvent({
        type: 'org.list.rejected',
        requestId: resolvedRequestId,
        operatorUserId,
        detail: 'organization list dependency unavailable',
        metadata: {
          error_code: 'ORG-503-DEPENDENCY-UNAVAILABLE'
        }
      });
      throw orgErrors.dependencyUnavailable();
    }

    const total = Number(result?.total);
    if (!Array.isArray(result?.items) || !Number.isInteger(total) || total < 0) {
      addAuditEvent({
        type: 'org.list.rejected',
        requestId: resolvedRequestId,
        operatorUserId,
        detail: 'organization list dependency returned invalid payload',
        metadata: {
          error_code: 'ORG-503-DEPENDENCY-UNAVAILABLE',
          upstream_error_code: 'ORG-LIST-RESULT-INVALID'
        }
      });
      throw orgErrors.dependencyUnavailable();
    }

    let items;
    try {
      items = result.items.map((item) => normalizeOrgListItem(item));
    } catch (_error) {
      addAuditEvent({
        type: 'org.list.rejected',
        requestId: resolvedRequestId,
        operatorUserId,
        detail: 'organization list dependency returned invalid item schema',
        metadata: {
          error_code: 'ORG-503-DEPENDENCY-UNAVAILABLE',
          upstream_error_code: 'ORG-LIST-ITEM-INVALID'
        }
      });
      throw orgErrors.dependencyUnavailable();
    }

    addAuditEvent({
      type: 'org.listed',
      requestId: resolvedRequestId,
      operatorUserId,
      detail: 'organizations listed',
      metadata: {
        total,
        page: parsedQuery.page,
        page_size: parsedQuery.pageSize,
        result_count: items.length,
        org_name: parsedQuery.orgName,
        owner: parsedQuery.owner,
        status: parsedQuery.status,
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

  const createOrg = async ({
    requestId,
    accessToken,
    payload = {},
    traceparent = null,
    authorizationContext = null
  }) => {
    const resolvedRequestId = String(requestId || '').trim() || 'request_id_unset';
    let operatorContext;
    try {
      operatorContext = await resolveOperatorContext({
        requestId: resolvedRequestId,
        accessToken,
        authorizationContext
      });
    } catch (error) {
      const mappedError =
        error instanceof AuthProblemError ? error : orgErrors.forbidden();
      addAuditEvent({
        type: 'org.create.rejected',
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

    let parsedPayload;
    try {
      parsedPayload = parseCreateOrgPayload(payload);
    } catch (error) {
      if (error instanceof AuthProblemError) {
        addAuditEvent({
          type: 'org.create.rejected',
          requestId: resolvedRequestId,
          operatorUserId,
          detail: 'payload validation failed',
          metadata: {
            error_code: error.errorCode
          }
        });
      }
      throw error;
    }

    assertAuthServiceMethod('getOrCreateUserIdentityByPhone');
    assertAuthServiceMethod('createOrganizationWithOwner');
    assertAuthServiceMethod('rollbackProvisionedUserIdentity');

    let ownerIdentity = null;
    try {
      ownerIdentity = await authService.getOrCreateUserIdentityByPhone({
        requestId: resolvedRequestId,
        phone: parsedPayload.ownerPhone,
        operatorUserId,
        operatorSessionId
      });
    } catch (error) {
      const mappedProblem = mapOwnerIdentityBootstrapProblem(error);
      if (mappedProblem) {
        addAuditEvent({
          type: 'org.create.rejected',
          requestId: resolvedRequestId,
          operatorUserId,
          detail:
            mappedProblem.errorCode === 'ORG-409-ORG-CONFLICT'
              ? 'owner identity conflict'
              : 'owner identity dependency unavailable',
          metadata: {
            error_code: mappedProblem.errorCode,
            upstream_error_code: String(error?.errorCode || '').trim() || 'unknown'
          }
        });
        throw mappedProblem;
      }
      addAuditEvent({
        type: 'org.create.rejected',
        requestId: resolvedRequestId,
        operatorUserId,
        detail: 'owner identity dependency unavailable',
        metadata: {
          error_code: 'ORG-503-DEPENDENCY-UNAVAILABLE'
        }
      });
      throw orgErrors.dependencyUnavailable();
    }

    const orgId = randomUUID();
    let createdOrg = null;
    try {
      createdOrg = await authService.createOrganizationWithOwner({
        requestId: resolvedRequestId,
        traceparent,
        orgId,
        orgName: parsedPayload.orgName,
        ownerDisplayName: parsedPayload.ownerName,
        ownerUserId: ownerIdentity.user_id,
        operatorUserId,
        operatorSessionId
      });
    } catch (error) {
      const ownerIdentityRollbackSucceeded = await rollbackOwnerIdentityIfNeeded({
        requestId: resolvedRequestId,
        operatorUserId,
        ownerIdentity,
        reason: String(error?.message || '').trim() || 'org-create-store-failure'
      });
      if (!ownerIdentityRollbackSucceeded) {
        addAuditEvent({
          type: 'org.create.rejected',
          requestId: resolvedRequestId,
          operatorUserId,
          detail: 'owner identity rollback failed after org create failure',
          metadata: {
            error_code: 'ORG-503-DEPENDENCY-UNAVAILABLE',
            upstream_error_code: String(
              error?.errorCode || error?.code || error?.message || 'unknown'
            ).trim() || 'unknown'
          }
        });
        throw orgErrors.dependencyUnavailable();
      }
      if (isDuplicateEntryError(error)) {
        addAuditEvent({
          type: 'org.create.rejected',
          requestId: resolvedRequestId,
          operatorUserId,
          detail: 'org create conflict',
          metadata: {
            error_code: 'ORG-409-ORG-CONFLICT'
          }
        });
        throw orgErrors.orgConflict();
      }
      if (isDataTooLongError(error)) {
        addAuditEvent({
          type: 'org.create.rejected',
          requestId: resolvedRequestId,
          operatorUserId,
          detail: 'payload length exceeds storage limit',
          metadata: {
            error_code: 'ORG-400-INVALID-PAYLOAD'
          }
        });
        throw orgErrors.invalidPayload('请求参数长度超出限制');
      }
      addAuditEvent({
        type: 'org.create.rejected',
        requestId: resolvedRequestId,
        operatorUserId,
        detail: 'organization governance dependency unavailable',
        metadata: {
          error_code: 'ORG-503-DEPENDENCY-UNAVAILABLE'
        }
      });
      throw orgErrors.dependencyUnavailable();
    }

    const resolvedOrgId = String(createdOrg?.org_id || orgId);
    const resolvedOwnerUserId = String(
      createdOrg?.owner_user_id || ownerIdentity.user_id
    );
    addAuditEvent({
      type: 'org.create.succeeded',
      requestId: resolvedRequestId,
      operatorUserId,
      orgId: resolvedOrgId,
      detail: 'organization created with initial owner',
      metadata: {
        owner_user_id: resolvedOwnerUserId,
        created_owner_user: Boolean(ownerIdentity.created_user),
        reused_existing_user: Boolean(ownerIdentity.reused_existing_user)
      }
    });

    return {
      org_id: resolvedOrgId,
      owner_user_id: resolvedOwnerUserId,
      created_owner_user: Boolean(ownerIdentity.created_user),
      reused_existing_user: Boolean(ownerIdentity.reused_existing_user),
      request_id: resolvedRequestId
    };
  };

  const updateOrgStatus = async ({
    requestId,
    accessToken,
    payload = {},
    traceparent = null,
    authorizationContext = null
  }) => {
    const resolvedRequestId = String(requestId || '').trim() || 'request_id_unset';
    const requestedOrgId = String(payload?.org_id || '').trim() || null;
    const requestedNextStatus = String(payload?.status || '').trim().toLowerCase() || null;
    let operatorContext;
    try {
      operatorContext = await resolveOperatorContext({
        requestId: resolvedRequestId,
        accessToken,
        authorizationContext
      });
    } catch (error) {
      const mappedError =
        error instanceof AuthProblemError ? error : orgErrors.forbidden();
      addAuditEvent({
        type: 'org.status.rejected',
        requestId: resolvedRequestId,
        operatorUserId: 'unknown',
        detail: 'operator authorization context invalid',
        metadata: {
          previous_status: null,
          next_status: requestedNextStatus,
          error_code: mappedError.errorCode
        }
      });
      throw mappedError;
    }
    const { operatorUserId, operatorSessionId } = operatorContext;

    let parsedPayload;
    try {
      parsedPayload = parseUpdateOrgStatusPayload(payload);
    } catch (error) {
      if (error instanceof AuthProblemError) {
        addAuditEvent({
          type: 'org.status.rejected',
          requestId: resolvedRequestId,
          operatorUserId,
          orgId: requestedOrgId,
          detail: 'payload validation failed',
          metadata: {
            previous_status: null,
            next_status: requestedNextStatus,
            error_code: error.errorCode
          }
        });
      }
      throw error;
    }

    assertAuthServiceMethod('updateOrganizationStatus');

    let statusUpdateResult;
    try {
      statusUpdateResult = await authService.updateOrganizationStatus({
        requestId: resolvedRequestId,
        traceparent,
        orgId: parsedPayload.orgId,
        nextStatus: parsedPayload.nextStatus,
        operatorUserId,
        operatorSessionId,
        reason: parsedPayload.reason
      });
    } catch (error) {
      const mappedError =
        error instanceof AuthProblemError && Number(error.status) === 404
          ? orgErrors.orgNotFound()
          : orgErrors.dependencyUnavailable();
      addAuditEvent({
        type: 'org.status.rejected',
        requestId: resolvedRequestId,
        operatorUserId,
        orgId: parsedPayload.orgId,
        detail:
          mappedError.errorCode === 'ORG-404-ORG-NOT-FOUND'
            ? 'organization not found'
            : 'organization status dependency unavailable',
        metadata: {
          previous_status: null,
          next_status: parsedPayload.nextStatus,
          error_code: mappedError.errorCode,
          upstream_error_code: String(error?.errorCode || error?.code || '').trim() || 'unknown'
        }
      });
      throw mappedError;
    }

    if (!statusUpdateResult) {
      addAuditEvent({
        type: 'org.status.rejected',
        requestId: resolvedRequestId,
        operatorUserId,
        orgId: parsedPayload.orgId,
        detail: 'organization not found',
        metadata: {
          previous_status: null,
          next_status: parsedPayload.nextStatus,
          error_code: 'ORG-404-ORG-NOT-FOUND'
        }
      });
      throw orgErrors.orgNotFound();
    }

    const previousStatus = String(statusUpdateResult.previous_status || '').trim().toLowerCase();
    const currentStatus = String(statusUpdateResult.current_status || '').trim().toLowerCase();
    if (!VALID_ORG_STATUSES.has(previousStatus) || !VALID_ORG_STATUSES.has(currentStatus)) {
      addAuditEvent({
        type: 'org.status.rejected',
        requestId: resolvedRequestId,
        operatorUserId,
        orgId: parsedPayload.orgId,
        detail: 'organization status dependency returned invalid state',
        metadata: {
          previous_status: previousStatus || null,
          next_status: parsedPayload.nextStatus,
          error_code: 'ORG-503-DEPENDENCY-UNAVAILABLE',
          upstream_error_code: 'ORG-STATUS-RESULT-INVALID'
        }
      });
      throw orgErrors.dependencyUnavailable();
    }
    const isNoOp = previousStatus === currentStatus;
    let affectedMembershipCount;
    let affectedRoleCount;
    let affectedRoleBindingCount;
    let revokedSessionCount;
    let revokedRefreshTokenCount;
    try {
      affectedMembershipCount = toNormalizedOrgStatusCascadeCount({
        value: statusUpdateResult.affected_membership_count
          ?? statusUpdateResult.affectedMembershipCount,
        field: 'affected_membership_count'
      });
      affectedRoleCount = toNormalizedOrgStatusCascadeCount({
        value: statusUpdateResult.affected_role_count
          ?? statusUpdateResult.affectedRoleCount,
        field: 'affected_role_count'
      });
      affectedRoleBindingCount = toNormalizedOrgStatusCascadeCount({
        value: statusUpdateResult.affected_role_binding_count
          ?? statusUpdateResult.affectedRoleBindingCount,
        field: 'affected_role_binding_count'
      });
      revokedSessionCount = toNormalizedOrgStatusCascadeCount({
        value: statusUpdateResult.revoked_session_count
          ?? statusUpdateResult.revokedSessionCount,
        field: 'revoked_session_count'
      });
      revokedRefreshTokenCount = toNormalizedOrgStatusCascadeCount({
        value: statusUpdateResult.revoked_refresh_token_count
          ?? statusUpdateResult.revokedRefreshTokenCount,
        field: 'revoked_refresh_token_count'
      });
    } catch (error) {
      addAuditEvent({
        type: 'org.status.rejected',
        requestId: resolvedRequestId,
        operatorUserId,
        orgId: parsedPayload.orgId,
        detail: 'organization status dependency returned invalid cascade counts',
        metadata: {
          previous_status: previousStatus,
          next_status: parsedPayload.nextStatus,
          error_code: 'ORG-503-DEPENDENCY-UNAVAILABLE',
          upstream_error_code: `${String(error?.code || 'unknown').trim()}:${String(error?.field || 'unknown').trim()}`
        }
      });
      throw orgErrors.dependencyUnavailable();
    }
    addAuditEvent({
      type: 'org.status.updated',
      requestId: resolvedRequestId,
      operatorUserId,
      orgId: parsedPayload.orgId,
      detail: isNoOp
        ? 'organization status update treated as no-op'
        : 'organization status updated',
      metadata: {
        previous_status: previousStatus,
        next_status: currentStatus,
        affected_membership_count: affectedMembershipCount,
        affected_role_count: affectedRoleCount,
        affected_role_binding_count: affectedRoleBindingCount,
        revoked_session_count: revokedSessionCount,
        revoked_refresh_token_count: revokedRefreshTokenCount
      }
    });

    return {
      org_id: parsedPayload.orgId,
      previous_status: previousStatus,
      current_status: currentStatus,
      request_id: resolvedRequestId
    };
  };

  const ownerTransfer = async ({
    requestId,
    accessToken,
    payload = {},
    traceparent = null,
    authorizationContext = null
  }) => {
    const resolvedRequestId = String(requestId || '').trim() || 'request_id_unset';
    const requestedOrgId = resolveRequestedOwnerTransferOrgId(payload);
    let operatorContext;
    try {
      operatorContext = await resolveOperatorContext({
        requestId: resolvedRequestId,
        accessToken,
        authorizationContext
      });
    } catch (error) {
      const mappedError =
        error instanceof AuthProblemError ? error : orgErrors.forbidden();
      const ownerTransferMappedError = withOwnerTransferContractProblem({
        problem: mappedError,
        orgId: requestedOrgId
      });
      addAuditEvent({
        type: 'org.owner_transfer.rejected',
        requestId: resolvedRequestId,
        operatorUserId: 'unknown',
        orgId: requestedOrgId,
        detail: 'operator authorization context invalid',
        metadata: {
          error_code: ownerTransferMappedError.errorCode,
          result_status: String(
            ownerTransferMappedError.extensions?.result_status || 'rejected'
          ),
          retryable: Boolean(ownerTransferMappedError.extensions?.retryable),
          upstream_error_code: String(
            error?.errorCode || error?.code || 'unknown'
          ).trim() || 'unknown'
        }
      });
      throw ownerTransferMappedError;
    }
    const { operatorUserId, operatorSessionId } = operatorContext;

    let parsedPayload;
    try {
      parsedPayload = parseOwnerTransferPayload(payload);
    } catch (error) {
      const mappedPayloadError =
        error instanceof AuthProblemError
          ? withOwnerTransferContractProblem({
            problem: error,
            orgId: requestedOrgId
          })
          : error;
      if (mappedPayloadError instanceof AuthProblemError) {
        addAuditEvent({
          type: 'org.owner_transfer.rejected',
          requestId: resolvedRequestId,
          operatorUserId,
          orgId: requestedOrgId,
          detail: 'payload validation failed',
          metadata: {
            error_code: mappedPayloadError.errorCode,
            result_status: String(
              mappedPayloadError.extensions?.result_status || 'rejected'
            ),
            retryable: Boolean(mappedPayloadError.extensions?.retryable),
            upstream_error_code: String(
              error?.errorCode || error?.code || 'unknown'
            ).trim() || 'unknown'
          }
        });
      }
      throw mappedPayloadError;
    }

    let lockAcquired = false;
    try {
      lockAcquired = await acquireOwnerTransferLock({
        orgId: parsedPayload.orgId,
        requestId: resolvedRequestId,
        operatorUserId
      });
    } catch (error) {
      const mappedLockError =
        error instanceof AuthProblemError
          ? mapOwnerTransferValidationProblem({
            error,
            orgId: parsedPayload.orgId
          })
          : withOwnerTransferContractProblem({
            problem: orgErrors.dependencyUnavailable(),
            orgId: parsedPayload.orgId
          });
      const mappedLockErrorCode = String(mappedLockError.errorCode || '').trim();
      addAuditEvent({
        type: mappedLockErrorCode === 'ORG-409-OWNER-TRANSFER-CONFLICT'
          ? 'org.owner_transfer.conflict'
          : 'org.owner_transfer.rejected',
        requestId: resolvedRequestId,
        operatorUserId,
        orgId: parsedPayload.orgId,
        detail:
          mappedLockErrorCode === 'ORG-409-OWNER-TRANSFER-CONFLICT'
            ? 'owner transfer request already in progress'
            : 'owner transfer lock dependency unavailable',
        metadata: {
          error_code: mappedLockErrorCode || 'ORG-503-DEPENDENCY-UNAVAILABLE',
          result_status: String(
            mappedLockError.extensions?.result_status
            || (mappedLockErrorCode === 'ORG-409-OWNER-TRANSFER-CONFLICT'
              ? 'conflict'
              : 'rejected')
          ),
          retryable: Boolean(mappedLockError.extensions?.retryable),
          upstream_error_code: String(
            error?.errorCode || error?.code || 'unknown'
          ).trim() || 'unknown'
        }
      });
      throw mappedLockError;
    }

    if (!lockAcquired) {
      const mappedConflictError = orgErrors.ownerTransferConflict({
        orgId: parsedPayload.orgId
      });
      addAuditEvent({
        type: 'org.owner_transfer.conflict',
        requestId: resolvedRequestId,
        operatorUserId,
        orgId: parsedPayload.orgId,
        detail: 'owner transfer request is already in progress for target org',
        metadata: {
          error_code: mappedConflictError.errorCode,
          retryable: true,
          result_status: 'conflict',
          upstream_error_code: 'AUTH-409-OWNER-TRANSFER-CONFLICT'
        }
      });
      throw mappedConflictError;
    }

    try {
      addAuditEvent({
        type: 'org.owner_transfer.initiated',
        requestId: resolvedRequestId,
        operatorUserId,
        orgId: parsedPayload.orgId,
        detail: 'owner transfer request initiated',
        metadata: {
          result_status: 'accepted',
          reason: parsedPayload.reason
        }
      });

      assertAuthServiceMethod('executeOwnerTransferTakeover');
      const takeoverResult = await authService.executeOwnerTransferTakeover({
        requestId: resolvedRequestId,
        traceparent,
        orgId: parsedPayload.orgId,
        newOwnerPhone: parsedPayload.newOwnerPhone,
        operatorUserId,
        operatorSessionId,
        reason: parsedPayload.reason
      });

      const resolvedOrgId = String(takeoverResult?.org_id || '').trim();
      const oldOwnerUserId = String(
        takeoverResult?.old_owner_user_id || ''
      ).trim();
      const newOwnerUserId = String(
        takeoverResult?.new_owner_user_id || ''
      ).trim();
      if (
        !resolvedOrgId
        || !oldOwnerUserId
        || !newOwnerUserId
        || resolvedOrgId !== parsedPayload.orgId
      ) {
        const takeoverResultInvalidError = new Error(
          'owner transfer takeover dependency returned invalid payload'
        );
        takeoverResultInvalidError.code = 'ORG-OWNER-TRANSFER-TAKEOVER-RESULT-INVALID';
        throw takeoverResultInvalidError;
      }

      addAuditEvent({
        type: 'org.owner_transfer.submitted',
        requestId: resolvedRequestId,
        operatorUserId,
        orgId: resolvedOrgId,
        detail: 'owner transfer takeover transaction committed',
        metadata: {
          old_owner_user_id: oldOwnerUserId,
          new_owner_user_id: newOwnerUserId,
          result_status: 'accepted',
          error_code: OWNER_TRANSFER_ACCEPTED_ERROR_CODE,
          retryable: false
        }
      });

      return {
        request_id: resolvedRequestId,
        org_id: resolvedOrgId,
        old_owner_user_id: oldOwnerUserId,
        new_owner_user_id: newOwnerUserId,
        result_status: 'accepted',
        error_code: OWNER_TRANSFER_ACCEPTED_ERROR_CODE,
        retryable: false
      };
    } catch (error) {
      if (error instanceof AuthProblemError) {
        const mappedError = mapOwnerTransferValidationProblem({
          error,
          orgId: parsedPayload.orgId
        });
        const mappedErrorCode = String(mappedError.errorCode || '').trim();
        addAuditEvent({
          type: mappedErrorCode === 'ORG-409-OWNER-TRANSFER-CONFLICT'
            ? 'org.owner_transfer.conflict'
            : 'org.owner_transfer.rejected',
          requestId: resolvedRequestId,
          operatorUserId,
          orgId: parsedPayload.orgId,
          detail:
            mappedErrorCode === 'ORG-404-ORG-NOT-FOUND'
              ? 'owner transfer org not found'
              : mappedErrorCode === 'ORG-404-NEW-OWNER-NOT-FOUND'
                ? 'owner transfer candidate not found'
                : mappedErrorCode === 'ORG-409-OWNER-TRANSFER-CONFLICT'
                  ? 'owner transfer request already in progress'
                : mappedErrorCode === 'ORG-409-ORG-NOT-ACTIVE'
                  ? 'owner transfer org not active'
                  : mappedErrorCode === 'ORG-409-NEW-OWNER-INACTIVE'
                    ? 'owner transfer candidate inactive'
                    : mappedErrorCode === 'ORG-409-OWNER-TRANSFER-SAME-OWNER'
                      ? 'owner transfer target equals current owner'
                      : 'owner transfer dependency unavailable',
          metadata: {
            error_code: mappedErrorCode || 'ORG-503-DEPENDENCY-UNAVAILABLE',
            result_status: String(
              mappedError.extensions?.result_status || 'rejected'
            ),
            retryable: Boolean(mappedError.extensions?.retryable),
            upstream_error_code: String(
              error.errorCode || error.code || 'unknown'
            ).trim() || 'unknown'
          }
        });
        throw mappedError;
      }
      addAuditEvent({
        type: 'org.owner_transfer.rejected',
        requestId: resolvedRequestId,
        operatorUserId,
        orgId: parsedPayload.orgId,
        detail:
          String(error?.code || '').trim() === 'ORG-OWNER-TRANSFER-TAKEOVER-RESULT-INVALID'
            ? 'owner transfer takeover dependency returned invalid payload'
            : 'owner transfer dependency unavailable',
        metadata: {
          error_code: 'ORG-503-DEPENDENCY-UNAVAILABLE',
          result_status: 'rejected',
          retryable: true,
          upstream_error_code: String(
            error?.errorCode || error?.code || 'unknown'
          ).trim() || 'unknown'
        }
      });
      throw withOwnerTransferContractProblem({
        problem: orgErrors.dependencyUnavailable(),
        orgId: parsedPayload.orgId
      });
    } finally {
      try {
        const released = await releaseOwnerTransferLock(parsedPayload.orgId);
        if (!released) {
          log('warn', 'owner transfer lock release not confirmed', {
            request_id: resolvedRequestId,
            org_id: parsedPayload.orgId
          });
        }
      } catch (releaseError) {
        log('warn', 'owner transfer lock release failed', {
          request_id: resolvedRequestId,
          org_id: parsedPayload.orgId,
          error_code: String(releaseError?.code || ''),
          detail: String(releaseError?.message || '')
        });
      }
    }
  };

  return {
    listOrgs,
    createOrg,
    updateOrgStatus,
    ownerTransfer,
    _internals: {
      auditTrail,
      authService,
      ownerTransferLocksByOrgId
    }
  };
};

module.exports = {
  createPlatformOrgService
};
