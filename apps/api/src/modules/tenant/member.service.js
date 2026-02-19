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
const MAX_AUDIT_TRAIL_ENTRIES = 200;
const DEFAULT_MEMBER_LIST_PAGE = 1;
const DEFAULT_MEMBER_LIST_PAGE_SIZE = 50;
const MAX_MEMBER_LIST_PAGE_SIZE = 200;
const MEMBERSHIP_ID_PATTERN = /^[^\s\u0000-\u001F\u007F]{1,64}$/;
const MAINLAND_PHONE_PATTERN = /^1\d{10}$/;
const CREATE_MEMBER_ALLOWED_FIELDS = new Set(['phone']);
const UPDATE_MEMBER_STATUS_ALLOWED_FIELDS = new Set(['status', 'reason']);
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

const normalizeMemberStatus = (status) => {
  const normalizedStatus = String(status || '').trim().toLowerCase();
  if (normalizedStatus === 'enabled') {
    return 'active';
  }
  return normalizedStatus;
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

const parseUpdateMemberStatusInput = ({ params = {}, payload = {} } = {}) => {
  const rawMembershipId = params.membership_id;
  if (typeof rawMembershipId !== 'string') {
    throw tenantMemberErrors.invalidPayload('membership_id 不能为空');
  }
  const membershipId = normalizeRequiredString(rawMembershipId);
  if (!membershipId) {
    throw tenantMemberErrors.invalidPayload('membership_id 不能为空');
  }
  if (rawMembershipId !== membershipId) {
    throw tenantMemberErrors.invalidPayload('membership_id 不能包含前后空白字符');
  }
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
  const rawTenantName = source.tenant_name ?? source.tenantName ?? null;
  const rawJoinedAt = source.joined_at ?? source.joinedAt ?? null;
  const rawLeftAt = source.left_at ?? source.leftAt ?? null;
  return {
    membership_id: normalizeRequiredString(
      source.membership_id || source.membershipId
    ),
    user_id: normalizeRequiredString(source.user_id || source.userId),
    tenant_id: normalizeRequiredString(source.tenant_id || source.tenantId),
    tenant_name: normalizeOptionalTenantName(rawTenantName),
    phone: normalizeRequiredString(source.phone),
    status: normalizeMemberStatus(source.status),
    joined_at: normalizeOptionalDateTime(rawJoinedAt),
    left_at: normalizeOptionalDateTime(rawLeftAt)
  };
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
    const hasMalformedMember = normalizedMembers.some(
      (member, index) => {
        const rawMember = isPlainObject(members[index]) ? members[index] : {};
        const rawTenantName = rawMember.tenant_name ?? rawMember.tenantName ?? null;
        const rawJoinedAt = rawMember.joined_at ?? rawMember.joinedAt ?? null;
        const rawLeftAt = rawMember.left_at ?? rawMember.leftAt ?? null;
        return (
        !isValidMembershipId(member.membership_id)
        || !member.user_id
        || !member.tenant_id
        || !isValidMainlandPhone(member.phone)
        || !VALID_MEMBER_STATUS.has(member.status)
        || !isValidOptionalTenantName(rawTenantName)
        || !isValidOptionalDateTime(rawJoinedAt)
        || !isValidOptionalDateTime(rawLeftAt)
        );
      }
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
      !isValidMembershipId(normalizedMembership.membership_id)
      || !normalizedMembership.user_id
      || !normalizedMembership.tenant_id
      || !isValidMainlandPhone(normalizedMembership.phone)
      || normalizedMembership.phone !== parsedPayload.phone
      || normalizedMembership.status !== 'active'
      || normalizedMembership.user_id !== targetUserId
      || normalizedMembership.tenant_id !== activeTenantId
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
    const resolvedMembershipId = normalizeRequiredString(
      updatedMembership.membership_id
    );
    const resolvedUserId = normalizeRequiredString(updatedMembership.user_id);
    const resolvedTenantId = normalizeRequiredString(updatedMembership.tenant_id);
    const resolvedPreviousStatus = normalizeMemberStatus(
      updatedMembership.previous_status
    );
    const resolvedCurrentStatus = normalizeMemberStatus(
      updatedMembership.current_status
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

  return {
    listMembers,
    createMember,
    updateMemberStatus,
    _internals: {
      auditTrail,
      authService
    }
  };
};

module.exports = { createTenantMemberService };
