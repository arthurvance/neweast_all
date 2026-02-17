const { randomUUID } = require('node:crypto');
const { log } = require('../../common/logger');
const { AuthProblemError } = require('../auth/auth.service');
const {
  resolveRoutePreauthorizedContext
} = require('../auth/route-preauthorization');
const {
  PLATFORM_ORG_CREATE_PERMISSION_CODE,
  PLATFORM_ORG_SCOPE
} = require('./org.constants');

const MYSQL_DUP_ENTRY_ERRNO = 1062;
const MYSQL_DATA_TOO_LONG_ERRNO = 1406;
const OWNER_PHONE_PATTERN = /^1\d{10}$/;
const CONTROL_CHAR_PATTERN = /[\u0000-\u001F\u007F]/;
const MAX_ORG_NAME_LENGTH = 128;
const MAX_STATUS_REASON_LENGTH = 256;
const MAX_AUDIT_TRAIL_ENTRIES = 200;
const CREATE_ORG_ALLOWED_FIELDS = new Set(['org_name', 'initial_owner_phone']);
const UPDATE_ORG_STATUS_ALLOWED_FIELDS = new Set(['org_id', 'status', 'reason']);
const VALID_ORG_STATUSES = new Set(['active', 'disabled']);
const MAX_UNKNOWN_PAYLOAD_KEYS_IN_DETAIL = 8;
const MAX_UNKNOWN_PAYLOAD_KEY_LENGTH_IN_DETAIL = 64;
const MAX_UNKNOWN_PAYLOAD_DETAIL_LENGTH = 280;

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

const resolveAuthorizedOperatorContext = (authorizationContext = null) => {
  const preauthorizedContext = resolveRoutePreauthorizedContext({
    authorizationContext,
    expectedPermissionCode: PLATFORM_ORG_CREATE_PERMISSION_CODE,
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
      detail: '组织已存在或负责人关系已建立，请勿重复提交',
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

  if (typeof payload.org_name !== 'string') {
    throw orgErrors.invalidPayload('org_name 必须为字符串');
  }
  if (typeof payload.initial_owner_phone !== 'string') {
    throw orgErrors.invalidPayload('initial_owner_phone 格式错误');
  }

  const orgName = normalizeRequiredString(payload.org_name);
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
  if (CONTROL_CHAR_PATTERN.test(orgName)) {
    throw orgErrors.invalidPayload('org_name 不能包含控制字符');
  }
  if (orgName.length > MAX_ORG_NAME_LENGTH) {
    throw orgErrors.invalidPayload(`org_name 长度不能超过 ${MAX_ORG_NAME_LENGTH}`);
  }
  if (!OWNER_PHONE_PATTERN.test(ownerPhoneRaw)) {
    throw orgErrors.invalidPayload('initial_owner_phone 格式错误');
  }

  return {
    orgName,
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

const createPlatformOrgService = ({ authService } = {}) => {
  const auditTrail = [];

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

  const mapOwnerIdentityBootstrapProblem = (error) => {
    if (!(error instanceof AuthProblemError)) {
      return null;
    }
    const normalizedStatus = Number(error.status);
    if (normalizedStatus === 409) {
      return orgErrors.orgConflict();
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
    authorizationContext = null
  }) => {
    const preAuthorizedOperatorContext =
      resolveAuthorizedOperatorContext(authorizationContext);
    let operatorUserId = preAuthorizedOperatorContext?.operatorUserId || 'unknown';
    let operatorSessionId = preAuthorizedOperatorContext?.operatorSessionId || 'unknown';
    if (!preAuthorizedOperatorContext) {
      assertAuthServiceMethod('authorizeRoute');
      const authorized = await authService.authorizeRoute({
        requestId,
        accessToken,
        permissionCode: PLATFORM_ORG_CREATE_PERMISSION_CODE,
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

  const createOrg = async ({
    requestId,
    accessToken,
    payload = {},
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
        orgId,
        orgName: parsedPayload.orgName,
        ownerUserId: ownerIdentity.user_id,
        operatorUserId
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
        next_status: currentStatus
      }
    });

    return {
      org_id: parsedPayload.orgId,
      previous_status: previousStatus,
      current_status: currentStatus,
      request_id: resolvedRequestId
    };
  };

  return {
    createOrg,
    updateOrgStatus,
    _internals: {
      auditTrail,
      authService
    }
  };
};

module.exports = {
  createPlatformOrgService
};
