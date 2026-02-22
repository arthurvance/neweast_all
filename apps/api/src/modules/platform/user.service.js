const { log } = require('../../common/logger');
const { AuthProblemError } = require('../auth/auth.service');
const {
  resolveRoutePreauthorizedContext
} = require('../auth/route-preauthorization');
const {
  PLATFORM_USER_PERMISSION_CODE,
  PLATFORM_USER_SCOPE
} = require('./user.constants');

const CONTROL_CHAR_PATTERN = /[\u0000-\u001F\u007F]/;
const MAX_STATUS_REASON_LENGTH = 256;
const MAX_USER_ID_LENGTH = 64;
const MAX_AUDIT_TRAIL_ENTRIES = 200;
const UPDATE_USER_STATUS_ALLOWED_FIELDS = new Set(['user_id', 'status', 'reason']);
const SOFT_DELETE_USER_ALLOWED_PARAM_FIELDS = new Set(['user_id']);
const VALID_USER_STATUSES = new Set(['active', 'disabled']);

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

const normalizeUserStatus = (status) => {
  const normalizedStatus = String(status || '').trim().toLowerCase();
  if (normalizedStatus === 'enabled') {
    return 'active';
  }
  return normalizedStatus;
};

const isResolvedOperatorIdentifier = (value) => {
  const normalized = String(value || '').trim();
  return normalized.length > 0 && normalized.toLowerCase() !== 'unknown';
};

const resolveAuthorizedOperatorContext = (authorizationContext = null) => {
  const preauthorizedContext = resolveRoutePreauthorizedContext({
    authorizationContext,
    expectedPermissionCode: PLATFORM_USER_PERMISSION_CODE,
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
        permissionCode: PLATFORM_USER_PERMISSION_CODE,
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

  const createUser = async ({
    requestId,
    accessToken,
    payload = {},
    authorizationContext = null
  }) => {
    const resolvedRequestId = String(requestId || '').trim() || 'request_id_unset';
    const requestedPhone = String(payload?.phone || '').trim() || null;
    const maskedRequestedPhone = maskPhone(requestedPhone);
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
        payload,
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
        reused_existing_user: Boolean(provisionedUser?.reused_existing_user)
      }
    });

    return {
      user_id: resolvedUserId,
      created_user: Boolean(provisionedUser?.created_user),
      reused_existing_user: Boolean(provisionedUser?.reused_existing_user),
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
    createUser,
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
