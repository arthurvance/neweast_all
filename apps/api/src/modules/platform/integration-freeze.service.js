const { log } = require('../../common/logger');
const { AuthProblemError } = require('../auth/auth.service');
const {
  resolveRoutePreauthorizedContext
} = require('../auth/route-preauthorization');
const {
  PLATFORM_INTEGRATION_FREEZE_VIEW_PERMISSION_CODE,
  PLATFORM_INTEGRATION_FREEZE_OPERATE_PERMISSION_CODE,
  PLATFORM_INTEGRATION_FREEZE_SCOPE,
  PLATFORM_INTEGRATION_FREEZE_STATUS_ENUM
} = require('./integration-freeze.constants');

const CONTROL_CHAR_PATTERN = /[\u0000-\u001F\u007F]/;
const MAX_AUDIT_TRAIL_ENTRIES = 200;
const MAX_FREEZE_ID_LENGTH = 64;
const MAX_REASON_LENGTH = 256;
const MAX_OPERATOR_USER_ID_LENGTH = 64;
const MAX_REQUEST_ID_LENGTH = 128;
const MAX_TRACEPARENT_LENGTH = 128;

const VALID_FREEZE_STATUSES = new Set(PLATFORM_INTEGRATION_FREEZE_STATUS_ENUM);
const ACTIVATE_ALLOWED_FIELDS = new Set([
  'freeze_id',
  'freeze_reason'
]);
const RELEASE_ALLOWED_FIELDS = new Set([
  'rollback_reason'
]);

const isPlainObject = (candidate) =>
  candidate !== null
  && typeof candidate === 'object'
  && !Array.isArray(candidate);

const normalizeStrictRequiredString = (candidate) => {
  if (typeof candidate !== 'string') {
    return '';
  }
  const normalized = candidate.trim();
  if (
    !normalized
    || normalized !== candidate
    || CONTROL_CHAR_PATTERN.test(normalized)
  ) {
    return '';
  }
  return normalized;
};

const normalizeStrictOptionalString = ({
  value,
  maxLength
} = {}) => {
  if (value === null || value === undefined) {
    return null;
  }
  if (typeof value !== 'string') {
    return undefined;
  }
  const normalized = value.trim();
  if (
    !normalized
    || normalized !== value
    || CONTROL_CHAR_PATTERN.test(normalized)
    || normalized.length > maxLength
  ) {
    return undefined;
  }
  return normalized;
};

const normalizeStoreIsoTimestamp = (value) => {
  if (value === null || value === undefined) {
    return null;
  }
  if (value instanceof Date) {
    return value.toISOString();
  }
  if (typeof value !== 'string') {
    return '';
  }
  const normalized = value.trim();
  if (!normalized) {
    return null;
  }
  if (normalized !== value || CONTROL_CHAR_PATTERN.test(normalized)) {
    return '';
  }
  const parsedDate = new Date(normalized);
  if (Number.isNaN(parsedDate.getTime())) {
    return '';
  }
  return parsedDate.toISOString();
};

const resolveStoreFieldValue = ({
  record,
  camelCaseKey,
  snakeCaseKey
}) =>
  record[camelCaseKey] === undefined
    ? record[snakeCaseKey]
    : record[camelCaseKey];

const normalizeStoreOptionalString = ({
  record,
  camelCaseKey,
  snakeCaseKey,
  maxLength
}) =>
  normalizeStrictOptionalString({
    value: resolveStoreFieldValue({
      record,
      camelCaseKey,
      snakeCaseKey
    }),
    maxLength
  });

const normalizeFreezeId = (freezeId) =>
  normalizeStrictRequiredString(freezeId).toLowerCase();

const normalizeFreezeStatus = (status) =>
  String(status || '').trim().toLowerCase();

const freezeProblem = ({
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

const freezeErrors = {
  invalidPayload: (detail = '请求参数不完整或格式错误') =>
    freezeProblem({
      status: 400,
      title: 'Bad Request',
      detail,
      errorCode: 'INT-400-INVALID-PAYLOAD'
    }),

  forbidden: () =>
    freezeProblem({
      status: 403,
      title: 'Forbidden',
      detail: '当前操作无权限',
      errorCode: 'AUTH-403-FORBIDDEN'
    }),

  freezeAlreadyActive: ({
    freezeId = null,
    frozenAt = null
  } = {}) =>
    freezeProblem({
      status: 409,
      title: 'Conflict',
      detail: '集成清单已处于冻结窗口，请先解冻后再重复冻结',
      errorCode: 'INT-409-INTEGRATION-FREEZE-ACTIVE',
      extensions: {
        retryable: false,
        freeze_id: freezeId,
        frozen_at: frozenAt
      }
    }),

  freezeReleaseConflict: () =>
    freezeProblem({
      status: 409,
      title: 'Conflict',
      detail: '当前不存在 active 冻结窗口，无法执行解冻',
      errorCode: 'INT-409-INTEGRATION-FREEZE-RELEASE-CONFLICT',
      extensions: {
        retryable: false
      }
    }),

  dependencyUnavailable: ({ reason = 'dependency-unavailable' } = {}) =>
    freezeProblem({
      status: 503,
      title: 'Service Unavailable',
      detail: '集成冻结治理依赖暂不可用，请稍后重试',
      errorCode: 'INT-503-DEPENDENCY-UNAVAILABLE',
      extensions: {
        retryable: true,
        degradation_reason: String(reason || 'dependency-unavailable').trim()
      }
    })
};

const mapStoreError = (error) => {
  if (error instanceof AuthProblemError) {
    return error;
  }
  const normalizedErrorCode = String(error?.code || '').trim();
  if (normalizedErrorCode === 'ERR_PLATFORM_INTEGRATION_FREEZE_ACTIVE_CONFLICT') {
    return freezeErrors.freezeAlreadyActive({
      freezeId: normalizeFreezeId(error?.freezeId) || null,
      frozenAt: normalizeStoreIsoTimestamp(error?.frozenAt) || null
    });
  }
  if (normalizedErrorCode === 'ERR_PLATFORM_INTEGRATION_FREEZE_RELEASE_CONFLICT') {
    return freezeErrors.freezeReleaseConflict();
  }
  return freezeErrors.dependencyUnavailable({
    reason: normalizedErrorCode
      || String(error?.message || 'dependency-unavailable').trim().toLowerCase()
  });
};

const mapFreezeRecord = ({
  record
} = {}) => {
  if (!record || typeof record !== 'object') {
    return null;
  }
  const freezeId = normalizeFreezeId(
    resolveStoreFieldValue({
      record,
      camelCaseKey: 'freezeId',
      snakeCaseKey: 'freeze_id'
    })
  );
  const status = normalizeFreezeStatus(
    resolveStoreFieldValue({
      record,
      camelCaseKey: 'status',
      snakeCaseKey: 'status'
    })
  );
  const freezeReason = normalizeStrictRequiredString(
    resolveStoreFieldValue({
      record,
      camelCaseKey: 'freezeReason',
      snakeCaseKey: 'freeze_reason'
    })
  );
  const rollbackReason = normalizeStoreOptionalString({
    record,
    camelCaseKey: 'rollbackReason',
    snakeCaseKey: 'rollback_reason',
    maxLength: MAX_REASON_LENGTH
  });
  const frozenAt = normalizeStoreIsoTimestamp(
    resolveStoreFieldValue({
      record,
      camelCaseKey: 'frozenAt',
      snakeCaseKey: 'frozen_at'
    })
  );
  const releasedAt = normalizeStoreIsoTimestamp(
    resolveStoreFieldValue({
      record,
      camelCaseKey: 'releasedAt',
      snakeCaseKey: 'released_at'
    })
  );
  const frozenByUserId = normalizeStoreOptionalString({
    record,
    camelCaseKey: 'frozenByUserId',
    snakeCaseKey: 'frozen_by_user_id',
    maxLength: MAX_OPERATOR_USER_ID_LENGTH
  });
  const releasedByUserId = normalizeStoreOptionalString({
    record,
    camelCaseKey: 'releasedByUserId',
    snakeCaseKey: 'released_by_user_id',
    maxLength: MAX_OPERATOR_USER_ID_LENGTH
  });
  const sourceRequestId = normalizeStrictRequiredString(
    resolveStoreFieldValue({
      record,
      camelCaseKey: 'requestId',
      snakeCaseKey: 'request_id'
    })
  );
  const traceparent = normalizeStoreOptionalString({
    record,
    camelCaseKey: 'traceparent',
    snakeCaseKey: 'traceparent',
    maxLength: MAX_TRACEPARENT_LENGTH
  });
  const createdAt = normalizeStoreIsoTimestamp(
    resolveStoreFieldValue({
      record,
      camelCaseKey: 'createdAt',
      snakeCaseKey: 'created_at'
    })
  );
  const updatedAt = normalizeStoreIsoTimestamp(
    resolveStoreFieldValue({
      record,
      camelCaseKey: 'updatedAt',
      snakeCaseKey: 'updated_at'
    })
  );
  if (
    !freezeId
    || freezeId.length > MAX_FREEZE_ID_LENGTH
    || !VALID_FREEZE_STATUSES.has(status)
    || !freezeReason
    || freezeReason.length > MAX_REASON_LENGTH
    || rollbackReason === undefined
    || !frozenAt
    || releasedAt === ''
    || (
      status === 'active'
      && releasedAt !== null
    )
    || (
      status === 'released'
      && releasedAt === null
    )
    || frozenByUserId === undefined
    || releasedByUserId === undefined
    || !sourceRequestId
    || sourceRequestId.length > MAX_REQUEST_ID_LENGTH
    || traceparent === undefined
    || !createdAt
    || !updatedAt
  ) {
    return null;
  }
  return {
    freeze_id: freezeId,
    status,
    freeze_reason: freezeReason,
    rollback_reason: rollbackReason,
    frozen_at: frozenAt,
    released_at: releasedAt,
    frozen_by_user_id: frozenByUserId,
    released_by_user_id: releasedByUserId,
    request_id: sourceRequestId,
    traceparent: traceparent || null,
    created_at: createdAt,
    updated_at: updatedAt
  };
};

const parseActivatePayload = (payload = {}) => {
  if (!isPlainObject(payload)) {
    throw freezeErrors.invalidPayload();
  }
  const unknownKeys = Object.keys(payload).filter(
    (key) => !ACTIVATE_ALLOWED_FIELDS.has(key)
  );
  if (unknownKeys.length > 0) {
    throw freezeErrors.invalidPayload();
  }
  if (!Object.prototype.hasOwnProperty.call(payload, 'freeze_reason')) {
    throw freezeErrors.invalidPayload('freeze_reason 必填');
  }
  const freezeId = Object.prototype.hasOwnProperty.call(payload, 'freeze_id')
    ? normalizeFreezeId(payload.freeze_id)
    : '';
  if (
    payload.freeze_id !== undefined
    && (
      !freezeId
      || freezeId.length > MAX_FREEZE_ID_LENGTH
    )
  ) {
    throw freezeErrors.invalidPayload('freeze_id 非法');
  }
  const freezeReason = normalizeStrictRequiredString(payload.freeze_reason);
  if (!freezeReason || freezeReason.length > MAX_REASON_LENGTH) {
    throw freezeErrors.invalidPayload(`freeze_reason 长度不能超过 ${MAX_REASON_LENGTH}`);
  }
  return {
    freezeId: freezeId || undefined,
    freezeReason
  };
};

const parseReleasePayload = (payload = {}) => {
  if (!isPlainObject(payload)) {
    throw freezeErrors.invalidPayload();
  }
  const unknownKeys = Object.keys(payload).filter(
    (key) => !RELEASE_ALLOWED_FIELDS.has(key)
  );
  if (unknownKeys.length > 0) {
    throw freezeErrors.invalidPayload();
  }
  const rollbackReason = Object.prototype.hasOwnProperty.call(payload, 'rollback_reason')
    ? normalizeStrictOptionalString({
      value: payload.rollback_reason,
      maxLength: MAX_REASON_LENGTH
    })
    : null;
  if (rollbackReason === undefined) {
    throw freezeErrors.invalidPayload(
      `rollback_reason 长度不能超过 ${MAX_REASON_LENGTH}`
    );
  }
  return {
    rollbackReason
  };
};

const createPlatformIntegrationFreezeService = ({ authService } = {}) => {
  const auditTrail = [];

  const addAuditEvent = ({
    type,
    requestId,
    operatorUserId = 'unknown',
    freezeId = null,
    detail,
    metadata = {}
  }) => {
    const event = {
      type: String(type || '').trim() || 'platform.integration.freeze.unknown',
      at: new Date().toISOString(),
      request_id: String(requestId || '').trim() || 'request_id_unset',
      operator_user_id: String(operatorUserId || '').trim() || 'unknown',
      freeze_id: freezeId ? String(freezeId) : null,
      detail: String(detail || '').trim(),
      ...metadata
    };
    auditTrail.push(event);
    if (auditTrail.length > MAX_AUDIT_TRAIL_ENTRIES) {
      auditTrail.splice(0, auditTrail.length - MAX_AUDIT_TRAIL_ENTRIES);
    }
    log('info', 'Platform integration freeze audit event', event);
  };

  const assertAuthServiceMethod = (methodName) => {
    if (!authService || typeof authService[methodName] !== 'function') {
      throw freezeErrors.dependencyUnavailable({
        reason: `auth-service-${methodName}-unsupported`
      });
    }
  };

  const resolveAuthStore = () => authService?._internals?.authStore || null;

  const assertAuthStoreMethod = (methodName) => {
    const authStore = resolveAuthStore();
    if (!authStore || typeof authStore[methodName] !== 'function') {
      throw freezeErrors.dependencyUnavailable({
        reason: `auth-store-${methodName}-unsupported`
      });
    }
    return authStore;
  };

  const resolvePreauthorizedOperatorContext = ({
    authorizationContext = null,
    expectedPermissionCode = PLATFORM_INTEGRATION_FREEZE_OPERATE_PERMISSION_CODE
  } = {}) => {
    const preauthorizedContext = resolveRoutePreauthorizedContext({
      authorizationContext,
      expectedPermissionCode,
      expectedScope: PLATFORM_INTEGRATION_FREEZE_SCOPE,
      expectedEntryDomain: PLATFORM_INTEGRATION_FREEZE_SCOPE
    });
    if (!preauthorizedContext) {
      return null;
    }
    return {
      operatorUserId: preauthorizedContext.userId,
      operatorSessionId: preauthorizedContext.sessionId
    };
  };

  const resolveOperatorContext = async ({
    requestId,
    accessToken,
    authorizationContext = null,
    permissionCode = PLATFORM_INTEGRATION_FREEZE_OPERATE_PERMISSION_CODE
  }) => {
    const preauthorizedContext = resolvePreauthorizedOperatorContext({
      authorizationContext,
      expectedPermissionCode: permissionCode
    });
    if (preauthorizedContext) {
      return preauthorizedContext;
    }
    assertAuthServiceMethod('authorizeRoute');
    const authorized = await authService.authorizeRoute({
      requestId,
      accessToken,
      permissionCode,
      scope: PLATFORM_INTEGRATION_FREEZE_SCOPE,
      authorizationContext
    });
    const operatorUserId = normalizeStrictRequiredString(
      authorized?.user_id || authorized?.userId
    );
    const operatorSessionId = normalizeStrictRequiredString(
      authorized?.session_id || authorized?.sessionId
    );
    if (!operatorUserId || !operatorSessionId) {
      throw freezeErrors.forbidden();
    }
    return {
      operatorUserId,
      operatorSessionId
    };
  };

  const getFreezeStatus = async ({
    requestId,
    accessToken,
    authorizationContext = null
  }) => {
    const resolvedRequestId = String(requestId || '').trim() || 'request_id_unset';
    const operatorContext = await resolveOperatorContext({
      requestId: resolvedRequestId,
      accessToken,
      authorizationContext,
      permissionCode: PLATFORM_INTEGRATION_FREEZE_VIEW_PERMISSION_CODE
    });
    const authStore = assertAuthStoreMethod('findActivePlatformIntegrationFreeze');
    assertAuthStoreMethod('findLatestPlatformIntegrationFreeze');
    let activeRecord;
    let latestRecord;
    try {
      activeRecord = await authStore.findActivePlatformIntegrationFreeze();
      latestRecord = await authStore.findLatestPlatformIntegrationFreeze();
    } catch (error) {
      throw mapStoreError(error);
    }
    const mappedActive = activeRecord
      ? mapFreezeRecord({
        record: activeRecord
      })
      : null;
    const mappedLatest = latestRecord
      ? mapFreezeRecord({
        record: latestRecord
      })
      : null;
    if (
      (activeRecord && !mappedActive)
      || (latestRecord && !mappedLatest)
    ) {
      throw freezeErrors.dependencyUnavailable({
        reason: 'integration-freeze-state-malformed'
      });
    }
    addAuditEvent({
      type: 'platform.integration.freeze.read.succeeded',
      requestId: resolvedRequestId,
      operatorUserId: operatorContext.operatorUserId,
      freezeId: mappedActive?.freeze_id || null,
      detail: 'integration freeze status loaded',
      metadata: {
        frozen: Boolean(mappedActive)
      }
    });
    return {
      frozen: Boolean(mappedActive),
      active_freeze: mappedActive,
      latest_freeze: mappedLatest,
      request_id: resolvedRequestId
    };
  };

  const activateFreeze = async ({
    requestId,
    accessToken,
    payload = {},
    traceparent = null,
    authorizationContext = null
  }) => {
    const resolvedRequestId = String(requestId || '').trim() || 'request_id_unset';
    const parsedPayload = parseActivatePayload(payload);
    const operatorContext = await resolveOperatorContext({
      requestId: resolvedRequestId,
      accessToken,
      authorizationContext,
      permissionCode: PLATFORM_INTEGRATION_FREEZE_OPERATE_PERMISSION_CODE
    });
    const authStore = assertAuthStoreMethod('activatePlatformIntegrationFreeze');
    let createdRecord;
    try {
      createdRecord = await authStore.activatePlatformIntegrationFreeze({
        freezeId: parsedPayload.freezeId,
        freezeReason: parsedPayload.freezeReason,
        operatorUserId: operatorContext.operatorUserId,
        operatorSessionId: operatorContext.operatorSessionId,
        requestId: resolvedRequestId,
        traceparent,
        auditContext: {
          requestId: resolvedRequestId,
          traceparent,
          actorUserId: operatorContext.operatorUserId,
          actorSessionId: operatorContext.operatorSessionId
        }
      });
    } catch (error) {
      const mappedError = mapStoreError(error);
      addAuditEvent({
        type: 'platform.integration.freeze.activate.rejected',
        requestId: resolvedRequestId,
        operatorUserId: operatorContext.operatorUserId,
        detail: 'integration freeze activate failed',
        metadata: {
          error_code: mappedError.errorCode
        }
      });
      throw mappedError;
    }
    const mapped = mapFreezeRecord({
      record: createdRecord
    });
    if (!mapped || mapped.status !== 'active') {
      throw freezeErrors.dependencyUnavailable({
        reason: 'integration-freeze-activate-result-malformed'
      });
    }
    addAuditEvent({
      type: 'platform.integration.freeze.activate.succeeded',
      requestId: resolvedRequestId,
      operatorUserId: operatorContext.operatorUserId,
      freezeId: mapped.freeze_id,
      detail: 'integration freeze activated'
    });
    return mapped;
  };

  const releaseFreeze = async ({
    requestId,
    accessToken,
    payload = {},
    traceparent = null,
    authorizationContext = null
  }) => {
    const resolvedRequestId = String(requestId || '').trim() || 'request_id_unset';
    const parsedPayload = parseReleasePayload(payload);
    const operatorContext = await resolveOperatorContext({
      requestId: resolvedRequestId,
      accessToken,
      authorizationContext,
      permissionCode: PLATFORM_INTEGRATION_FREEZE_OPERATE_PERMISSION_CODE
    });
    const authStore = assertAuthStoreMethod('releasePlatformIntegrationFreeze');
    let releasedRecord;
    try {
      releasedRecord = await authStore.releasePlatformIntegrationFreeze({
        rollbackReason: parsedPayload.rollbackReason,
        operatorUserId: operatorContext.operatorUserId,
        operatorSessionId: operatorContext.operatorSessionId,
        requestId: resolvedRequestId,
        traceparent,
        auditContext: {
          requestId: resolvedRequestId,
          traceparent,
          actorUserId: operatorContext.operatorUserId,
          actorSessionId: operatorContext.operatorSessionId
        }
      });
    } catch (error) {
      const mappedError = mapStoreError(error);
      addAuditEvent({
        type: 'platform.integration.freeze.release.rejected',
        requestId: resolvedRequestId,
        operatorUserId: operatorContext.operatorUserId,
        detail: 'integration freeze release failed',
        metadata: {
          error_code: mappedError.errorCode
        }
      });
      throw mappedError;
    }
    const mapped = mapFreezeRecord({
      record: releasedRecord
    });
    const previousStatus = normalizeFreezeStatus(
      releasedRecord.previousStatus || releasedRecord.previous_status || ''
    );
    const currentStatus = normalizeFreezeStatus(
      releasedRecord.currentStatus || releasedRecord.current_status || ''
    );
    if (
      !mapped
      || mapped.status !== 'released'
      || !VALID_FREEZE_STATUSES.has(previousStatus)
      || !VALID_FREEZE_STATUSES.has(currentStatus)
      || currentStatus !== mapped.status
    ) {
      throw freezeErrors.dependencyUnavailable({
        reason: 'integration-freeze-release-result-malformed'
      });
    }
    addAuditEvent({
      type: 'platform.integration.freeze.release.succeeded',
      requestId: resolvedRequestId,
      operatorUserId: operatorContext.operatorUserId,
      freezeId: mapped.freeze_id,
      detail: 'integration freeze released'
    });
    return {
      ...mapped,
      previous_status: previousStatus,
      current_status: currentStatus,
      released: true
    };
  };

  return {
    getFreezeStatus,
    activateFreeze,
    releaseFreeze,
    _internals: {
      authService,
      auditTrail,
      mapFreezeRecord,
      parseActivatePayload,
      parseReleasePayload,
      mapStoreError
    }
  };
};

module.exports = {
  createPlatformIntegrationFreezeService
};
