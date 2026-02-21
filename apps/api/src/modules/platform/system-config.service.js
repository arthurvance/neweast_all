const { log } = require('../../common/logger');
const { AuthProblemError } = require('../auth/auth.service');
const {
  resolveRoutePreauthorizedContext
} = require('../auth/route-preauthorization');
const {
  PLATFORM_SYSTEM_CONFIG_VIEW_PERMISSION_CODE,
  PLATFORM_SYSTEM_CONFIG_OPERATE_PERMISSION_CODE,
  PLATFORM_SYSTEM_CONFIG_SCOPE,
  PLATFORM_SYSTEM_CONFIG_ALLOWED_KEYS
} = require('./system-config.constants');

const CONTROL_CHAR_PATTERN = /[\u0000-\u001F\u007F]/;
const MAX_AUDIT_TRAIL_ENTRIES = 200;
const SYSTEM_CONFIG_ENVELOPE_VERSION = 'enc:v1';
const BASE64URL_SEGMENT_PATTERN = /^[A-Za-z0-9_-]+$/;
const MYSQL_DUP_ENTRY_ERRNO = 1062;
const UPDATE_SYSTEM_CONFIG_ALLOWED_FIELDS = new Set([
  'encrypted_value',
  'expected_version',
  'status'
]);
const VALID_SYSTEM_CONFIG_STATUS = new Set(['active', 'disabled']);
const ALLOWED_CONFIG_KEY_SET = new Set(
  PLATFORM_SYSTEM_CONFIG_ALLOWED_KEYS.map((configKey) =>
    String(configKey || '').trim().toLowerCase()
  )
);

const isPlainObject = (candidate) =>
  candidate !== null
  && typeof candidate === 'object'
  && !Array.isArray(candidate);

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

const normalizeConfigKey = (configKey) =>
  normalizeStrictRequiredString(configKey).toLowerCase();

const isWhitelistedConfigKey = (configKey) =>
  ALLOWED_CONFIG_KEY_SET.has(normalizeConfigKey(configKey));

const normalizeConfigStatus = (status) => {
  const normalizedStatus = String(status || 'active').trim().toLowerCase();
  if (normalizedStatus === 'enabled') {
    return 'active';
  }
  return VALID_SYSTEM_CONFIG_STATUS.has(normalizedStatus)
    ? normalizedStatus
    : '';
};
const isValidEncryptedEnvelope = (encryptedValue) => {
  const normalized = String(encryptedValue || '').trim();
  const sections = normalized.split(':');
  if (
    sections.length !== 5
    || `${sections[0]}:${sections[1]}` !== SYSTEM_CONFIG_ENVELOPE_VERSION
  ) {
    return false;
  }
  if (
    !BASE64URL_SEGMENT_PATTERN.test(sections[2] || '')
    || !BASE64URL_SEGMENT_PATTERN.test(sections[3] || '')
    || !BASE64URL_SEGMENT_PATTERN.test(sections[4] || '')
  ) {
    return false;
  }
  const iv = Buffer.from(sections[2], 'base64url');
  const authTag = Buffer.from(sections[3], 'base64url');
  const cipherText = Buffer.from(sections[4], 'base64url');
  return iv.length === 12 && authTag.length === 16 && cipherText.length > 0;
};

const toIsoTimestamp = (value) => {
  if (value instanceof Date) {
    return value.toISOString();
  }
  const normalized = normalizeStrictRequiredString(value);
  if (normalized) {
    return normalized;
  }
  return new Date().toISOString();
};

const systemConfigProblem = ({
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

const systemConfigErrors = {
  invalidPayload: (detail = '请求参数不完整或格式错误') =>
    systemConfigProblem({
      status: 400,
      title: 'Bad Request',
      detail,
      errorCode: 'SYSCFG-400-INVALID-PAYLOAD'
    }),

  configNotFound: ({ configKey = null } = {}) =>
    systemConfigProblem({
      status: 404,
      title: 'Not Found',
      detail: '目标受控配置不存在',
      errorCode: 'SYSCFG-404-CONFIG-NOT-FOUND',
      extensions: {
        retryable: false,
        config_key: configKey ? String(configKey).trim() : null
      }
    }),

  versionConflict: ({
    configKey = null,
    expectedVersion = null,
    currentVersion = null
  } = {}) =>
    systemConfigProblem({
      status: 409,
      title: 'Conflict',
      detail: '配置版本冲突，请刷新后重试',
      errorCode: 'SYSCFG-409-VERSION-CONFLICT',
      extensions: {
        retryable: true,
        config_key: configKey ? String(configKey).trim() : null,
        expected_version:
          Number.isInteger(expectedVersion) && expectedVersion >= 0
            ? expectedVersion
            : null,
        current_version:
          Number.isInteger(currentVersion) && currentVersion >= 0
            ? currentVersion
            : null
      }
    }),

  forbidden: () =>
    systemConfigProblem({
      status: 403,
      title: 'Forbidden',
      detail: '当前操作无权限',
      errorCode: 'AUTH-403-FORBIDDEN'
    }),

  dependencyUnavailable: ({ reason = 'dependency-unavailable' } = {}) =>
    systemConfigProblem({
      status: 503,
      title: 'Service Unavailable',
      detail: '受控配置治理依赖暂不可用，请稍后重试',
      errorCode: 'SYSCFG-503-DEPENDENCY-UNAVAILABLE',
      extensions: {
        retryable: true,
        degradation_reason: String(reason || 'dependency-unavailable').trim()
      }
    })
};

const mapAuthorizationError = (error) => {
  if (error instanceof AuthProblemError) {
    return error;
  }
  return systemConfigErrors.dependencyUnavailable({
    reason: 'authorization-dependency-unavailable'
  });
};

const mapUpdateDependencyError = (error, configKey, expectedVersion) => {
  if (error instanceof AuthProblemError) {
    return error;
  }
  const normalizedErrorCode = String(error?.code || '').trim();
  if (
    normalizedErrorCode === 'ERR_SYSTEM_SENSITIVE_CONFIG_VERSION_CONFLICT'
    || normalizedErrorCode === 'ER_DUP_ENTRY'
    || Number(error?.errno || 0) === MYSQL_DUP_ENTRY_ERRNO
  ) {
    const currentVersion = Number(error?.currentVersion ?? error?.current_version);
    return systemConfigErrors.versionConflict({
      configKey,
      expectedVersion,
      currentVersion: Number.isInteger(currentVersion) ? currentVersion : null
    });
  }
  return systemConfigErrors.dependencyUnavailable({
    reason: normalizedErrorCode
      || String(error?.message || 'system-config-update-failed').trim().toLowerCase()
  });
};

const mapReadDependencyError = (error) => {
  if (error instanceof AuthProblemError) {
    return error;
  }
  return systemConfigErrors.dependencyUnavailable({
    reason: String(error?.code || error?.message || 'system-config-read-failed').trim().toLowerCase()
  });
};

const parseUpdatePayload = (payload) => {
  if (!isPlainObject(payload)) {
    throw systemConfigErrors.invalidPayload();
  }

  const unknownPayloadKeys = Object.keys(payload).filter(
    (key) => !UPDATE_SYSTEM_CONFIG_ALLOWED_FIELDS.has(key)
  );
  if (unknownPayloadKeys.length > 0) {
    throw systemConfigErrors.invalidPayload();
  }

  if (!Object.prototype.hasOwnProperty.call(payload, 'encrypted_value')) {
    throw systemConfigErrors.invalidPayload('encrypted_value 必填');
  }
  if (!Object.prototype.hasOwnProperty.call(payload, 'expected_version')) {
    throw systemConfigErrors.invalidPayload('expected_version 必填');
  }

  if (typeof payload.encrypted_value !== 'string') {
    throw systemConfigErrors.invalidPayload('encrypted_value 必须为字符串');
  }
  const encryptedValue = payload.encrypted_value.trim();
  if (
    !encryptedValue
    || encryptedValue !== payload.encrypted_value
    || CONTROL_CHAR_PATTERN.test(encryptedValue)
    || !isValidEncryptedEnvelope(encryptedValue)
  ) {
    throw systemConfigErrors.invalidPayload('encrypted_value 必须为有效 enc:v1 密文信封');
  }

  if (
    typeof payload.expected_version !== 'number'
    || !Number.isInteger(payload.expected_version)
    || payload.expected_version < 0
  ) {
    throw systemConfigErrors.invalidPayload('expected_version 必须为大于等于 0 的整数');
  }

  let status = 'active';
  if (Object.prototype.hasOwnProperty.call(payload, 'status')) {
    if (typeof payload.status !== 'string') {
      throw systemConfigErrors.invalidPayload('status 必须为字符串');
    }
    status = normalizeConfigStatus(payload.status);
    if (!status) {
      throw systemConfigErrors.invalidPayload('status 必须为 active 或 disabled');
    }
  }

  return {
    encryptedValue,
    expectedVersion: payload.expected_version,
    status
  };
};

const toReadResponse = ({
  configKey,
  version,
  status,
  updatedByUserId,
  updatedAt,
  requestId
}) => ({
  data: {
    config_key: configKey,
    version,
    status,
    updated_by_user_id: updatedByUserId,
    updated_at: updatedAt
  },
  meta: {
    request_id: requestId
  }
});

const toWriteResponse = ({
  configKey,
  version,
  previousVersion,
  status,
  updatedByUserId,
  updatedAt,
  requestId
}) => ({
  data: {
    config_key: configKey,
    previous_version: previousVersion,
    version,
    status,
    updated_by_user_id: updatedByUserId,
    updated_at: updatedAt
  },
  meta: {
    request_id: requestId
  }
});

const normalizeSystemSensitiveConfigRecord = (record = null) => {
  if (!record || typeof record !== 'object') {
    return null;
  }
  const configKey = normalizeConfigKey(record.configKey || record.config_key);
  if (!configKey || !isWhitelistedConfigKey(configKey)) {
    return null;
  }
  const normalizedVersion = Number(record.version);
  const normalizedPreviousVersion = Number(
    record.previousVersion
    ?? record.previous_version
    ?? 0
  );
  if (
    !Number.isInteger(normalizedVersion)
    || normalizedVersion < 0
    || !Number.isInteger(normalizedPreviousVersion)
    || normalizedPreviousVersion < 0
  ) {
    return null;
  }
  const status = normalizeConfigStatus(record.status || 'active');
  if (!status) {
    return null;
  }
  const updatedByUserId = normalizeStrictRequiredString(
    record.updatedByUserId || record.updated_by_user_id
  );
  if (!updatedByUserId) {
    return null;
  }
  return {
    configKey,
    version: normalizedVersion,
    previousVersion: normalizedPreviousVersion,
    status,
    updatedByUserId,
    updatedAt: toIsoTimestamp(record.updatedAt || record.updated_at)
  };
};

const createPlatformSystemConfigService = ({ authService } = {}) => {
  const auditTrail = [];

  const addAuditEvent = ({
    type,
    requestId,
    operatorUserId = 'unknown',
    configKey = null,
    detail,
    metadata = {}
  }) => {
    const event = {
      type: String(type || '').trim() || 'platform.system_config.unknown',
      at: new Date().toISOString(),
      request_id: String(requestId || '').trim() || 'request_id_unset',
      operator_user_id: String(operatorUserId || '').trim() || 'unknown',
      config_key: configKey ? String(configKey).trim() : null,
      detail: String(detail || '').trim(),
      ...metadata
    };
    auditTrail.push(event);
    if (auditTrail.length > MAX_AUDIT_TRAIL_ENTRIES) {
      auditTrail.splice(0, auditTrail.length - MAX_AUDIT_TRAIL_ENTRIES);
    }
    log('info', 'Platform system config audit event', event);
  };

  const persistRejectedAuditEvent = async ({
    requestId,
    traceparent = null,
    operatorUserId = null,
    operatorSessionId = null,
    configKey = null,
    eventType = 'auth.system_config.update.rejected',
    failureReason = 'unknown',
    expectedVersion = null,
    currentVersion = null,
    detail = null
  } = {}) => {
    if (
      !authService
      || typeof authService.recordSystemSensitiveConfigAuditEvent !== 'function'
    ) {
      return;
    }
    await authService.recordSystemSensitiveConfigAuditEvent({
      requestId,
      traceparent,
      actorUserId: operatorUserId,
      actorSessionId: operatorSessionId,
      targetId: configKey,
      eventType,
      result: 'rejected',
      beforeState: Number.isInteger(currentVersion) && currentVersion >= 0
        ? { version: currentVersion }
        : null,
      afterState: null,
      metadata: {
        config_key: configKey,
        expected_version:
          Number.isInteger(expectedVersion) && expectedVersion >= 0
            ? expectedVersion
            : null,
        current_version:
          Number.isInteger(currentVersion) && currentVersion >= 0
            ? currentVersion
            : null,
        failure_reason: String(failureReason || 'unknown').trim().toLowerCase(),
        detail: detail ? String(detail).trim() : null
      }
    });
  };

  const assertAuthServiceMethod = (methodName) => {
    if (!authService || typeof authService[methodName] !== 'function') {
      throw systemConfigErrors.dependencyUnavailable();
    }
  };

  const resolveAuthorizedOperatorContext = ({
    authorizationContext = null,
    expectedPermissionCode = PLATFORM_SYSTEM_CONFIG_OPERATE_PERMISSION_CODE
  } = {}) => {
    const preauthorizedContext = resolveRoutePreauthorizedContext({
      authorizationContext,
      expectedPermissionCode,
      expectedScope: PLATFORM_SYSTEM_CONFIG_SCOPE,
      expectedEntryDomain: PLATFORM_SYSTEM_CONFIG_SCOPE
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
    permissionCode = PLATFORM_SYSTEM_CONFIG_OPERATE_PERMISSION_CODE
  }) => {
    const preAuthorizedContext = resolveAuthorizedOperatorContext({
      authorizationContext,
      expectedPermissionCode: permissionCode
    });
    if (preAuthorizedContext) {
      return preAuthorizedContext;
    }

    assertAuthServiceMethod('authorizeRoute');
    const authorized = await authService.authorizeRoute({
      requestId,
      accessToken,
      permissionCode,
      scope: PLATFORM_SYSTEM_CONFIG_SCOPE,
      authorizationContext
    });
    const operatorUserId = normalizeStrictRequiredString(
      authorized?.user_id || authorized?.userId
    );
    const operatorSessionId = normalizeStrictRequiredString(
      authorized?.session_id || authorized?.sessionId
    );
    if (!operatorUserId || !operatorSessionId) {
      throw systemConfigErrors.forbidden();
    }
    return {
      operatorUserId,
      operatorSessionId
    };
  };

  const getSystemConfig = async ({
    requestId,
    accessToken,
    configKey,
    traceparent = null,
    authorizationContext = null
  }) => {
    const resolvedRequestId = String(requestId || '').trim() || 'request_id_unset';
    const normalizedConfigKey = normalizeConfigKey(configKey);

    let operatorContext;
    try {
      operatorContext = await resolveOperatorContext({
        requestId: resolvedRequestId,
        accessToken,
        authorizationContext,
        permissionCode: PLATFORM_SYSTEM_CONFIG_VIEW_PERMISSION_CODE
      });
    } catch (error) {
      const mappedError = mapAuthorizationError(error);
      addAuditEvent({
        type: 'platform.system_config.read.rejected',
        requestId: resolvedRequestId,
        operatorUserId: 'unknown',
        configKey: isWhitelistedConfigKey(normalizedConfigKey) ? normalizedConfigKey : null,
        detail: 'operator authorization context invalid',
        metadata: {
          error_code: mappedError.errorCode
        }
      });
      await persistRejectedAuditEvent({
        requestId: resolvedRequestId,
        traceparent,
        operatorUserId: null,
        operatorSessionId: null,
        configKey: normalizedConfigKey,
        eventType: 'auth.system_config.read.rejected',
        failureReason: mappedError.errorCode || 'authorization-failed',
        detail: mappedError.detail
      }).catch(() => {});
      throw mappedError;
    }

    const { operatorUserId, operatorSessionId } = operatorContext;

    if (!isWhitelistedConfigKey(normalizedConfigKey)) {
      const problem = systemConfigErrors.invalidPayload('config_key 非受控白名单项');
      addAuditEvent({
        type: 'platform.system_config.read.rejected',
        requestId: resolvedRequestId,
        operatorUserId,
        configKey: normalizedConfigKey,
        detail: 'system config key is not in whitelist',
        metadata: {
          error_code: problem.errorCode,
          failure_reason: 'config-key-not-whitelisted'
        }
      });
      await persistRejectedAuditEvent({
        requestId: resolvedRequestId,
        traceparent,
        operatorUserId,
        operatorSessionId,
        configKey: normalizedConfigKey,
        eventType: 'auth.system_config.read.rejected',
        failureReason: 'config-key-not-whitelisted',
        detail: problem.detail
      }).catch(() => {});
      throw problem;
    }

    let record;
    try {
      assertAuthServiceMethod('getSystemSensitiveConfig');
      record = await authService.getSystemSensitiveConfig({
        configKey: normalizedConfigKey
      });
    } catch (error) {
      const mappedError = mapReadDependencyError(error);
      addAuditEvent({
        type: 'platform.system_config.read.rejected',
        requestId: resolvedRequestId,
        operatorUserId,
        configKey: normalizedConfigKey,
        detail: 'system config read failed',
        metadata: {
          error_code: mappedError.errorCode,
          failure_reason: String(error?.code || error?.message || 'dependency-unavailable').trim().toLowerCase()
        }
      });
      await persistRejectedAuditEvent({
        requestId: resolvedRequestId,
        traceparent,
        operatorUserId,
        operatorSessionId,
        configKey: normalizedConfigKey,
        eventType: 'auth.system_config.read.rejected',
        failureReason: String(error?.code || error?.message || 'dependency-unavailable').trim().toLowerCase(),
        detail: mappedError.detail
      }).catch(() => {});
      throw mappedError;
    }

    const normalizedRecord = normalizeSystemSensitiveConfigRecord(record);
    if (!normalizedRecord) {
      const problem = systemConfigErrors.configNotFound({
        configKey: normalizedConfigKey
      });
      addAuditEvent({
        type: 'platform.system_config.read.rejected',
        requestId: resolvedRequestId,
        operatorUserId,
        configKey: normalizedConfigKey,
        detail: 'system config not found',
        metadata: {
          error_code: problem.errorCode,
          failure_reason: 'config-not-found'
        }
      });
      await persistRejectedAuditEvent({
        requestId: resolvedRequestId,
        traceparent,
        operatorUserId,
        operatorSessionId,
        configKey: normalizedConfigKey,
        eventType: 'auth.system_config.read.rejected',
        failureReason: 'config-not-found',
        detail: problem.detail
      }).catch(() => {});
      throw problem;
    }

    addAuditEvent({
      type: 'platform.system_config.read.succeeded',
      requestId: resolvedRequestId,
      operatorUserId,
      configKey: normalizedConfigKey,
      detail: 'system config read succeeded',
      metadata: {
        version: normalizedRecord.version,
        status: normalizedRecord.status
      }
    });

    return toReadResponse({
      configKey: normalizedRecord.configKey,
      version: normalizedRecord.version,
      status: normalizedRecord.status,
      updatedByUserId: normalizedRecord.updatedByUserId,
      updatedAt: normalizedRecord.updatedAt,
      requestId: resolvedRequestId
    });
  };

  const updateSystemConfig = async ({
    requestId,
    accessToken,
    configKey,
    payload = {},
    traceparent = null,
    authorizationContext = null
  }) => {
    const resolvedRequestId = String(requestId || '').trim() || 'request_id_unset';
    const normalizedConfigKey = normalizeConfigKey(configKey);

    let operatorContext;
    try {
      operatorContext = await resolveOperatorContext({
        requestId: resolvedRequestId,
        accessToken,
        authorizationContext,
        permissionCode: PLATFORM_SYSTEM_CONFIG_OPERATE_PERMISSION_CODE
      });
    } catch (error) {
      const mappedError = mapAuthorizationError(error);
      addAuditEvent({
        type: 'platform.system_config.update.rejected',
        requestId: resolvedRequestId,
        operatorUserId: 'unknown',
        configKey: isWhitelistedConfigKey(normalizedConfigKey) ? normalizedConfigKey : null,
        detail: 'operator authorization context invalid',
        metadata: {
          error_code: mappedError.errorCode
        }
      });
      await persistRejectedAuditEvent({
        requestId: resolvedRequestId,
        traceparent,
        configKey: normalizedConfigKey,
        eventType: 'auth.system_config.update.rejected',
        failureReason: mappedError.errorCode || 'authorization-failed',
        detail: mappedError.detail
      }).catch(() => {});
      throw mappedError;
    }

    const { operatorUserId, operatorSessionId } = operatorContext;

    if (!isWhitelistedConfigKey(normalizedConfigKey)) {
      const problem = systemConfigErrors.invalidPayload('config_key 非受控白名单项');
      addAuditEvent({
        type: 'platform.system_config.update.rejected',
        requestId: resolvedRequestId,
        operatorUserId,
        configKey: normalizedConfigKey,
        detail: 'system config key is not in whitelist',
        metadata: {
          error_code: problem.errorCode,
          failure_reason: 'config-key-not-whitelisted'
        }
      });
      await persistRejectedAuditEvent({
        requestId: resolvedRequestId,
        traceparent,
        operatorUserId,
        operatorSessionId,
        configKey: normalizedConfigKey,
        eventType: 'auth.system_config.update.rejected',
        failureReason: 'config-key-not-whitelisted',
        detail: problem.detail
      }).catch(() => {});
      throw problem;
    }

    let parsedPayload;
    try {
      parsedPayload = parseUpdatePayload(payload);
    } catch (error) {
      const mappedError = error instanceof AuthProblemError
        ? error
        : systemConfigErrors.invalidPayload();
      addAuditEvent({
        type: 'platform.system_config.update.rejected',
        requestId: resolvedRequestId,
        operatorUserId,
        configKey: normalizedConfigKey,
        detail: 'system config payload invalid',
        metadata: {
          error_code: mappedError.errorCode,
          failure_reason: 'payload-invalid'
        }
      });
      await persistRejectedAuditEvent({
        requestId: resolvedRequestId,
        traceparent,
        operatorUserId,
        operatorSessionId,
        configKey: normalizedConfigKey,
        eventType: 'auth.system_config.update.rejected',
        failureReason: 'payload-invalid',
        detail: mappedError.detail
      }).catch(() => {});
      throw mappedError;
    }

    let updatedRecord;
    let delegatedUpsertCall = false;
    try {
      assertAuthServiceMethod('upsertSystemSensitiveConfig');
      delegatedUpsertCall = true;
      updatedRecord = await authService.upsertSystemSensitiveConfig({
        requestId: resolvedRequestId,
        traceparent,
        configKey: normalizedConfigKey,
        encryptedValue: parsedPayload.encryptedValue,
        expectedVersion: parsedPayload.expectedVersion,
        updatedByUserId: operatorUserId,
        updatedBySessionId: operatorSessionId,
        status: parsedPayload.status
      });
    } catch (error) {
      const mappedError = mapUpdateDependencyError(
        error,
        normalizedConfigKey,
        parsedPayload.expectedVersion
      );
      addAuditEvent({
        type: 'platform.system_config.update.rejected',
        requestId: resolvedRequestId,
        operatorUserId,
        configKey: normalizedConfigKey,
        detail: 'system config update failed',
        metadata: {
          error_code: mappedError.errorCode,
          failure_reason: String(error?.code || error?.message || 'update-failed').trim().toLowerCase()
        }
      });
      if (!delegatedUpsertCall) {
        await persistRejectedAuditEvent({
          requestId: resolvedRequestId,
          traceparent,
          operatorUserId,
          operatorSessionId,
          configKey: normalizedConfigKey,
          eventType: 'auth.system_config.update.rejected',
          failureReason: String(error?.code || error?.message || 'update-failed').trim().toLowerCase(),
          expectedVersion: parsedPayload.expectedVersion,
          detail: mappedError.detail
        }).catch(() => {});
      }
      throw mappedError;
    }

    const normalizedUpdatedRecord = normalizeSystemSensitiveConfigRecord(updatedRecord);
    if (!normalizedUpdatedRecord) {
      const mappedError = systemConfigErrors.dependencyUnavailable({
        reason: 'system-config-upsert-result-invalid'
      });
      addAuditEvent({
        type: 'platform.system_config.update.rejected',
        requestId: resolvedRequestId,
        operatorUserId,
        configKey: normalizedConfigKey,
        detail: 'system config update result invalid',
        metadata: {
          error_code: mappedError.errorCode,
          failure_reason: 'upsert-result-invalid'
        }
      });
      await persistRejectedAuditEvent({
        requestId: resolvedRequestId,
        traceparent,
        operatorUserId,
        operatorSessionId,
        configKey: normalizedConfigKey,
        eventType: 'auth.system_config.update.rejected',
        failureReason: 'upsert-result-invalid',
        detail: mappedError.detail
      }).catch(() => {});
      throw mappedError;
    }

    addAuditEvent({
      type: 'platform.system_config.update.succeeded',
      requestId: resolvedRequestId,
      operatorUserId,
      configKey: normalizedConfigKey,
      detail: 'system config updated',
      metadata: {
        previous_version: normalizedUpdatedRecord.previousVersion,
        current_version: normalizedUpdatedRecord.version,
        status: normalizedUpdatedRecord.status
      }
    });

    return toWriteResponse({
      configKey: normalizedUpdatedRecord.configKey,
      version: normalizedUpdatedRecord.version,
      previousVersion: normalizedUpdatedRecord.previousVersion,
      status: normalizedUpdatedRecord.status,
      updatedByUserId: normalizedUpdatedRecord.updatedByUserId,
      updatedAt: normalizedUpdatedRecord.updatedAt,
      requestId: resolvedRequestId
    });
  };

  return {
    getSystemConfig,
    updateSystemConfig,
    _internals: {
      auditTrail
    }
  };
};

module.exports = { createPlatformSystemConfigService };
