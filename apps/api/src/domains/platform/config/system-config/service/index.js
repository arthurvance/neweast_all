const { log } = require('../../../../../common/logger');
const { AuthProblemError } = require('../../../../../shared-kernel/auth/auth-problem-error');
const {
  resolveRoutePreauthorizedContext
} = require('../../../../../shared-kernel/auth/route-authz');
const {
  PLATFORM_SYSTEM_CONFIG_VIEW_PERMISSION_CODE,
  PLATFORM_SYSTEM_CONFIG_OPERATE_PERMISSION_CODE,
  PLATFORM_SYSTEM_CONFIG_SCOPE,
  PLATFORM_SYSTEM_CONFIG_ALLOWED_KEYS
} = require('../constants');
const { ALLOWED_CONFIG_KEY_SET, BASE64URL_SEGMENT_PATTERN, CONTROL_CHAR_PATTERN, MAX_AUDIT_TRAIL_ENTRIES, MYSQL_DUP_ENTRY_ERRNO, SYSTEM_CONFIG_ENVELOPE_VERSION, UPDATE_SYSTEM_CONFIG_ALLOWED_FIELDS, VALID_SYSTEM_CONFIG_STATUS, isPlainObject, isValidEncryptedEnvelope, isWhitelistedConfigKey, mapAuthorizationError, mapReadDependencyError, mapUpdateDependencyError, normalizeConfigKey, normalizeConfigStatus, normalizeStrictRequiredString, normalizeSystemSensitiveConfigRecord, parseUpdatePayload, systemConfigErrors, systemConfigProblem, toIsoTimestamp, toReadResponse, toWriteResponse } = require('./service.helpers');

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
