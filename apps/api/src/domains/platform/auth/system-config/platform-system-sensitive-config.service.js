'use strict';

const createPlatformSystemSensitiveConfigCapabilities = ({
  authStore,
  errors,
  assertStoreMethod,
  bindRequestTraceparent,
  normalizeAuditRequestIdOrNull,
  normalizeSystemSensitiveConfigKey,
  normalizeSystemSensitiveConfigStatus,
  normalizeStrictRequiredStringField,
  toSystemSensitiveConfigRecord,
  addAuditEvent,
  recordPersistentAuditEvent,
  DEFAULT_PASSWORD_CONFIG_KEY,
  SUPPORTED_SYSTEM_SENSITIVE_CONFIG_KEYS,
  REJECTED_SYSTEM_CONFIG_AUDIT_EVENT_TYPES,
  CONTROL_CHAR_PATTERN
} = {}) => {
  const MAX_SYSTEM_SENSITIVE_CONFIG_REMARK_LENGTH = 255;
  const recordSystemSensitiveConfigAuditEvent = async ({
    requestId = 'request_id_unset',
    traceparent = null,
    actorUserId = null,
    actorSessionId = null,
    targetId = DEFAULT_PASSWORD_CONFIG_KEY,
    eventType = 'auth.system_config.updated',
    result = 'success',
    beforeState = null,
    afterState = null,
    metadata = null
  } = {}) => {
    const normalizedEventType =
      normalizeStrictRequiredStringField(eventType) || 'auth.system_config.updated';
    const normalizedEventTypeKey = normalizedEventType.toLowerCase();
    const isRejectedEventType =
      REJECTED_SYSTEM_CONFIG_AUDIT_EVENT_TYPES.has(normalizedEventTypeKey);
    const normalizedTargetId = normalizeSystemSensitiveConfigKey(targetId);
    const hasSupportedTargetId =
      Boolean(normalizedTargetId)
      && SUPPORTED_SYSTEM_SENSITIVE_CONFIG_KEYS.has(normalizedTargetId);
    if (!hasSupportedTargetId && !isRejectedEventType) {
      throw errors.invalidPayload();
    }
    const resolvedTargetId = hasSupportedTargetId
      ? normalizedTargetId
      : (normalizedTargetId || null);
    return recordPersistentAuditEvent({
      domain: 'platform',
      tenantId: null,
      requestId,
      traceparent,
      eventType: normalizedEventType,
      actorUserId,
      actorSessionId,
      targetType: 'system_config',
      targetId: resolvedTargetId,
      result,
      beforeState,
      afterState,
      metadata
    });
  };

  const getSystemSensitiveConfig = async ({
    configKey = DEFAULT_PASSWORD_CONFIG_KEY
  } = {}) => {
    const normalizedConfigKey = normalizeSystemSensitiveConfigKey(configKey);
    if (
      !normalizedConfigKey
      || !SUPPORTED_SYSTEM_SENSITIVE_CONFIG_KEYS.has(normalizedConfigKey)
    ) {
      throw errors.invalidPayload();
    }
    assertStoreMethod(authStore, 'getSystemSensitiveConfig', 'authStore');
    const record = await authStore.getSystemSensitiveConfig({
      configKey: normalizedConfigKey
    });
    return toSystemSensitiveConfigRecord(record);
  };

  const upsertSystemSensitiveConfig = async ({
    requestId,
    traceparent = null,
    configKey = DEFAULT_PASSWORD_CONFIG_KEY,
    encryptedValue,
    remark,
    hasRemark = false,
    expectedVersion,
    updatedByUserId,
    updatedBySessionId = null,
    status = 'active'
  } = {}) => {
    const normalizedRequestId =
      normalizeAuditRequestIdOrNull(requestId) || 'request_id_unset';
    const normalizedTraceparent = bindRequestTraceparent({
      requestId: normalizedRequestId,
      traceparent
    });
    const normalizedConfigKey = normalizeSystemSensitiveConfigKey(configKey);
    if (
      !normalizedConfigKey
      || !SUPPORTED_SYSTEM_SENSITIVE_CONFIG_KEYS.has(normalizedConfigKey)
    ) {
      throw errors.invalidPayload();
    }
    const normalizedEncryptedValue = String(encryptedValue || '').trim();
    if (
      !normalizedEncryptedValue
      || CONTROL_CHAR_PATTERN.test(normalizedEncryptedValue)
    ) {
      throw errors.invalidPayload();
    }
    const parsedExpectedVersion = Number(expectedVersion);
    if (!Number.isInteger(parsedExpectedVersion) || parsedExpectedVersion < 0) {
      throw errors.invalidPayload();
    }
    let normalizedRemark = '';
    if (hasRemark) {
      if (remark === null || remark === undefined) {
        normalizedRemark = '';
      } else if (typeof remark === 'string') {
        normalizedRemark = remark.trim();
      } else {
        throw errors.invalidPayload();
      }
      if (
        CONTROL_CHAR_PATTERN.test(normalizedRemark)
        || normalizedRemark.length > MAX_SYSTEM_SENSITIVE_CONFIG_REMARK_LENGTH
      ) {
        throw errors.invalidPayload();
      }
    }
    const normalizedStatus = normalizeSystemSensitiveConfigStatus(status);
    if (!normalizedStatus) {
      throw errors.invalidPayload();
    }
    const normalizedUpdatedByUserId = normalizeStrictRequiredStringField(updatedByUserId);
    const normalizedUpdatedBySessionId = normalizeStrictRequiredStringField(updatedBySessionId);
    if (!normalizedUpdatedByUserId || !normalizedUpdatedBySessionId) {
      throw errors.invalidPayload();
    }

    assertStoreMethod(authStore, 'upsertSystemSensitiveConfig', 'authStore');
    let normalizedSavedRecord = null;
    try {
      const savedRecord = await authStore.upsertSystemSensitiveConfig({
        configKey: normalizedConfigKey,
        encryptedValue: normalizedEncryptedValue,
        remark: hasRemark ? normalizedRemark : undefined,
        hasRemark,
        expectedVersion: parsedExpectedVersion,
        updatedByUserId: normalizedUpdatedByUserId,
        status: normalizedStatus
      });
      normalizedSavedRecord = toSystemSensitiveConfigRecord(savedRecord);
      if (!normalizedSavedRecord) {
        throw new Error('system-sensitive-config-upsert-result-invalid');
      }
    } catch (error) {
      const currentVersion = Number(error?.currentVersion ?? error?.current_version ?? -1);
      const expectedVersionValue = Number(
        error?.expectedVersion ?? error?.expected_version ?? parsedExpectedVersion
      );
      const isVersionConflict =
        String(error?.code || '').trim() === 'ERR_SYSTEM_SENSITIVE_CONFIG_VERSION_CONFLICT';
      addAuditEvent({
        type: 'auth.system_config.update.rejected',
        requestId: normalizedRequestId,
        traceparent: normalizedTraceparent,
        userId: normalizedUpdatedByUserId,
        sessionId: normalizedUpdatedBySessionId,
        detail: isVersionConflict
          ? 'system sensitive config version conflict'
          : 'system sensitive config update failed',
        metadata: {
          key: normalizedConfigKey,
          expected_version: expectedVersionValue,
          current_version: Number.isInteger(currentVersion) && currentVersion >= 0
            ? currentVersion
            : null,
          failure_reason: isVersionConflict
            ? 'version-conflict'
            : String(error?.code || error?.message || 'unknown').trim().toLowerCase()
        }
      });
      await recordSystemSensitiveConfigAuditEvent({
        requestId: normalizedRequestId,
        traceparent: normalizedTraceparent,
        actorUserId: normalizedUpdatedByUserId,
        actorSessionId: normalizedUpdatedBySessionId,
        targetId: normalizedConfigKey,
        eventType: 'auth.system_config.update.rejected',
        result: 'rejected',
        beforeState: Number.isInteger(currentVersion) && currentVersion >= 0
          ? { version: currentVersion }
          : null,
        afterState: null,
        metadata: {
          key: normalizedConfigKey,
          expected_version: expectedVersionValue,
          current_version: Number.isInteger(currentVersion) && currentVersion >= 0
            ? currentVersion
            : null,
          failure_reason: isVersionConflict
            ? 'version-conflict'
            : String(error?.code || error?.message || 'unknown').trim().toLowerCase()
        }
      }).catch(() => {});
      throw error;
    }

    addAuditEvent({
      type: 'auth.system_config.updated',
      requestId: normalizedRequestId,
      traceparent: normalizedTraceparent,
      userId: normalizedUpdatedByUserId,
      sessionId: normalizedUpdatedBySessionId,
      detail: 'system sensitive config updated',
      metadata: {
        key: normalizedConfigKey,
        previous_version: normalizedSavedRecord.previousVersion,
        current_version: normalizedSavedRecord.version,
        status: normalizedSavedRecord.status
      }
    });
    try {
      await recordSystemSensitiveConfigAuditEvent({
        requestId: normalizedRequestId,
        traceparent: normalizedTraceparent,
        actorUserId: normalizedUpdatedByUserId,
        actorSessionId: normalizedUpdatedBySessionId,
        targetId: normalizedConfigKey,
        eventType: 'auth.system_config.updated',
        result: 'success',
        beforeState: {
          version: normalizedSavedRecord.previousVersion
        },
        afterState: {
          version: normalizedSavedRecord.version,
          status: normalizedSavedRecord.status
        },
        metadata: {
          key: normalizedConfigKey,
          previous_version: normalizedSavedRecord.previousVersion,
          current_version: normalizedSavedRecord.version,
          status: normalizedSavedRecord.status
        }
      });
    } catch (error) {
      addAuditEvent({
        type: 'auth.system_config.audit.degraded',
        requestId: normalizedRequestId,
        traceparent: normalizedTraceparent,
        userId: normalizedUpdatedByUserId,
        sessionId: normalizedUpdatedBySessionId,
        detail: 'system sensitive config persistent audit degraded',
        metadata: {
          key: normalizedConfigKey,
          previous_version: normalizedSavedRecord.previousVersion,
          current_version: normalizedSavedRecord.version,
          status: normalizedSavedRecord.status,
          failure_reason: String(
            error?.errorCode
              || error?.code
              || error?.message
              || 'audit-write-failed'
          ).trim().toLowerCase()
        }
      });
    }

    return normalizedSavedRecord;
  };

  return {
    recordSystemSensitiveConfigAuditEvent,
    getSystemSensitiveConfig,
    upsertSystemSensitiveConfig
  };
};

module.exports = {
  createPlatformSystemSensitiveConfigCapabilities
};
