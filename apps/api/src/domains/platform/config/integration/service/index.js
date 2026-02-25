const { log } = require('../../../../../common/logger');
const { AuthProblemError } = require('../../../../../shared-kernel/auth/auth-problem-error');
const {
  resolveRoutePreauthorizedContext
} = require('../../../../../shared-kernel/auth/route-authz');
const {
  PLATFORM_INTEGRATION_DIRECTIONS,
  PLATFORM_INTEGRATION_LIFECYCLE_STATUSES,
  PLATFORM_INTEGRATION_VIEW_PERMISSION_CODE,
  PLATFORM_INTEGRATION_OPERATE_PERMISSION_CODE,
  PLATFORM_INTEGRATION_SCOPE
} = require('../constants');
const { integrationErrors, integrationProblem, mapStoreError } = require('./service.errors');
const { parseCreatePayload, parseLifecyclePayload, parseListQuery, parseUpdatePayload } = require('./service.parsers');
const { CONTROL_CHAR_PATTERN, CREATE_ALLOWED_FIELDS, DEFAULT_PAGE, DEFAULT_PAGE_SIZE, DEFAULT_TIMEOUT_MS, LIFECYCLE_ALLOWED_FIELDS, LIST_ALLOWED_QUERY_FIELDS, MAX_AUDIT_TRAIL_ENTRIES, MAX_AUTH_MODE_LENGTH, MAX_BASE_URL_LENGTH, MAX_CODE_LENGTH, MAX_ENDPOINT_LENGTH, MAX_FREEZE_ID_LENGTH, MAX_FREEZE_REASON_LENGTH, MAX_INTEGRATION_ID_LENGTH, MAX_LIFECYCLE_REASON_LENGTH, MAX_LIST_KEYWORD_LENGTH, MAX_NAME_LENGTH, MAX_OPERATOR_USER_ID_LENGTH, MAX_PAGE_SIZE, MAX_PROTOCOL_LENGTH, MAX_RUNBOOK_URL_LENGTH, MAX_TIMEOUT_MS, MAX_VERSION_STRATEGY_LENGTH, UPDATE_ALLOWED_FIELDS, VALID_DIRECTIONS, VALID_LIFECYCLE_STATUSES, isPlainObject, mapActiveFreezeRecordForWriteGate, mapIntegrationRecord, normalizeDirection, normalizeIntegrationId, normalizeLifecycleStatus, normalizePolicyPayload, normalizeStoreIsoTimestamp, normalizeStoreOptionalString, normalizeStrictOptionalString, normalizeStrictRequiredString, resolveStoreFieldValue } = require('./service.helpers');

const createPlatformIntegrationService = ({ authService } = {}) => {
  const auditTrail = [];

  const addAuditEvent = ({
    type,
    requestId,
    operatorUserId = 'unknown',
    targetIntegrationId = null,
    detail,
    metadata = {}
  }) => {
    const event = {
      type: String(type || '').trim() || 'platform.integration.unknown',
      at: new Date().toISOString(),
      request_id: String(requestId || '').trim() || 'request_id_unset',
      operator_user_id: String(operatorUserId || '').trim() || 'unknown',
      target_integration_id: targetIntegrationId ? String(targetIntegrationId) : null,
      detail: String(detail || '').trim(),
      ...metadata
    };
    auditTrail.push(event);
    if (auditTrail.length > MAX_AUDIT_TRAIL_ENTRIES) {
      auditTrail.splice(0, auditTrail.length - MAX_AUDIT_TRAIL_ENTRIES);
    }
    log('info', 'Platform integration audit event', event);
  };

  const assertAuthServiceMethod = (methodName) => {
    if (!authService || typeof authService[methodName] !== 'function') {
      throw integrationErrors.dependencyUnavailable();
    }
  };

  const resolveAuthStore = () => authService?._internals?.authStore || null;

  const assertAuthStoreMethod = (methodName) => {
    const authStore = resolveAuthStore();
    if (!authStore || typeof authStore[methodName] !== 'function') {
      throw integrationErrors.dependencyUnavailable({
        reason: `auth-store-${methodName}-unsupported`
      });
    }
    return authStore;
  };

  const recordFreezeChangeBlockedAuditEvent = async ({
    requestId,
    traceparent = null,
    operatorUserId = null,
    operatorSessionId = null,
    targetIntegrationId = null,
    changeOperation = 'unknown',
    activeFreeze = null,
    changePayload = null
  } = {}) => {
    const authStore = assertAuthStoreMethod('recordAuditEvent');
    try {
      await authStore.recordAuditEvent({
        domain: 'platform',
        requestId,
        traceparent,
        eventType: 'platform.integration.freeze.change_blocked',
        actorUserId: operatorUserId,
        actorSessionId: operatorSessionId,
        targetType: 'integration',
        targetId: targetIntegrationId,
        result: 'rejected',
        beforeState: activeFreeze
          ? {
            freeze_id: activeFreeze.freeze_id,
            status: activeFreeze.status,
            freeze_reason: activeFreeze.freeze_reason,
            frozen_at: activeFreeze.frozen_at
          }
          : null,
        afterState: null,
        metadata: {
          change_operation: String(changeOperation || '').trim() || 'unknown',
          change_payload: isPlainObject(changePayload) ? changePayload : null
        }
      });
    } catch (error) {
      throw mapStoreError(error);
    }
  };

  const maybeRecordFreezeBlockedAuditEvent = async ({
    mappedError = null,
    requestId,
    traceparent = null,
    operatorUserId = null,
    operatorSessionId = null,
    targetIntegrationId = null,
    changeOperation = 'unknown',
    changePayload = null
  } = {}) => {
    if (
      !(mappedError instanceof AuthProblemError)
      || mappedError.errorCode !== 'INT-409-INTEGRATION-FREEZE-BLOCKED'
    ) {
      return;
    }
    let activeFreeze = null;
    try {
      const authStore = assertAuthStoreMethod('findActivePlatformIntegrationFreeze');
      activeFreeze = mapActiveFreezeRecordForWriteGate({
        record: await authStore.findActivePlatformIntegrationFreeze()
      });
    } catch (_error) {
      activeFreeze = null;
    }
    if (!activeFreeze) {
      const freezeId = normalizeIntegrationId(mappedError?.extensions?.freeze_id);
      const frozenAt = normalizeStoreIsoTimestamp(mappedError?.extensions?.frozen_at);
      if (freezeId && frozenAt) {
        activeFreeze = {
          freeze_id: freezeId,
          status: 'active',
          freeze_reason: null,
          frozen_at: frozenAt
        };
      }
    }
    if (!activeFreeze) {
      return;
    }
    await recordFreezeChangeBlockedAuditEvent({
      requestId,
      traceparent,
      operatorUserId,
      operatorSessionId,
      targetIntegrationId,
      changeOperation,
      activeFreeze,
      changePayload
    });
  };

  const assertNotFrozenForWrite = async ({
    requestId,
    traceparent = null,
    operatorUserId = null,
    operatorSessionId = null,
    targetIntegrationId = null,
    changeOperation = 'unknown',
    changePayload = null
  } = {}) => {
    const authStore = assertAuthStoreMethod('findActivePlatformIntegrationFreeze');
    let activeFreezeRecord;
    try {
      activeFreezeRecord = await authStore.findActivePlatformIntegrationFreeze();
    } catch (error) {
      throw mapStoreError(error);
    }
    if (!activeFreezeRecord) {
      return;
    }
    const activeFreeze = mapActiveFreezeRecordForWriteGate({
      record: activeFreezeRecord
    });
    if (!activeFreeze) {
      throw integrationErrors.dependencyUnavailable({
        reason: 'integration-freeze-state-malformed'
      });
    }
    await recordFreezeChangeBlockedAuditEvent({
      requestId,
      traceparent,
      operatorUserId,
      operatorSessionId,
      targetIntegrationId,
      changeOperation,
      activeFreeze,
      changePayload
    });
    throw integrationErrors.freezeBlocked({
      freezeId: activeFreeze.freeze_id,
      frozenAt: activeFreeze.frozen_at
    });
  };

  const resolvePreauthorizedOperatorContext = ({
    authorizationContext = null,
    expectedPermissionCode = PLATFORM_INTEGRATION_OPERATE_PERMISSION_CODE
  } = {}) => {
    const preauthorizedContext = resolveRoutePreauthorizedContext({
      authorizationContext,
      expectedPermissionCode,
      expectedScope: PLATFORM_INTEGRATION_SCOPE,
      expectedEntryDomain: PLATFORM_INTEGRATION_SCOPE
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
    permissionCode = PLATFORM_INTEGRATION_OPERATE_PERMISSION_CODE
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
      scope: PLATFORM_INTEGRATION_SCOPE,
      authorizationContext
    });
    const operatorUserId = normalizeStrictRequiredString(
      authorized?.user_id || authorized?.userId
    );
    const operatorSessionId = normalizeStrictRequiredString(
      authorized?.session_id || authorized?.sessionId
    );
    if (!operatorUserId || !operatorSessionId) {
      throw integrationErrors.forbidden();
    }
    return {
      operatorUserId,
      operatorSessionId
    };
  };

  const listIntegrations = async ({
    requestId,
    accessToken,
    query = {},
    authorizationContext = null
  }) => {
    const resolvedRequestId = String(requestId || '').trim() || 'request_id_unset';
    const filters = parseListQuery(query || {});
    let operatorContext;
    try {
      operatorContext = await resolveOperatorContext({
        requestId: resolvedRequestId,
        accessToken,
        authorizationContext,
        permissionCode: PLATFORM_INTEGRATION_VIEW_PERMISSION_CODE
      });
    } catch (error) {
      addAuditEvent({
        type: 'platform.integration.list.rejected',
        requestId: resolvedRequestId,
        detail: 'operator authorization context invalid',
        metadata: {
          error_code: String(error?.errorCode || 'AUTH-403-FORBIDDEN')
        }
      });
      throw error;
    }
    const authStore = assertAuthStoreMethod('listPlatformIntegrationCatalogEntries');
    let list;
    try {
      list = await authStore.listPlatformIntegrationCatalogEntries({
        direction: filters.direction,
        protocol: filters.protocol,
        authMode: filters.authMode,
        lifecycleStatus: filters.lifecycleStatus,
        keyword: filters.keyword
      });
    } catch (error) {
      const mappedError = mapStoreError(error);
      addAuditEvent({
        type: 'platform.integration.list.rejected',
        requestId: resolvedRequestId,
        operatorUserId: operatorContext.operatorUserId,
        detail: 'integration catalog list dependency unavailable',
        metadata: {
          error_code: mappedError.errorCode
        }
      });
      throw mappedError;
    }
    if (!Array.isArray(list)) {
      throw integrationErrors.dependencyUnavailable({
        reason: 'integration-catalog-list-invalid'
      });
    }
    const mappedIntegrations = list.map((record) =>
      mapIntegrationRecord({
        record,
        requestId: resolvedRequestId
      })
    );
    if (mappedIntegrations.some((record) => !record)) {
      throw integrationErrors.dependencyUnavailable({
        reason: 'integration-catalog-list-result-malformed'
      });
    }
    const total = mappedIntegrations.length;
    const start = (filters.page - 1) * filters.pageSize;
    const end = start + filters.pageSize;
    const pagedIntegrations = mappedIntegrations.slice(start, end);
    addAuditEvent({
      type: 'platform.integration.list.succeeded',
      requestId: resolvedRequestId,
      operatorUserId: operatorContext.operatorUserId,
      detail: 'integration catalog listed',
      metadata: {
        total
      }
    });
    return {
      page: filters.page,
      page_size: filters.pageSize,
      total,
      integrations: pagedIntegrations,
      request_id: resolvedRequestId
    };
  };

  const getIntegration = async ({
    requestId,
    accessToken,
    integrationId,
    authorizationContext = null
  }) => {
    const resolvedRequestId = String(requestId || '').trim() || 'request_id_unset';
    const normalizedIntegrationId = normalizeIntegrationId(integrationId);
    if (
      !normalizedIntegrationId
      || normalizedIntegrationId.length > MAX_INTEGRATION_ID_LENGTH
    ) {
      throw integrationErrors.invalidPayload('integration_id 非法');
    }
    let operatorContext;
    try {
      operatorContext = await resolveOperatorContext({
        requestId: resolvedRequestId,
        accessToken,
        authorizationContext,
        permissionCode: PLATFORM_INTEGRATION_VIEW_PERMISSION_CODE
      });
    } catch (error) {
      addAuditEvent({
        type: 'platform.integration.read.rejected',
        requestId: resolvedRequestId,
        targetIntegrationId: normalizedIntegrationId,
        detail: 'operator authorization context invalid',
        metadata: {
          error_code: String(error?.errorCode || 'AUTH-403-FORBIDDEN')
        }
      });
      throw error;
    }
    const authStore = assertAuthStoreMethod(
      'findPlatformIntegrationCatalogEntryByIntegrationId'
    );
    let record = null;
    try {
      record = await authStore.findPlatformIntegrationCatalogEntryByIntegrationId({
        integrationId: normalizedIntegrationId
      });
    } catch (error) {
      throw mapStoreError(error);
    }
    if (!record) {
      throw integrationErrors.integrationNotFound();
    }
    const mapped = mapIntegrationRecord({
      record,
      requestId: resolvedRequestId
    });
    if (!mapped) {
      throw integrationErrors.dependencyUnavailable({
        reason: 'integration-catalog-read-result-invalid'
      });
    }
    addAuditEvent({
      type: 'platform.integration.read.succeeded',
      requestId: resolvedRequestId,
      operatorUserId: operatorContext.operatorUserId,
      targetIntegrationId: normalizedIntegrationId,
      detail: 'integration catalog entry loaded'
    });
    return mapped;
  };

  const createIntegration = async ({
    requestId,
    accessToken,
    payload = {},
    traceparent = null,
    authorizationContext = null
  }) => {
    const resolvedRequestId = String(requestId || '').trim() || 'request_id_unset';
    const parsedPayload = parseCreatePayload(payload);
    const operatorContext = await resolveOperatorContext({
      requestId: resolvedRequestId,
      accessToken,
      authorizationContext,
      permissionCode: PLATFORM_INTEGRATION_OPERATE_PERMISSION_CODE
    });
    await assertNotFrozenForWrite({
      requestId: resolvedRequestId,
      traceparent,
      operatorUserId: operatorContext.operatorUserId,
      operatorSessionId: operatorContext.operatorSessionId,
      targetIntegrationId: parsedPayload.integrationId || null,
      changeOperation: 'create',
      changePayload: {
        integration_id: parsedPayload.integrationId || null,
        code: parsedPayload.code,
        direction: parsedPayload.direction,
        lifecycle_status: parsedPayload.lifecycleStatus
      }
    });
    const authStore = assertAuthStoreMethod('createPlatformIntegrationCatalogEntry');
    let createdRecord = null;
    try {
      createdRecord = await authStore.createPlatformIntegrationCatalogEntry({
        integrationId: parsedPayload.integrationId,
        code: parsedPayload.code,
        name: parsedPayload.name,
        direction: parsedPayload.direction,
        protocol: parsedPayload.protocol,
        authMode: parsedPayload.authMode,
        endpoint: parsedPayload.endpoint,
        baseUrl: parsedPayload.baseUrl,
        timeoutMs: parsedPayload.timeoutMs,
        retryPolicy: parsedPayload.retryPolicy,
        idempotencyPolicy: parsedPayload.idempotencyPolicy,
        versionStrategy: parsedPayload.versionStrategy,
        runbookUrl: parsedPayload.runbookUrl,
        lifecycleStatus: parsedPayload.lifecycleStatus,
        lifecycleReason: parsedPayload.lifecycleReason,
        operatorUserId: operatorContext.operatorUserId,
        operatorSessionId: operatorContext.operatorSessionId,
        auditContext: {
          requestId: resolvedRequestId,
          traceparent,
          actorUserId: operatorContext.operatorUserId,
          actorSessionId: operatorContext.operatorSessionId
        }
      });
    } catch (error) {
      const mappedError = mapStoreError(error);
      await maybeRecordFreezeBlockedAuditEvent({
        mappedError,
        requestId: resolvedRequestId,
        traceparent,
        operatorUserId: operatorContext.operatorUserId,
        operatorSessionId: operatorContext.operatorSessionId,
        targetIntegrationId: parsedPayload.integrationId || null,
        changeOperation: 'create',
        changePayload: {
          integration_id: parsedPayload.integrationId || null,
          code: parsedPayload.code,
          direction: parsedPayload.direction,
          lifecycle_status: parsedPayload.lifecycleStatus
        }
      });
      addAuditEvent({
        type: 'platform.integration.create.rejected',
        requestId: resolvedRequestId,
        operatorUserId: operatorContext.operatorUserId,
        detail: 'integration catalog create failed',
        metadata: {
          error_code: mappedError.errorCode
        }
      });
      throw mappedError;
    }
    const mapped = mapIntegrationRecord({
      record: createdRecord,
      requestId: resolvedRequestId
    });
    if (!mapped) {
      throw integrationErrors.dependencyUnavailable({
        reason: 'integration-catalog-create-result-invalid'
      });
    }
    addAuditEvent({
      type: 'platform.integration.create.succeeded',
      requestId: resolvedRequestId,
      operatorUserId: operatorContext.operatorUserId,
      targetIntegrationId: mapped.integration_id,
      detail: 'integration catalog entry created'
    });
    return mapped;
  };

  const updateIntegration = async ({
    requestId,
    accessToken,
    integrationId,
    payload = {},
    traceparent = null,
    authorizationContext = null
  }) => {
    const resolvedRequestId = String(requestId || '').trim() || 'request_id_unset';
    const normalizedIntegrationId = normalizeIntegrationId(integrationId);
    if (
      !normalizedIntegrationId
      || normalizedIntegrationId.length > MAX_INTEGRATION_ID_LENGTH
    ) {
      throw integrationErrors.invalidPayload('integration_id 非法');
    }
    const parsedPayload = parseUpdatePayload(payload);
    const operatorContext = await resolveOperatorContext({
      requestId: resolvedRequestId,
      accessToken,
      authorizationContext,
      permissionCode: PLATFORM_INTEGRATION_OPERATE_PERMISSION_CODE
    });
    await assertNotFrozenForWrite({
      requestId: resolvedRequestId,
      traceparent,
      operatorUserId: operatorContext.operatorUserId,
      operatorSessionId: operatorContext.operatorSessionId,
      targetIntegrationId: normalizedIntegrationId,
      changeOperation: 'update',
      changePayload: {
        integration_id: normalizedIntegrationId,
        fields: Object.keys(parsedPayload)
      }
    });
    const authStore = assertAuthStoreMethod('updatePlatformIntegrationCatalogEntry');
    let updatedRecord = null;
    try {
      updatedRecord = await authStore.updatePlatformIntegrationCatalogEntry({
        integrationId: normalizedIntegrationId,
        code: parsedPayload.code,
        name: parsedPayload.name,
        direction: parsedPayload.direction,
        protocol: parsedPayload.protocol,
        authMode: parsedPayload.authMode,
        endpoint: parsedPayload.endpoint,
        baseUrl: parsedPayload.baseUrl,
        timeoutMs: parsedPayload.timeoutMs,
        retryPolicy: parsedPayload.retryPolicy,
        idempotencyPolicy: parsedPayload.idempotencyPolicy,
        versionStrategy: parsedPayload.versionStrategy,
        runbookUrl: parsedPayload.runbookUrl,
        lifecycleReason: parsedPayload.lifecycleReason,
        operatorUserId: operatorContext.operatorUserId,
        operatorSessionId: operatorContext.operatorSessionId,
        auditContext: {
          requestId: resolvedRequestId,
          traceparent,
          actorUserId: operatorContext.operatorUserId,
          actorSessionId: operatorContext.operatorSessionId
        }
      });
    } catch (error) {
      const mappedError = mapStoreError(error);
      await maybeRecordFreezeBlockedAuditEvent({
        mappedError,
        requestId: resolvedRequestId,
        traceparent,
        operatorUserId: operatorContext.operatorUserId,
        operatorSessionId: operatorContext.operatorSessionId,
        targetIntegrationId: normalizedIntegrationId,
        changeOperation: 'update',
        changePayload: {
          integration_id: normalizedIntegrationId,
          fields: Object.keys(parsedPayload)
        }
      });
      addAuditEvent({
        type: 'platform.integration.update.rejected',
        requestId: resolvedRequestId,
        operatorUserId: operatorContext.operatorUserId,
        targetIntegrationId: normalizedIntegrationId,
        detail: 'integration catalog update failed',
        metadata: {
          error_code: mappedError.errorCode
        }
      });
      throw mappedError;
    }
    if (!updatedRecord) {
      throw integrationErrors.integrationNotFound();
    }
    const mapped = mapIntegrationRecord({
      record: updatedRecord,
      requestId: resolvedRequestId
    });
    if (!mapped) {
      throw integrationErrors.dependencyUnavailable({
        reason: 'integration-catalog-update-result-invalid'
      });
    }
    addAuditEvent({
      type: 'platform.integration.update.succeeded',
      requestId: resolvedRequestId,
      operatorUserId: operatorContext.operatorUserId,
      targetIntegrationId: normalizedIntegrationId,
      detail: 'integration catalog entry updated'
    });
    return mapped;
  };

  const changeIntegrationLifecycle = async ({
    requestId,
    accessToken,
    integrationId,
    payload = {},
    traceparent = null,
    authorizationContext = null
  }) => {
    const resolvedRequestId = String(requestId || '').trim() || 'request_id_unset';
    const normalizedIntegrationId = normalizeIntegrationId(integrationId);
    if (
      !normalizedIntegrationId
      || normalizedIntegrationId.length > MAX_INTEGRATION_ID_LENGTH
    ) {
      throw integrationErrors.invalidPayload('integration_id 非法');
    }
    const parsedPayload = parseLifecyclePayload(payload);
    const operatorContext = await resolveOperatorContext({
      requestId: resolvedRequestId,
      accessToken,
      authorizationContext,
      permissionCode: PLATFORM_INTEGRATION_OPERATE_PERMISSION_CODE
    });
    await assertNotFrozenForWrite({
      requestId: resolvedRequestId,
      traceparent,
      operatorUserId: operatorContext.operatorUserId,
      operatorSessionId: operatorContext.operatorSessionId,
      targetIntegrationId: normalizedIntegrationId,
      changeOperation: 'change_lifecycle',
      changePayload: {
        integration_id: normalizedIntegrationId,
        requested_status: parsedPayload.nextStatus,
        reason: parsedPayload.reason
      }
    });
    const authStore = assertAuthStoreMethod('transitionPlatformIntegrationLifecycle');
    let transitionResult = null;
    try {
      transitionResult = await authStore.transitionPlatformIntegrationLifecycle({
        integrationId: normalizedIntegrationId,
        nextStatus: parsedPayload.nextStatus,
        reason: parsedPayload.reason,
        operatorUserId: operatorContext.operatorUserId,
        operatorSessionId: operatorContext.operatorSessionId,
        auditContext: {
          requestId: resolvedRequestId,
          traceparent,
          actorUserId: operatorContext.operatorUserId,
          actorSessionId: operatorContext.operatorSessionId
        }
      });
    } catch (error) {
      const mappedError = mapStoreError(error);
      await maybeRecordFreezeBlockedAuditEvent({
        mappedError,
        requestId: resolvedRequestId,
        traceparent,
        operatorUserId: operatorContext.operatorUserId,
        operatorSessionId: operatorContext.operatorSessionId,
        targetIntegrationId: normalizedIntegrationId,
        changeOperation: 'change_lifecycle',
        changePayload: {
          integration_id: normalizedIntegrationId,
          requested_status: parsedPayload.nextStatus,
          reason: parsedPayload.reason
        }
      });
      addAuditEvent({
        type: 'platform.integration.lifecycle.rejected',
        requestId: resolvedRequestId,
        operatorUserId: operatorContext.operatorUserId,
        targetIntegrationId: normalizedIntegrationId,
        detail: 'integration lifecycle transition failed',
        metadata: {
          error_code: mappedError.errorCode
        }
      });
      throw mappedError;
    }
    if (!transitionResult) {
      throw integrationErrors.integrationNotFound();
    }
    const mapped = mapIntegrationRecord({
      record: transitionResult,
      requestId: resolvedRequestId
    });
    if (!mapped) {
      throw integrationErrors.dependencyUnavailable({
        reason: 'integration-lifecycle-result-invalid'
      });
    }
    const previousStatus = normalizeLifecycleStatus(
      transitionResult.previousStatus || transitionResult.previous_status || ''
    );
    const currentStatus = normalizeLifecycleStatus(
      transitionResult.currentStatus || transitionResult.current_status || ''
    );
    if (
      !VALID_LIFECYCLE_STATUSES.has(previousStatus)
      || !VALID_LIFECYCLE_STATUSES.has(currentStatus)
      || currentStatus !== mapped.lifecycle_status
    ) {
      throw integrationErrors.dependencyUnavailable({
        reason: 'integration-lifecycle-result-malformed'
      });
    }
    const hasExplicitEffectiveInvocationEnabled =
      Object.prototype.hasOwnProperty.call(
        transitionResult,
        'effectiveInvocationEnabled'
      )
      || Object.prototype.hasOwnProperty.call(
        transitionResult,
        'effective_invocation_enabled'
      );
    const explicitEffectiveInvocationEnabled =
      transitionResult.effectiveInvocationEnabled === undefined
        ? transitionResult.effective_invocation_enabled
        : transitionResult.effectiveInvocationEnabled;
    if (
      hasExplicitEffectiveInvocationEnabled
      && typeof explicitEffectiveInvocationEnabled !== 'boolean'
    ) {
      throw integrationErrors.dependencyUnavailable({
        reason: 'integration-lifecycle-result-malformed'
      });
    }
    const derivedEffectiveInvocationEnabled = currentStatus === 'active';
    if (
      hasExplicitEffectiveInvocationEnabled
      && explicitEffectiveInvocationEnabled !== derivedEffectiveInvocationEnabled
    ) {
      throw integrationErrors.dependencyUnavailable({
        reason: 'integration-lifecycle-result-malformed'
      });
    }
    const effectiveInvocationEnabled = derivedEffectiveInvocationEnabled;
    addAuditEvent({
      type: 'platform.integration.lifecycle.succeeded',
      requestId: resolvedRequestId,
      operatorUserId: operatorContext.operatorUserId,
      targetIntegrationId: normalizedIntegrationId,
      detail: 'integration lifecycle transitioned',
      metadata: {
        previous_status: previousStatus,
        current_status: currentStatus
      }
    });
    return {
      ...mapped,
      previous_status: previousStatus,
      current_status: currentStatus,
      effective_invocation_enabled: effectiveInvocationEnabled
    };
  };

  return {
    listIntegrations,
    getIntegration,
    createIntegration,
    updateIntegration,
    changeIntegrationLifecycle,
    _internals: {
      authService,
      auditTrail
    }
  };
};

module.exports = {
  createPlatformIntegrationService
};
