const { log } = require('../../../../../common/logger');
const { AuthProblemError } = require('../../../../../shared-kernel/auth/auth-problem-error');
const {
  resolveRoutePreauthorizedContext
} = require('../../../../../shared-kernel/auth/route-authz');
const {
  PLATFORM_INTEGRATION_RECOVERY_VIEW_PERMISSION_CODE,
  PLATFORM_INTEGRATION_RECOVERY_OPERATE_PERMISSION_CODE,
  PLATFORM_INTEGRATION_RECOVERY_SCOPE,
  PLATFORM_INTEGRATION_RECOVERY_STATUS_ENUM
} = require('../constants');
const { CONTROL_CHAR_PATTERN, DEFAULT_LIST_LIMIT, LIST_ALLOWED_QUERY_FIELDS, MAX_AUDIT_TRAIL_ENTRIES, MAX_CONTRACT_VERSION_LENGTH, MAX_FAILURE_CODE_LENGTH, MAX_FAILURE_DETAIL_LENGTH, MAX_IDEMPOTENCY_KEY_LENGTH, MAX_INTEGRATION_ID_LENGTH, MAX_LIST_LIMIT, MAX_OPERATOR_USER_ID_LENGTH, MAX_RECOVERY_ID_LENGTH, MAX_REPLAY_REASON_LENGTH, MAX_REQUEST_ID_LENGTH, MAX_TRACEPARENT_LENGTH, REPLAY_ALLOWED_FIELDS, VALID_CONTRACT_TYPES, VALID_INTEGRATION_LIFECYCLE_STATUSES, VALID_RECOVERY_STATUSES, isPlainObject, mapRecoveryRecord, mapStoreError, normalizeContractType, normalizeContractVersion, normalizeIntegrationId, normalizeLastHttpStatus, normalizeRecoveryId, normalizeRecoveryStatus, normalizeStoreIsoTimestamp, normalizeStoreOptionalString, normalizeStrictOptionalString, normalizeStrictRequiredString, parseJsonValue, parseListQuery, parseReplayPayload, recoveryErrors, recoveryProblem, resolveStoreFieldValue } = require('./service.helpers');

const createPlatformIntegrationRecoveryService = ({
  authService,
  deliveryExecutor = null
} = {}) => {
  const auditTrail = [];

  const addAuditEvent = ({
    type,
    requestId,
    operatorUserId = 'unknown',
    integrationId = null,
    recoveryId = null,
    detail,
    metadata = {}
  }) => {
    const event = {
      type: String(type || '').trim() || 'platform.integration.recovery.unknown',
      at: new Date().toISOString(),
      request_id: String(requestId || '').trim() || 'request_id_unset',
      operator_user_id: String(operatorUserId || '').trim() || 'unknown',
      integration_id: integrationId ? String(integrationId) : null,
      recovery_id: recoveryId ? String(recoveryId) : null,
      detail: String(detail || '').trim(),
      ...metadata
    };
    auditTrail.push(event);
    if (auditTrail.length > MAX_AUDIT_TRAIL_ENTRIES) {
      auditTrail.splice(0, auditTrail.length - MAX_AUDIT_TRAIL_ENTRIES);
    }
    log('info', 'Platform integration recovery audit event', event);
  };

  const assertAuthServiceMethod = (methodName) => {
    if (!authService || typeof authService[methodName] !== 'function') {
      throw recoveryErrors.dependencyUnavailable();
    }
  };

  const resolveAuthStore = () => authService?._internals?.authStore || null;

  const resolveDeliveryExecutor = () => {
    if (typeof deliveryExecutor === 'function') {
      return deliveryExecutor;
    }
    if (typeof authService?.executePlatformIntegrationRecoveryDelivery === 'function') {
      return authService.executePlatformIntegrationRecoveryDelivery.bind(authService);
    }
    return null;
  };

  const assertAuthStoreMethod = (methodName) => {
    const authStore = resolveAuthStore();
    if (!authStore || typeof authStore[methodName] !== 'function') {
      throw recoveryErrors.dependencyUnavailable({
        reason: `auth-store-${methodName}-unsupported`
      });
    }
    return authStore;
  };

  const resolvePreauthorizedOperatorContext = ({
    authorizationContext = null,
    expectedPermissionCode = PLATFORM_INTEGRATION_RECOVERY_OPERATE_PERMISSION_CODE
  } = {}) => {
    const preauthorizedContext = resolveRoutePreauthorizedContext({
      authorizationContext,
      expectedPermissionCode,
      expectedScope: PLATFORM_INTEGRATION_RECOVERY_SCOPE,
      expectedEntryDomain: PLATFORM_INTEGRATION_RECOVERY_SCOPE
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
    permissionCode = PLATFORM_INTEGRATION_RECOVERY_OPERATE_PERMISSION_CODE
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
      scope: PLATFORM_INTEGRATION_RECOVERY_SCOPE,
      authorizationContext
    });
    const operatorUserId = normalizeStrictRequiredString(
      authorized?.user_id || authorized?.userId
    );
    const operatorSessionId = normalizeStrictRequiredString(
      authorized?.session_id || authorized?.sessionId
    );
    if (!operatorUserId || !operatorSessionId) {
      throw recoveryErrors.forbidden();
    }
    return {
      operatorUserId,
      operatorSessionId
    };
  };

  const getIntegrationEntry = async ({ integrationId }) => {
    const authStore = assertAuthStoreMethod(
      'findPlatformIntegrationCatalogEntryByIntegrationId'
    );
    let record;
    try {
      record = await authStore.findPlatformIntegrationCatalogEntryByIntegrationId({
        integrationId
      });
    } catch (error) {
      throw mapStoreError(error);
    }
    if (!record) {
      return null;
    }
    const requestedIntegrationId = normalizeIntegrationId(integrationId);
    const recordIntegrationId = normalizeIntegrationId(
      record.integrationId || record.integration_id
    );
    const lifecycleStatus = String(
      record.lifecycleStatus === undefined
        ? record.lifecycle_status
        : record.lifecycleStatus
    ).trim().toLowerCase();
    if (
      !requestedIntegrationId
      || !recordIntegrationId
      || recordIntegrationId.length > MAX_INTEGRATION_ID_LENGTH
      || requestedIntegrationId !== recordIntegrationId
      || !VALID_INTEGRATION_LIFECYCLE_STATUSES.has(lifecycleStatus)
    ) {
      throw recoveryErrors.dependencyUnavailable({
        reason: 'integration-catalog-record-invalid'
      });
    }
    return {
      integration_id: recordIntegrationId,
      lifecycle_status: lifecycleStatus
    };
  };

  const listRecoveryQueue = async ({
    requestId,
    accessToken,
    integrationId,
    query = {},
    authorizationContext = null
  }) => {
    const resolvedRequestId = String(requestId || '').trim() || 'request_id_unset';
    const normalizedIntegrationId = normalizeIntegrationId(integrationId);
    if (
      !normalizedIntegrationId
      || normalizedIntegrationId.length > MAX_INTEGRATION_ID_LENGTH
    ) {
      throw recoveryErrors.invalidPayload('integration_id 非法');
    }
    const filters = parseListQuery(query || {});

    const operatorContext = await resolveOperatorContext({
      requestId: resolvedRequestId,
      accessToken,
      authorizationContext,
      permissionCode: PLATFORM_INTEGRATION_RECOVERY_VIEW_PERMISSION_CODE
    });

    const integrationEntry = await getIntegrationEntry({
      integrationId: normalizedIntegrationId
    });
    if (!integrationEntry) {
      throw recoveryErrors.integrationNotFound({
        integrationId: normalizedIntegrationId
      });
    }

    const authStore = assertAuthStoreMethod('listPlatformIntegrationRecoveryQueueEntries');
    let records = [];
    try {
      records = await authStore.listPlatformIntegrationRecoveryQueueEntries({
        integrationId: normalizedIntegrationId,
        status: filters.status,
        limit: filters.limit
      });
    } catch (error) {
      const mappedError = mapStoreError(error);
      addAuditEvent({
        type: 'platform.integration.recovery.queue.list.rejected',
        requestId: resolvedRequestId,
        operatorUserId: operatorContext.operatorUserId,
        integrationId: normalizedIntegrationId,
        detail: 'integration recovery queue list failed',
        metadata: {
          error_code: mappedError.errorCode
        }
      });
      throw mappedError;
    }

    if (!Array.isArray(records)) {
      throw recoveryErrors.dependencyUnavailable({
        reason: 'integration-recovery-list-result-malformed'
      });
    }
    const queue = records.map((record) => mapRecoveryRecord({ record }));
    if (
      queue.some((record) => !record)
      || queue.some((record) => record.integration_id !== normalizedIntegrationId)
      || (
        filters.status
        && queue.some((record) => record.status !== filters.status)
      )
    ) {
      throw recoveryErrors.dependencyUnavailable({
        reason: 'integration-recovery-list-result-malformed'
      });
    }

    addAuditEvent({
      type: 'platform.integration.recovery.queue.list.succeeded',
      requestId: resolvedRequestId,
      operatorUserId: operatorContext.operatorUserId,
      integrationId: normalizedIntegrationId,
      detail: 'integration recovery queue listed',
      metadata: {
        total: queue.length,
        status: filters.status
      }
    });

    return {
      integration_id: normalizedIntegrationId,
      lifecycle_status: integrationEntry.lifecycle_status,
      status: filters.status,
      limit: filters.limit,
      queue,
      request_id: resolvedRequestId
    };
  };

  const replayRecoveryQueueItem = async ({
    requestId,
    accessToken,
    integrationId,
    recoveryId,
    payload = {},
    traceparent = null,
    authorizationContext = null
  }) => {
    const resolvedRequestId = String(requestId || '').trim() || 'request_id_unset';
    const normalizedIntegrationId = normalizeIntegrationId(integrationId);
    const normalizedRecoveryId = normalizeRecoveryId(recoveryId);
    if (
      !normalizedIntegrationId
      || normalizedIntegrationId.length > MAX_INTEGRATION_ID_LENGTH
      || !normalizedRecoveryId
      || normalizedRecoveryId.length > MAX_RECOVERY_ID_LENGTH
    ) {
      throw recoveryErrors.invalidPayload('integration_id 或 recovery_id 非法');
    }
    const parsedPayload = parseReplayPayload(payload || {});

    const operatorContext = await resolveOperatorContext({
      requestId: resolvedRequestId,
      accessToken,
      authorizationContext,
      permissionCode: PLATFORM_INTEGRATION_RECOVERY_OPERATE_PERMISSION_CODE
    });

    const integrationEntry = await getIntegrationEntry({
      integrationId: normalizedIntegrationId
    });
    if (!integrationEntry) {
      throw recoveryErrors.integrationNotFound({
        integrationId: normalizedIntegrationId
      });
    }

    const authStore = assertAuthStoreMethod('replayPlatformIntegrationRecoveryQueueEntry');
    let replayResult = null;
    try {
      replayResult = await authStore.replayPlatformIntegrationRecoveryQueueEntry({
        integrationId: normalizedIntegrationId,
        recoveryId: normalizedRecoveryId,
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
      addAuditEvent({
        type: 'platform.integration.recovery.queue.replay.rejected',
        requestId: resolvedRequestId,
        operatorUserId: operatorContext.operatorUserId,
        integrationId: normalizedIntegrationId,
        recoveryId: normalizedRecoveryId,
        detail: 'integration recovery replay failed',
        metadata: {
          error_code: mappedError.errorCode
        }
      });
      throw mappedError;
    }

    if (!replayResult) {
      throw recoveryErrors.recoveryNotFound({
        integrationId: normalizedIntegrationId,
        recoveryId: normalizedRecoveryId
      });
    }

    const mappedRecovery = mapRecoveryRecord({
      record: replayResult
    });
    const previousStatus = normalizeRecoveryStatus(
      replayResult.previousStatus || replayResult.previous_status || ''
    );
    const currentStatus = normalizeRecoveryStatus(
      replayResult.currentStatus || replayResult.current_status || mappedRecovery?.status || ''
    );
    if (
      !mappedRecovery
      || mappedRecovery.integration_id !== normalizedIntegrationId
      || mappedRecovery.recovery_id !== normalizedRecoveryId
      || !VALID_RECOVERY_STATUSES.has(previousStatus)
      || !VALID_RECOVERY_STATUSES.has(currentStatus)
      || (previousStatus !== 'failed' && previousStatus !== 'dlq')
      || currentStatus !== 'replayed'
      || mappedRecovery.status !== 'replayed'
      || currentStatus !== mappedRecovery.status
    ) {
      throw recoveryErrors.dependencyUnavailable({
        reason: 'integration-recovery-replay-result-malformed'
      });
    }

    addAuditEvent({
      type: 'platform.integration.recovery.queue.replay.succeeded',
      requestId: resolvedRequestId,
      operatorUserId: operatorContext.operatorUserId,
      integrationId: normalizedIntegrationId,
      recoveryId: normalizedRecoveryId,
      detail: 'integration recovery queue replay requested',
      metadata: {
        previous_status: previousStatus,
        current_status: currentStatus
      }
    });

    return {
      recovery: mappedRecovery,
      previous_status: previousStatus,
      current_status: currentStatus,
      replayed: currentStatus === 'replayed',
      request_id: resolvedRequestId
    };
  };

  const processNextRecoveryQueueItem = async ({
    requestId,
    integrationId = null,
    now = new Date().toISOString(),
    traceparent = null,
    operatorUserId = null,
    operatorSessionId = null
  } = {}) => {
    const resolvedRequestId = String(requestId || '').trim() || 'request_id_unset';
    const normalizedIntegrationId = integrationId === null || integrationId === undefined
      ? null
      : normalizeIntegrationId(integrationId);
    if (
      normalizedIntegrationId !== null
      && (
        !normalizedIntegrationId
        || normalizedIntegrationId.length > MAX_INTEGRATION_ID_LENGTH
      )
    ) {
      throw recoveryErrors.invalidPayload('integration_id 非法');
    }
    const normalizedOperatorUserId = normalizeStrictOptionalString({
      value: operatorUserId,
      maxLength: MAX_OPERATOR_USER_ID_LENGTH
    });
    const normalizedOperatorSessionId = normalizeStrictOptionalString({
      value: operatorSessionId,
      maxLength: MAX_REQUEST_ID_LENGTH
    });
    if (normalizedOperatorUserId === undefined || normalizedOperatorSessionId === undefined) {
      throw recoveryErrors.invalidPayload('operator 标识非法');
    }

    const resolvedDeliveryExecutor = resolveDeliveryExecutor();
    if (!resolvedDeliveryExecutor) {
      throw recoveryErrors.dependencyUnavailable({
        reason: 'integration-recovery-delivery-executor-unavailable'
      });
    }

    const authStore = assertAuthStoreMethod('claimNextDuePlatformIntegrationRecoveryQueueEntry');
    assertAuthStoreMethod('completePlatformIntegrationRecoveryQueueAttempt');

    let claimedRecord = null;
    try {
      claimedRecord = await authStore.claimNextDuePlatformIntegrationRecoveryQueueEntry({
        integrationId: normalizedIntegrationId,
        now,
        operatorUserId: normalizedOperatorUserId,
        operatorSessionId: normalizedOperatorSessionId,
        auditContext: {
          requestId: resolvedRequestId,
          traceparent,
          actorUserId: normalizedOperatorUserId,
          actorSessionId: normalizedOperatorSessionId
        }
      });
    } catch (error) {
      throw mapStoreError(error);
    }
    if (!claimedRecord) {
      return {
        processed: false,
        request_id: resolvedRequestId
      };
    }

    const mappedClaimedRecord = mapRecoveryRecord({
      record: claimedRecord
    });
    if (!mappedClaimedRecord) {
      throw recoveryErrors.dependencyUnavailable({
        reason: 'integration-recovery-claim-result-malformed'
      });
    }
    const claimedPreviousStatus = normalizeRecoveryStatus(
      claimedRecord.previousStatus
      || claimedRecord.previous_status
      || mappedClaimedRecord.status
    );
    if (!VALID_RECOVERY_STATUSES.has(claimedPreviousStatus)) {
      throw recoveryErrors.dependencyUnavailable({
        reason: 'integration-recovery-claim-result-malformed'
      });
    }

    let completionInput = null;
    try {
      const executionResult = await resolvedDeliveryExecutor({
        requestId: resolvedRequestId,
        traceparent,
        recovery: mappedClaimedRecord
      });
      if (!isPlainObject(executionResult)) {
        throw recoveryErrors.dependencyUnavailable({
          reason: 'integration-recovery-delivery-result-malformed'
        });
      }
      completionInput = {
        succeeded: Boolean(executionResult.succeeded),
        retryable: executionResult.retryable === undefined
          ? true
          : Boolean(executionResult.retryable),
        nextRetryAt: executionResult.nextRetryAt ?? null,
        failureCode: executionResult.failureCode ?? null,
        failureDetail: executionResult.failureDetail ?? null,
        lastHttpStatus: executionResult.lastHttpStatus ?? null,
        responseSnapshot: executionResult.responseSnapshot ?? null
      };
    } catch (error) {
      const fallbackFailureCode = normalizeStrictOptionalString({
        value: typeof error?.code === 'string'
          ? error.code
          : 'DELIVERY_EXECUTION_FAILED',
        maxLength: MAX_FAILURE_CODE_LENGTH
      }) || 'DELIVERY_EXECUTION_FAILED';
      const fallbackFailureDetail = normalizeStrictOptionalString({
        value: String(error?.message || 'delivery execution failed').trim(),
        maxLength: MAX_FAILURE_DETAIL_LENGTH
      }) || 'delivery execution failed';
      completionInput = {
        succeeded: false,
        retryable: error?.retryable === undefined ? true : Boolean(error?.retryable),
        nextRetryAt: error?.nextRetryAt ?? null,
        failureCode: fallbackFailureCode,
        failureDetail: fallbackFailureDetail,
        lastHttpStatus: normalizeLastHttpStatus(
          error?.httpStatus ?? error?.statusCode ?? error?.status
        ),
        responseSnapshot: {
          error_code: fallbackFailureCode,
          message: fallbackFailureDetail
        }
      };
    }

    let completionResult = null;
    try {
      completionResult = await authStore.completePlatformIntegrationRecoveryQueueAttempt({
        integrationId: mappedClaimedRecord.integration_id,
        recoveryId: mappedClaimedRecord.recovery_id,
        succeeded: completionInput.succeeded,
        retryable: completionInput.retryable,
        nextRetryAt: completionInput.nextRetryAt,
        failureCode: completionInput.failureCode,
        failureDetail: completionInput.failureDetail,
        lastHttpStatus: completionInput.lastHttpStatus,
        responseSnapshot: completionInput.responseSnapshot,
        operatorUserId: normalizedOperatorUserId,
        operatorSessionId: normalizedOperatorSessionId,
        auditContext: {
          requestId: resolvedRequestId,
          traceparent,
          actorUserId: normalizedOperatorUserId,
          actorSessionId: normalizedOperatorSessionId
        }
      });
    } catch (error) {
      throw mapStoreError(error);
    }
    if (!completionResult) {
      throw recoveryErrors.dependencyUnavailable({
        reason: 'integration-recovery-complete-result-missing'
      });
    }
    const mappedCompletion = mapRecoveryRecord({
      record: completionResult
    });
    if (
      !mappedCompletion
      || mappedCompletion.integration_id !== mappedClaimedRecord.integration_id
      || mappedCompletion.recovery_id !== mappedClaimedRecord.recovery_id
    ) {
      throw recoveryErrors.dependencyUnavailable({
        reason: 'integration-recovery-complete-result-malformed'
      });
    }

    addAuditEvent({
      type: 'platform.integration.recovery.queue.processed',
      requestId: resolvedRequestId,
      operatorUserId: normalizedOperatorUserId || 'system',
      integrationId: mappedClaimedRecord.integration_id,
      recoveryId: mappedClaimedRecord.recovery_id,
      detail: 'integration recovery queue item processed',
      metadata: {
        previous_status: claimedPreviousStatus,
        current_status: mappedCompletion.status
      }
    });

    return {
      processed: true,
      recovery: mappedCompletion,
      previous_status: claimedPreviousStatus,
      current_status: mappedCompletion.status,
      request_id: resolvedRequestId
    };
  };

  return {
    listRecoveryQueue,
    replayRecoveryQueueItem,
    processNextRecoveryQueueItem,
    _internals: {
      authService,
      deliveryExecutor: resolveDeliveryExecutor(),
      auditTrail
    }
  };
};

module.exports = {
  createPlatformIntegrationRecoveryService
};
