'use strict';

const createPlatformMysqlAuthStoreIntegrationCatalogCreatePlatformIntegrationCatalogEntry = ({
  MAX_PLATFORM_INTEGRATION_AUTH_MODE_LENGTH,
  MAX_PLATFORM_INTEGRATION_BASE_URL_LENGTH,
  MAX_PLATFORM_INTEGRATION_CODE_LENGTH,
  MAX_PLATFORM_INTEGRATION_ENDPOINT_LENGTH,
  MAX_PLATFORM_INTEGRATION_LIFECYCLE_REASON_LENGTH,
  MAX_PLATFORM_INTEGRATION_NAME_LENGTH,
  MAX_PLATFORM_INTEGRATION_PROTOCOL_LENGTH,
  MAX_PLATFORM_INTEGRATION_RUNBOOK_URL_LENGTH,
  MAX_PLATFORM_INTEGRATION_TIMEOUT_MS,
  MAX_PLATFORM_INTEGRATION_VERSION_STRATEGY_LENGTH,
  MYSQL_DUP_ENTRY_ERRNO,
  PLATFORM_INTEGRATION_DEFAULT_TIMEOUT_MS,
  VALID_PLATFORM_INTEGRATION_DIRECTION,
  VALID_PLATFORM_INTEGRATION_LIFECYCLE_STATUS,
  assertPlatformIntegrationWriteAllowedByFreezeGate,
  dbClient,
  executeWithDeadlockRetry,
  isDuplicateEntryError,
  isValidPlatformIntegrationId,
  normalizePlatformIntegrationCode,
  normalizePlatformIntegrationCodeKey,
  normalizePlatformIntegrationDirection,
  normalizePlatformIntegrationId,
  normalizePlatformIntegrationJsonForStorage,
  normalizePlatformIntegrationLifecycleStatus,
  normalizePlatformIntegrationOptionalText,
  normalizePlatformIntegrationTimeoutMs,
  randomUUID,
  recordAuditEventWithQueryClient,
  toPlatformIntegrationCatalogRecord
} = {}) => ({
createPlatformIntegrationCatalogEntry: async ({
      integrationId = randomUUID(),
      code,
      name,
      direction,
      protocol,
      authMode,
      endpoint = null,
      baseUrl = null,
      timeoutMs = PLATFORM_INTEGRATION_DEFAULT_TIMEOUT_MS,
      retryPolicy = null,
      idempotencyPolicy = null,
      versionStrategy = null,
      runbookUrl = null,
      lifecycleStatus = 'draft',
      lifecycleReason = null,
      operatorUserId = null,
      operatorSessionId = null,
      auditContext = null
    } = {}) =>
      executeWithDeadlockRetry({
        operation: 'createPlatformIntegrationCatalogEntry',
        onExhausted: 'throw',
        execute: () =>
          dbClient.inTransaction(async (tx) => {
            const integrationIdProvided =
              integrationId !== undefined && integrationId !== null;
            const normalizedRequestedIntegrationId =
              normalizePlatformIntegrationId(integrationId);
            if (
              integrationIdProvided
              && !isValidPlatformIntegrationId(normalizedRequestedIntegrationId)
            ) {
              throw new Error('createPlatformIntegrationCatalogEntry received invalid integrationId');
            }
            const normalizedIntegrationId = isValidPlatformIntegrationId(
              normalizedRequestedIntegrationId
            )
              ? normalizedRequestedIntegrationId
              : randomUUID();
            const normalizedCode = normalizePlatformIntegrationCode(code);
            const normalizedCodeKey = normalizePlatformIntegrationCodeKey(normalizedCode);
            const normalizedName = String(name || '').trim();
            const normalizedDirection = normalizePlatformIntegrationDirection(direction);
            const normalizedProtocol = String(protocol || '').trim();
            const normalizedAuthMode = String(authMode || '').trim();
            const normalizedEndpoint = normalizePlatformIntegrationOptionalText(endpoint);
            const normalizedBaseUrl = normalizePlatformIntegrationOptionalText(baseUrl);
            const normalizedTimeoutMs = normalizePlatformIntegrationTimeoutMs(timeoutMs);
            const normalizedRetryPolicy = normalizePlatformIntegrationJsonForStorage({
              value: retryPolicy
            });
            const normalizedIdempotencyPolicy = normalizePlatformIntegrationJsonForStorage({
              value: idempotencyPolicy
            });
            const normalizedVersionStrategy = normalizePlatformIntegrationOptionalText(
              versionStrategy
            );
            const normalizedRunbookUrl = normalizePlatformIntegrationOptionalText(runbookUrl);
            const normalizedLifecycleStatus = normalizePlatformIntegrationLifecycleStatus(
              lifecycleStatus
            );
            const normalizedLifecycleReason = normalizePlatformIntegrationOptionalText(
              lifecycleReason
            );
            if (
              !isValidPlatformIntegrationId(normalizedIntegrationId)
              || !normalizedCode
              || normalizedCode.length > MAX_PLATFORM_INTEGRATION_CODE_LENGTH
              || !normalizedName
              || normalizedName.length > MAX_PLATFORM_INTEGRATION_NAME_LENGTH
              || !VALID_PLATFORM_INTEGRATION_DIRECTION.has(normalizedDirection)
              || !normalizedProtocol
              || normalizedProtocol.length > MAX_PLATFORM_INTEGRATION_PROTOCOL_LENGTH
              || !normalizedAuthMode
              || normalizedAuthMode.length > MAX_PLATFORM_INTEGRATION_AUTH_MODE_LENGTH
              || (
                normalizedEndpoint !== null
                && normalizedEndpoint.length > MAX_PLATFORM_INTEGRATION_ENDPOINT_LENGTH
              )
              || (
                normalizedBaseUrl !== null
                && normalizedBaseUrl.length > MAX_PLATFORM_INTEGRATION_BASE_URL_LENGTH
              )
              || (
                normalizedVersionStrategy !== null
                && normalizedVersionStrategy.length
                  > MAX_PLATFORM_INTEGRATION_VERSION_STRATEGY_LENGTH
              )
              || (
                normalizedRunbookUrl !== null
                && normalizedRunbookUrl.length > MAX_PLATFORM_INTEGRATION_RUNBOOK_URL_LENGTH
              )
              || (
                normalizedLifecycleReason !== null
                && normalizedLifecycleReason.length
                  > MAX_PLATFORM_INTEGRATION_LIFECYCLE_REASON_LENGTH
              )
              || !Number.isInteger(normalizedTimeoutMs)
              || normalizedTimeoutMs < 1
              || normalizedTimeoutMs > MAX_PLATFORM_INTEGRATION_TIMEOUT_MS
              || !VALID_PLATFORM_INTEGRATION_LIFECYCLE_STATUS.has(normalizedLifecycleStatus)
              || normalizedRetryPolicy === undefined
              || normalizedIdempotencyPolicy === undefined
            ) {
              throw new Error('createPlatformIntegrationCatalogEntry received invalid input');
            }
            await assertPlatformIntegrationWriteAllowedByFreezeGate(tx);
            try {
              await tx.query(
                `
                  INSERT INTO platform_integration_catalog (
                    integration_id,
                    code,
                    code_normalized,
                    name,
                    direction,
                    protocol,
                    auth_mode,
                    endpoint,
                    base_url,
                    timeout_ms,
                    retry_policy,
                    idempotency_policy,
                    version_strategy,
                    runbook_url,
                    lifecycle_status,
                    lifecycle_reason,
                    created_by_user_id,
                    updated_by_user_id
                  )
                  VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CAST(? AS JSON), CAST(? AS JSON), ?, ?, ?, ?, ?, ?)
                `,
                [
                  normalizedIntegrationId,
                  normalizedCode,
                  normalizedCodeKey,
                  normalizedName,
                  normalizedDirection,
                  normalizedProtocol,
                  normalizedAuthMode,
                  normalizedEndpoint,
                  normalizedBaseUrl,
                  normalizedTimeoutMs,
                  normalizedRetryPolicy,
                  normalizedIdempotencyPolicy,
                  normalizedVersionStrategy,
                  normalizedRunbookUrl,
                  normalizedLifecycleStatus,
                  normalizedLifecycleReason,
                  normalizePlatformIntegrationOptionalText(operatorUserId),
                  normalizePlatformIntegrationOptionalText(operatorUserId)
                ]
              );
            } catch (error) {
              if (isDuplicateEntryError(error)) {
                const duplicateError = new Error(
                  'duplicate platform integration catalog entry'
                );
                duplicateError.code = 'ER_DUP_ENTRY';
                duplicateError.errno = MYSQL_DUP_ENTRY_ERRNO;
                const duplicateMessage = String(
                  error?.sqlMessage || error?.message || ''
                ).toLowerCase();
                duplicateError.platformIntegrationCatalogConflictTarget =
                  duplicateMessage.includes('code_normalized')
                    ? 'code'
                    : 'integration_id';
                throw duplicateError;
              }
              throw error;
            }
            const rows = await tx.query(
              `
                SELECT integration_id,
                       code,
                       code_normalized,
                       name,
                       direction,
                       protocol,
                       auth_mode,
                       endpoint,
                       base_url,
                       timeout_ms,
                       retry_policy,
                       idempotency_policy,
                       version_strategy,
                       runbook_url,
                       lifecycle_status,
                       lifecycle_reason,
                       created_by_user_id,
                       updated_by_user_id,
                       created_at,
                       updated_at
                FROM platform_integration_catalog
                WHERE integration_id = ?
                LIMIT 1
              `,
              [normalizedIntegrationId]
            );
            const createdIntegration = toPlatformIntegrationCatalogRecord(
              rows?.[0] || null
            );
            if (!createdIntegration) {
              throw new Error('createPlatformIntegrationCatalogEntry result unavailable');
            }
            let auditRecorded = false;
            if (auditContext && typeof auditContext === 'object') {
              try {
                await recordAuditEventWithQueryClient({
                  queryClient: tx,
                  domain: 'platform',
                  requestId: String(auditContext.requestId || '').trim() || 'request_id_unset',
                  traceparent: auditContext.traceparent,
                  eventType: 'platform.integration.created',
                  actorUserId: auditContext.actorUserId || operatorUserId,
                  actorSessionId: auditContext.actorSessionId || operatorSessionId,
                  targetType: 'integration',
                  targetId: normalizedIntegrationId,
                  result: 'success',
                  beforeState: null,
                  afterState: {
                    integration_id: normalizedIntegrationId,
                    code: normalizedCode,
                    direction: normalizedDirection,
                    protocol: normalizedProtocol,
                    auth_mode: normalizedAuthMode,
                    lifecycle_status: normalizedLifecycleStatus
                  }
                });
                auditRecorded = true;
              } catch (error) {
                const auditWriteError = new Error(
                  'platform integration create audit write failed'
                );
                auditWriteError.code = 'ERR_AUDIT_WRITE_FAILED';
                auditWriteError.cause = error;
                throw auditWriteError;
              }
            }
            return {
              ...createdIntegration,
              auditRecorded
            };
          })
      })
});

module.exports = {
  createPlatformMysqlAuthStoreIntegrationCatalogCreatePlatformIntegrationCatalogEntry
};
