'use strict';

const createPlatformMysqlAuthStoreIntegrationCatalogUpdatePlatformIntegrationCatalogEntry = ({
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
  VALID_PLATFORM_INTEGRATION_DIRECTION,
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
  normalizePlatformIntegrationOptionalText,
  normalizePlatformIntegrationTimeoutMs,
  recordAuditEventWithQueryClient,
  toPlatformIntegrationCatalogRecord
} = {}) => ({
updatePlatformIntegrationCatalogEntry: async ({
      integrationId,
      code = undefined,
      name = undefined,
      direction = undefined,
      protocol = undefined,
      authMode = undefined,
      endpoint = undefined,
      baseUrl = undefined,
      timeoutMs = undefined,
      retryPolicy = undefined,
      idempotencyPolicy = undefined,
      versionStrategy = undefined,
      runbookUrl = undefined,
      lifecycleReason = undefined,
      operatorUserId = null,
      operatorSessionId = null,
      auditContext = null
    } = {}) =>
      executeWithDeadlockRetry({
        operation: 'updatePlatformIntegrationCatalogEntry',
        onExhausted: 'throw',
        execute: () =>
          dbClient.inTransaction(async (tx) => {
            const normalizedIntegrationId = normalizePlatformIntegrationId(integrationId);
            if (!isValidPlatformIntegrationId(normalizedIntegrationId)) {
              throw new Error('updatePlatformIntegrationCatalogEntry requires integrationId');
            }
            const hasUpdates = [
              code,
              name,
              direction,
              protocol,
              authMode,
              endpoint,
              baseUrl,
              timeoutMs,
              retryPolicy,
              idempotencyPolicy,
              versionStrategy,
              runbookUrl,
              lifecycleReason
            ].some((value) => value !== undefined);
            if (!hasUpdates) {
              throw new Error('updatePlatformIntegrationCatalogEntry requires update fields');
            }
            await assertPlatformIntegrationWriteAllowedByFreezeGate(tx);
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
                FOR UPDATE
              `,
              [normalizedIntegrationId]
            );
            if (!Array.isArray(rows)) {
              throw new Error('updatePlatformIntegrationCatalogEntry existing query malformed');
            }
            if (rows.length === 0) {
              return null;
            }
            const existing = toPlatformIntegrationCatalogRecord(rows[0]);
            if (!existing) {
              throw new Error('updatePlatformIntegrationCatalogEntry existing row malformed');
            }
            const nextCode = code === undefined
              ? existing.code
              : normalizePlatformIntegrationCode(code);
            const nextName = name === undefined
              ? existing.name
              : String(name || '').trim();
            const nextDirection = direction === undefined
              ? existing.direction
              : normalizePlatformIntegrationDirection(direction);
            const nextProtocol = protocol === undefined
              ? existing.protocol
              : String(protocol || '').trim();
            const nextAuthMode = authMode === undefined
              ? existing.authMode
              : String(authMode || '').trim();
            const nextEndpoint = endpoint === undefined
              ? existing.endpoint
              : normalizePlatformIntegrationOptionalText(endpoint);
            const nextBaseUrl = baseUrl === undefined
              ? existing.baseUrl
              : normalizePlatformIntegrationOptionalText(baseUrl);
            const nextTimeoutMs = timeoutMs === undefined
              ? existing.timeoutMs
              : normalizePlatformIntegrationTimeoutMs(timeoutMs);
            const nextRetryPolicy = retryPolicy === undefined
              ? normalizePlatformIntegrationJsonForStorage({
                value: existing.retryPolicy
              })
              : normalizePlatformIntegrationJsonForStorage({
                value: retryPolicy
              });
            const nextIdempotencyPolicy = idempotencyPolicy === undefined
              ? normalizePlatformIntegrationJsonForStorage({
                value: existing.idempotencyPolicy
              })
              : normalizePlatformIntegrationJsonForStorage({
                value: idempotencyPolicy
              });
            const nextVersionStrategy = versionStrategy === undefined
              ? existing.versionStrategy
              : normalizePlatformIntegrationOptionalText(versionStrategy);
            const nextRunbookUrl = runbookUrl === undefined
              ? existing.runbookUrl
              : normalizePlatformIntegrationOptionalText(runbookUrl);
            const nextLifecycleReason = lifecycleReason === undefined
              ? existing.lifecycleReason
              : normalizePlatformIntegrationOptionalText(lifecycleReason);
            if (
              !nextCode
              || nextCode.length > MAX_PLATFORM_INTEGRATION_CODE_LENGTH
              || !nextName
              || nextName.length > MAX_PLATFORM_INTEGRATION_NAME_LENGTH
              || !VALID_PLATFORM_INTEGRATION_DIRECTION.has(nextDirection)
              || !nextProtocol
              || nextProtocol.length > MAX_PLATFORM_INTEGRATION_PROTOCOL_LENGTH
              || !nextAuthMode
              || nextAuthMode.length > MAX_PLATFORM_INTEGRATION_AUTH_MODE_LENGTH
              || (
                nextEndpoint !== null
                && nextEndpoint.length > MAX_PLATFORM_INTEGRATION_ENDPOINT_LENGTH
              )
              || (
                nextBaseUrl !== null
                && nextBaseUrl.length > MAX_PLATFORM_INTEGRATION_BASE_URL_LENGTH
              )
              || (
                nextVersionStrategy !== null
                && nextVersionStrategy.length
                  > MAX_PLATFORM_INTEGRATION_VERSION_STRATEGY_LENGTH
              )
              || (
                nextRunbookUrl !== null
                && nextRunbookUrl.length > MAX_PLATFORM_INTEGRATION_RUNBOOK_URL_LENGTH
              )
              || (
                nextLifecycleReason !== null
                && nextLifecycleReason.length > MAX_PLATFORM_INTEGRATION_LIFECYCLE_REASON_LENGTH
              )
              || !Number.isInteger(nextTimeoutMs)
              || nextTimeoutMs < 1
              || nextTimeoutMs > MAX_PLATFORM_INTEGRATION_TIMEOUT_MS
              || nextRetryPolicy === undefined
              || nextIdempotencyPolicy === undefined
            ) {
              throw new Error('updatePlatformIntegrationCatalogEntry received invalid payload');
            }
            try {
              await tx.query(
                `
                  UPDATE platform_integration_catalog
                  SET code = ?,
                      code_normalized = ?,
                      name = ?,
                      direction = ?,
                      protocol = ?,
                      auth_mode = ?,
                      endpoint = ?,
                      base_url = ?,
                      timeout_ms = ?,
                      retry_policy = CAST(? AS JSON),
                      idempotency_policy = CAST(? AS JSON),
                      version_strategy = ?,
                      runbook_url = ?,
                      lifecycle_reason = ?,
                      updated_by_user_id = ?,
                      updated_at = CURRENT_TIMESTAMP(3)
                  WHERE integration_id = ?
                `,
                [
                  nextCode,
                  normalizePlatformIntegrationCodeKey(nextCode),
                  nextName,
                  nextDirection,
                  nextProtocol,
                  nextAuthMode,
                  nextEndpoint,
                  nextBaseUrl,
                  nextTimeoutMs,
                  nextRetryPolicy,
                  nextIdempotencyPolicy,
                  nextVersionStrategy,
                  nextRunbookUrl,
                  nextLifecycleReason,
                  normalizePlatformIntegrationOptionalText(operatorUserId)
                    || existing.updatedByUserId,
                  normalizedIntegrationId
                ]
              );
            } catch (error) {
              if (isDuplicateEntryError(error)) {
                const duplicateError = new Error(
                  'duplicate platform integration catalog code'
                );
                duplicateError.code = 'ER_DUP_ENTRY';
                duplicateError.errno = MYSQL_DUP_ENTRY_ERRNO;
                duplicateError.platformIntegrationCatalogConflictTarget = 'code';
                throw duplicateError;
              }
              throw error;
            }
            const updatedRows = await tx.query(
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
            const updated = toPlatformIntegrationCatalogRecord(updatedRows?.[0] || null);
            if (!updated) {
              throw new Error('updatePlatformIntegrationCatalogEntry result unavailable');
            }
            let auditRecorded = false;
            if (auditContext && typeof auditContext === 'object') {
              try {
                await recordAuditEventWithQueryClient({
                  queryClient: tx,
                  domain: 'platform',
                  requestId: String(auditContext.requestId || '').trim() || 'request_id_unset',
                  traceparent: auditContext.traceparent,
                  eventType: 'platform.integration.updated',
                  actorUserId: auditContext.actorUserId || operatorUserId,
                  actorSessionId: auditContext.actorSessionId || operatorSessionId,
                  targetType: 'integration',
                  targetId: normalizedIntegrationId,
                  result: 'success',
                  beforeState: {
                    code: existing.code,
                    direction: existing.direction,
                    protocol: existing.protocol,
                    auth_mode: existing.authMode
                  },
                  afterState: {
                    code: updated.code,
                    direction: updated.direction,
                    protocol: updated.protocol,
                    auth_mode: updated.authMode
                  },
                  metadata: {
                    changed_fields: [
                      ...new Set(Object.keys({
                        ...(code === undefined ? {} : { code: true }),
                        ...(name === undefined ? {} : { name: true }),
                        ...(direction === undefined ? {} : { direction: true }),
                        ...(protocol === undefined ? {} : { protocol: true }),
                        ...(authMode === undefined ? {} : { auth_mode: true }),
                        ...(endpoint === undefined ? {} : { endpoint: true }),
                        ...(baseUrl === undefined ? {} : { base_url: true }),
                        ...(timeoutMs === undefined ? {} : { timeout_ms: true }),
                        ...(retryPolicy === undefined ? {} : { retry_policy: true }),
                        ...(idempotencyPolicy === undefined ? {} : { idempotency_policy: true }),
                        ...(versionStrategy === undefined ? {} : { version_strategy: true }),
                        ...(runbookUrl === undefined ? {} : { runbook_url: true }),
                        ...(lifecycleReason === undefined ? {} : { lifecycle_reason: true })
                      }))
                    ]
                  }
                });
                auditRecorded = true;
              } catch (error) {
                const auditWriteError = new Error(
                  'platform integration update audit write failed'
                );
                auditWriteError.code = 'ERR_AUDIT_WRITE_FAILED';
                auditWriteError.cause = error;
                throw auditWriteError;
              }
            }
            return {
              ...updated,
              auditRecorded
            };
          })
      })
});

module.exports = {
  createPlatformMysqlAuthStoreIntegrationCatalogUpdatePlatformIntegrationCatalogEntry
};
