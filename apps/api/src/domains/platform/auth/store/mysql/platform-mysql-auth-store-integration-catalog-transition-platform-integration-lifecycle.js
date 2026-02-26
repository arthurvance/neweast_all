'use strict';

const createPlatformMysqlAuthStoreIntegrationCatalogTransitionPlatformIntegrationLifecycle = ({
  MAX_PLATFORM_INTEGRATION_LIFECYCLE_REASON_LENGTH,
  VALID_PLATFORM_INTEGRATION_LIFECYCLE_STATUS,
  assertPlatformIntegrationWriteAllowedByFreezeGate,
  createPlatformIntegrationLifecycleConflictError,
  dbClient,
  executeWithDeadlockRetry,
  isPlatformIntegrationLifecycleTransitionAllowed,
  isValidPlatformIntegrationId,
  normalizePlatformIntegrationId,
  normalizePlatformIntegrationLifecycleStatus,
  normalizePlatformIntegrationOptionalText,
  recordAuditEventWithQueryClient,
  toPlatformIntegrationCatalogRecord
} = {}) => ({
transitionPlatformIntegrationLifecycle: async ({
      integrationId,
      nextStatus,
      reason = null,
      operatorUserId = null,
      operatorSessionId = null,
      auditContext = null
    } = {}) =>
      executeWithDeadlockRetry({
        operation: 'transitionPlatformIntegrationLifecycle',
        onExhausted: 'throw',
        execute: () =>
          dbClient.inTransaction(async (tx) => {
            const normalizedIntegrationId = normalizePlatformIntegrationId(integrationId);
            const normalizedNextStatus = normalizePlatformIntegrationLifecycleStatus(
              nextStatus
            );
            const normalizedReason = normalizePlatformIntegrationOptionalText(reason);
            if (
              !isValidPlatformIntegrationId(normalizedIntegrationId)
              || !VALID_PLATFORM_INTEGRATION_LIFECYCLE_STATUS.has(normalizedNextStatus)
              || (
                normalizedReason !== null
                && normalizedReason.length > MAX_PLATFORM_INTEGRATION_LIFECYCLE_REASON_LENGTH
              )
            ) {
              throw new Error('transitionPlatformIntegrationLifecycle received invalid input');
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
              throw new Error('transitionPlatformIntegrationLifecycle existing query malformed');
            }
            if (rows.length === 0) {
              return null;
            }
            const existing = toPlatformIntegrationCatalogRecord(rows[0]);
            if (!existing) {
              throw new Error('transitionPlatformIntegrationLifecycle existing row malformed');
            }
            if (
              !isPlatformIntegrationLifecycleTransitionAllowed({
                previousStatus: existing.lifecycleStatus,
                nextStatus: normalizedNextStatus
              })
            ) {
              throw createPlatformIntegrationLifecycleConflictError({
                integrationId: normalizedIntegrationId,
                previousStatus: existing.lifecycleStatus,
                requestedStatus: normalizedNextStatus
              });
            }
            await tx.query(
              `
                UPDATE platform_integration_catalog
                SET lifecycle_status = ?,
                    lifecycle_reason = ?,
                    updated_by_user_id = ?,
                    updated_at = CURRENT_TIMESTAMP(3)
                WHERE integration_id = ?
              `,
              [
                normalizedNextStatus,
                normalizedReason,
                normalizePlatformIntegrationOptionalText(operatorUserId)
                  || existing.updatedByUserId,
                normalizedIntegrationId
              ]
            );
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
              throw new Error('transitionPlatformIntegrationLifecycle result unavailable');
            }
            let auditRecorded = false;
            if (auditContext && typeof auditContext === 'object') {
              try {
                await recordAuditEventWithQueryClient({
                  queryClient: tx,
                  domain: 'platform',
                  requestId: String(auditContext.requestId || '').trim() || 'request_id_unset',
                  traceparent: auditContext.traceparent,
                  eventType: 'platform.integration.lifecycle_changed',
                  actorUserId: auditContext.actorUserId || operatorUserId,
                  actorSessionId: auditContext.actorSessionId || operatorSessionId,
                  targetType: 'integration',
                  targetId: normalizedIntegrationId,
                  result: 'success',
                  beforeState: {
                    lifecycle_status: existing.lifecycleStatus
                  },
                  afterState: {
                    lifecycle_status: updated.lifecycleStatus
                  }
                });
                auditRecorded = true;
              } catch (error) {
                const auditWriteError = new Error(
                  'platform integration lifecycle audit write failed'
                );
                auditWriteError.code = 'ERR_AUDIT_WRITE_FAILED';
                auditWriteError.cause = error;
                throw auditWriteError;
              }
            }
            return {
              ...updated,
              previousStatus: existing.lifecycleStatus,
              currentStatus: updated.lifecycleStatus,
              effectiveInvocationEnabled: updated.lifecycleStatus === 'active',
              auditRecorded
            };
          })
      })
});

module.exports = {
  createPlatformMysqlAuthStoreIntegrationCatalogTransitionPlatformIntegrationLifecycle
};
