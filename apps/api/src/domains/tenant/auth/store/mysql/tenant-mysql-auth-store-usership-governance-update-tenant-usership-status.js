'use strict';

const createTenantMysqlAuthStoreUsershipGovernanceUpdateTenantUsershipStatus = ({
  VALID_TENANT_MEMBERSHIP_STATUS,
  dbClient,
  ensureTenantDomainAccessForUserTx,
  executeWithDeadlockRetry,
  insertTenantUsershipHistoryTx,
  normalizeTenantUsershipStatusForRead,
  randomUUID,
  recordAuditEventWithQueryClient,
  removeTenantDomainAccessForUserTx,
  syncTenantUsershipPermissionSnapshotInTx
} = {}) => ({
updateTenantUsershipStatus: async ({
      membershipId,
      tenantId,
      nextStatus,
      operatorUserId,
      reason = null,
      auditContext = null
    }) =>
      executeWithDeadlockRetry({
        operation: 'updateTenantUsershipStatus',
        onExhausted: 'throw',
        execute: async () => {
          const normalizedMembershipId = String(membershipId || '').trim();
          const normalizedTenantId = String(tenantId || '').trim();
          const normalizedNextStatus = normalizeTenantUsershipStatusForRead(nextStatus);
          const normalizedOperatorUserId = String(operatorUserId || '').trim();
          const normalizedReason = reason === null || reason === undefined
            ? null
            : String(reason).trim() || null;
          if (
            !normalizedMembershipId
            || !normalizedTenantId
            || !normalizedOperatorUserId
            || !VALID_TENANT_MEMBERSHIP_STATUS.has(normalizedNextStatus)
          ) {
            throw new Error(
              'updateTenantUsershipStatus requires membershipId, tenantId, nextStatus and operatorUserId'
            );
          }
          return dbClient.inTransaction(async (tx) => {
            const rows = await tx.query(
              `
                SELECT membership_id,
                       user_id,
                       tenant_id,
                       tenant_name,
                       status,
                       can_view_user_management,
                       can_operate_user_management,
                       can_view_role_management,
                       can_operate_role_management,
                       joined_at,
                       left_at
                FROM tenant_memberships
                WHERE membership_id = ? AND tenant_id = ?
                LIMIT 1
                FOR UPDATE
              `,
              [normalizedMembershipId, normalizedTenantId]
            );
            const row = rows?.[0] || null;
            if (!row) {
              return null;
            }
            const previousStatus = normalizeTenantUsershipStatusForRead(row.status);
            if (!VALID_TENANT_MEMBERSHIP_STATUS.has(previousStatus)) {
              throw new Error(
                'updateTenantUsershipStatus encountered unsupported existing status'
              );
            }
            let finalMembershipId = String(row.membership_id || '').trim() || normalizedMembershipId;
            let auditRecorded = false;
            if (previousStatus !== normalizedNextStatus) {
              if (previousStatus === 'left' && normalizedNextStatus === 'active') {
                await insertTenantUsershipHistoryTx({
                  txClient: tx,
                  row,
                  archivedReason: normalizedReason || 'reactivate',
                  archivedByUserId: normalizedOperatorUserId
                });
                await tx.query(
                  `
                    DELETE FROM tenant_membership_roles
                    WHERE membership_id = ?
                  `,
                  [normalizedMembershipId]
                );
                finalMembershipId = randomUUID();
                await tx.query(
                  `
                    UPDATE tenant_memberships
                    SET membership_id = ?,
                        status = 'active',
                        can_view_user_management = 0,
                        can_operate_user_management = 0,
                        can_view_role_management = 0,
                        can_operate_role_management = 0,
                        left_at = NULL,
                        joined_at = CURRENT_TIMESTAMP(3),
                        updated_at = CURRENT_TIMESTAMP(3)
                    WHERE membership_id = ? AND tenant_id = ?
                  `,
                  [finalMembershipId, normalizedMembershipId, normalizedTenantId]
                );
              } else {
                if (normalizedNextStatus === 'left') {
                  await insertTenantUsershipHistoryTx({
                    txClient: tx,
                    row,
                    archivedReason: normalizedReason || 'left',
                    archivedByUserId: normalizedOperatorUserId
                  });
                  await tx.query(
                    `
                      DELETE FROM tenant_membership_roles
                      WHERE membership_id = ?
                    `,
                    [finalMembershipId]
                  );
                }
                await tx.query(
                  `
                    UPDATE tenant_memberships
                    SET status = ?,
                        can_view_user_management = CASE WHEN ? = 'left' THEN 0 ELSE can_view_user_management END,
                        can_operate_user_management = CASE WHEN ? = 'left' THEN 0 ELSE can_operate_user_management END,
                        can_view_role_management = CASE WHEN ? = 'left' THEN 0 ELSE can_view_role_management END,
                        can_operate_role_management = CASE WHEN ? = 'left' THEN 0 ELSE can_operate_role_management END,
                        left_at = CASE
                          WHEN ? = 'left' THEN CURRENT_TIMESTAMP(3)
                          WHEN ? = 'active' THEN NULL
                          ELSE left_at
                        END,
                        updated_at = CURRENT_TIMESTAMP(3)
                    WHERE membership_id = ? AND tenant_id = ?
                  `,
                  [
                    normalizedNextStatus,
                    normalizedNextStatus,
                    normalizedNextStatus,
                    normalizedNextStatus,
                    normalizedNextStatus,
                    normalizedNextStatus,
                    normalizedNextStatus,
                    finalMembershipId,
                    normalizedTenantId
                  ]
                );
              }

              if (normalizedNextStatus === 'active') {
                await syncTenantUsershipPermissionSnapshotInTx({
                  txClient: tx,
                  membershipId: finalMembershipId,
                  tenantId: normalizedTenantId,
                  roleIds: previousStatus === 'left' ? [] : null,
                  revokeReason: 'tenant-membership-status-changed'
                });
                await ensureTenantDomainAccessForUserTx({
                  txClient: tx,
                  userId: row.user_id
                });
              } else {
                await tx.query(
                  `
                    UPDATE auth_sessions
                    SET status = 'revoked',
                        revoked_reason = ?,
                        updated_at = CURRENT_TIMESTAMP(3)
                    WHERE user_id = ?
                      AND entry_domain = 'tenant'
                      AND active_tenant_id = ?
                      AND status = 'active'
                  `,
                  [
                    'tenant-membership-status-changed',
                    row.user_id,
                    normalizedTenantId
                  ]
                );
                await tx.query(
                  `
                    UPDATE auth_refresh_tokens
                    SET status = 'revoked',
                        updated_at = CURRENT_TIMESTAMP(3)
                    WHERE status = 'active'
                      AND session_id IN (
                        SELECT session_id
                        FROM auth_sessions
                        WHERE user_id = ?
                          AND entry_domain = 'tenant'
                          AND active_tenant_id = ?
                      )
                  `,
                  [row.user_id, normalizedTenantId]
                );
                await removeTenantDomainAccessForUserTx({
                  txClient: tx,
                  userId: row.user_id
                });
              }
            }
            if (auditContext && typeof auditContext === 'object') {
              const normalizedAuditReason =
                auditContext.reason === null || auditContext.reason === undefined
                  ? null
                  : String(auditContext.reason).trim() || null;
              try {
                await recordAuditEventWithQueryClient({
                  queryClient: tx,
                  domain: 'tenant',
                  tenantId: normalizedTenantId,
                  requestId: String(auditContext.requestId || '').trim() || 'request_id_unset',
                  traceparent: auditContext.traceparent,
                  eventType: 'auth.tenant.user.status.updated',
                  actorUserId: auditContext.actorUserId || normalizedOperatorUserId,
                  actorSessionId: auditContext.actorSessionId,
                  targetType: 'membership',
                  targetId: finalMembershipId,
                  result: 'success',
                  beforeState: {
                    status: previousStatus
                  },
                  afterState: {
                    status: normalizedNextStatus
                  },
                  metadata: {
                    tenant_id: normalizedTenantId,
                    membership_id: finalMembershipId,
                    target_user_id: String(row.user_id || '').trim() || null,
                    previous_status: previousStatus,
                    current_status: normalizedNextStatus,
                    reason: normalizedAuditReason
                  }
                });
                auditRecorded = true;
              } catch (error) {
                const auditWriteError = new Error('tenant usership status audit write failed');
                auditWriteError.code = 'ERR_AUDIT_WRITE_FAILED';
                auditWriteError.cause = error;
                throw auditWriteError;
              }
            }

            return {
              membership_id: finalMembershipId,
              user_id: String(row.user_id || '').trim(),
              tenant_id: String(row.tenant_id || '').trim(),
              previous_status: previousStatus,
              current_status: normalizedNextStatus,
              audit_recorded: auditRecorded
            };
          });
        }
      })
});

module.exports = {
  createTenantMysqlAuthStoreUsershipGovernanceUpdateTenantUsershipStatus
};
