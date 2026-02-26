'use strict';

const createPlatformMysqlAuthStoreOrganizationGovernanceUpdateOrganizationStatus = ({
  VALID_ORG_STATUS,
  dbClient,
  executeWithDeadlockRetry,
  isActiveLikeStatus,
  normalizeOrgStatus,
  normalizeTenantUsershipStatusForRead,
  recordAuditEventWithQueryClient,
  removeTenantDomainAccessForUserTx
} = {}) => ({
updateOrganizationStatus: async ({
      orgId,
      nextStatus,
      operatorUserId,
      auditContext = null
    }) =>
      executeWithDeadlockRetry({
        operation: 'updateOrganizationStatus',
        onExhausted: 'throw',
        execute: () =>
          dbClient.inTransaction(async (tx) => {
            const normalizedOrgId = String(orgId || '').trim();
            const normalizedNextStatus = normalizeOrgStatus(nextStatus);
            const normalizedOperatorUserId = String(operatorUserId || '').trim();
            if (
              !normalizedOrgId
              || !normalizedOperatorUserId
              || !VALID_ORG_STATUS.has(normalizedNextStatus)
            ) {
              throw new Error(
                'updateOrganizationStatus requires orgId, nextStatus, and operatorUserId'
              );
            }

            const orgRows = await tx.query(
              `
                SELECT id, status, owner_user_id
                FROM tenants
                WHERE BINARY id = ?
                LIMIT 1
                FOR UPDATE
              `,
              [normalizedOrgId]
            );
            const org = orgRows?.[0] || null;
            if (!org) {
              return null;
            }

            const previousStatus = normalizeOrgStatus(org.status);
            let affectedMembershipCount = 0;
            let affectedRoleCount = 0;
            let affectedRoleBindingCount = 0;
            let revokedSessionCount = 0;
            let revokedRefreshTokenCount = 0;
            if (previousStatus !== normalizedNextStatus) {
              const updateResult = await tx.query(
                `
                  UPDATE tenants
                  SET status = ?,
                      updated_at = CURRENT_TIMESTAMP(3)
                  WHERE BINARY id = ? AND status <> ?
                `,
                [normalizedNextStatus, normalizedOrgId, normalizedNextStatus]
              );
              if (Number(updateResult?.affectedRows || 0) !== 1) {
                throw new Error('org-status-write-not-applied');
              }

              if (normalizedNextStatus === 'disabled') {
                const affectedMembershipUserIds = new Set();
                const affectedUserIds = new Set();

                const tenantUsershipRows = await tx.query(
                  `
                    SELECT membership_id, user_id, status
                    FROM tenant_memberships
                    WHERE tenant_id = ?
                    FOR UPDATE
                  `,
                  [normalizedOrgId]
                );
                const activeTenantUsershipUserIds = (Array.isArray(tenantUsershipRows)
                  ? tenantUsershipRows
                  : [])
                  .filter((row) =>
                    isActiveLikeStatus(
                      normalizeTenantUsershipStatusForRead(row?.status)
                    )
                  )
                  .map((row) => String(row?.user_id || '').trim())
                  .filter((userId) => userId.length > 0);
                for (const activeTenantUsershipUserId of activeTenantUsershipUserIds) {
                  affectedMembershipUserIds.add(activeTenantUsershipUserId);
                  affectedUserIds.add(activeTenantUsershipUserId);
                }
                await tx.query(
                  `
                    UPDATE tenant_memberships
                    SET status = 'disabled',
                        can_view_user_management = 0,
                        can_operate_user_management = 0,
                        can_view_role_management = 0,
                        can_operate_role_management = 0,
                        updated_at = CURRENT_TIMESTAMP(3)
                    WHERE tenant_id = ?
                      AND status IN ('active', 'enabled')
                  `,
                  [normalizedOrgId]
                );
                const disableTenantRolesResult = await tx.query(
                  `
                    UPDATE platform_roles
                    SET status = 'disabled',
                        updated_by_user_id = ?,
                        updated_at = CURRENT_TIMESTAMP(3)
                    WHERE scope = 'tenant'
                      AND tenant_id = ?
                      AND status IN ('active', 'enabled')
                  `,
                  [normalizedOperatorUserId, normalizedOrgId]
                );
                const deleteTenantRoleBindingsResult = await tx.query(
                  `
                    DELETE amr
                    FROM tenant_membership_roles amr
                    INNER JOIN tenant_memberships ut
                      ON ut.membership_id = amr.membership_id
                    WHERE ut.tenant_id = ?
                  `,
                  [normalizedOrgId]
                );
                const ownerUserId = String(org.owner_user_id || '').trim();
                if (ownerUserId.length > 0) {
                  affectedUserIds.add(ownerUserId);
                }
                affectedMembershipCount = affectedMembershipUserIds.size;
                affectedRoleCount = Number(
                  disableTenantRolesResult?.affectedRows || 0
                );
                affectedRoleBindingCount = Number(
                  deleteTenantRoleBindingsResult?.affectedRows || 0
                );
                for (const affectedUserId of affectedUserIds) {
                  const revokeSessionsResult = await tx.query(
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
                    ['org-status-changed', affectedUserId, normalizedOrgId]
                  );
                  revokedSessionCount += Number(
                    revokeSessionsResult?.affectedRows || 0
                  );
                  const revokeRefreshTokensResult = await tx.query(
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
                    [affectedUserId, normalizedOrgId]
                  );
                  revokedRefreshTokenCount += Number(
                    revokeRefreshTokensResult?.affectedRows || 0
                  );
                  await removeTenantDomainAccessForUserTx({
                    txClient: tx,
                    userId: affectedUserId
                  });
                }
              }
            }

            let auditRecorded = false;
            if (auditContext && typeof auditContext === 'object') {
              const normalizedAuditReason =
                auditContext.reason === null || auditContext.reason === undefined
                  ? null
                  : String(auditContext.reason).trim() || null;
              try {
                await recordAuditEventWithQueryClient({
                  queryClient: tx,
                  domain: 'tenant',
                  tenantId: normalizedOrgId,
                  requestId: String(auditContext.requestId || '').trim() || 'request_id_unset',
                  traceparent: auditContext.traceparent,
                  eventType: 'auth.org.status.updated',
                  actorUserId: auditContext.actorUserId,
                  actorSessionId: auditContext.actorSessionId,
                  targetType: 'org',
                  targetId: normalizedOrgId,
                  result: 'success',
                  beforeState: {
                    status: previousStatus
                  },
                  afterState: {
                    status: normalizedNextStatus
                  },
                  metadata: {
                    reason: normalizedAuditReason,
                    affected_membership_count: affectedMembershipCount,
                    affected_role_count: affectedRoleCount,
                    affected_role_binding_count: affectedRoleBindingCount,
                    revoked_session_count: revokedSessionCount,
                    revoked_refresh_token_count: revokedRefreshTokenCount
                  }
                });
                auditRecorded = true;
              } catch (error) {
                const auditWriteError = new Error('organization status audit write failed');
                auditWriteError.code = 'ERR_AUDIT_WRITE_FAILED';
                auditWriteError.cause = error;
                throw auditWriteError;
              }
            }
            return {
              org_id: normalizedOrgId,
              previous_status: previousStatus,
              current_status: normalizedNextStatus,
              affected_membership_count: affectedMembershipCount,
              affected_role_count: affectedRoleCount,
              affected_role_binding_count: affectedRoleBindingCount,
              revoked_session_count: revokedSessionCount,
              revoked_refresh_token_count: revokedRefreshTokenCount,
              audit_recorded: auditRecorded
            };
          })
      })
});

module.exports = {
  createPlatformMysqlAuthStoreOrganizationGovernanceUpdateOrganizationStatus
};
