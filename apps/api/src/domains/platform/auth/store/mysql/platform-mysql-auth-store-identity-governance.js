'use strict';

const createPlatformMysqlAuthStoreIdentityGovernance = ({
  VALID_PLATFORM_USER_STATUS,
  dbClient,
  executeWithDeadlockRetry,
  isDuplicateEntryError,
  normalizeOrgStatus,
  normalizeUserStatus,
  randomUUID,
  recordAuditEventWithQueryClient,
  repositoryMethods,
  toUserRecord
} = {}) => ({
listPlatformUsers: repositoryMethods.listPlatformUsers,

listPlatformOrgs: repositoryMethods.listPlatformOrgs,

getPlatformUserById: repositoryMethods.getPlatformUserById,

upsertPlatformUserProfile: repositoryMethods.upsertPlatformUserProfile,

createUserByPhone: async ({ phone, passwordHash, status = 'active' }) => {
      const normalizedPhone = String(phone || '').trim();
      const normalizedPasswordHash = String(passwordHash || '').trim();
      if (!normalizedPhone || !normalizedPasswordHash) {
        throw new Error('createUserByPhone requires phone and passwordHash');
      }
      const normalizedStatus = String(status || 'active').trim().toLowerCase() || 'active';
      const userId = randomUUID();
      try {
        await dbClient.query(
          `
            INSERT INTO iam_users (id, phone, password_hash, status, session_version)
            VALUES (?, ?, ?, ?, 1)
          `,
          [userId, normalizedPhone, normalizedPasswordHash, normalizedStatus]
        );
      } catch (error) {
        if (isDuplicateEntryError(error)) {
          return null;
        }
        throw error;
      }
      const rows = await dbClient.query(
        `
          SELECT id, phone, password_hash, status, session_version
          FROM iam_users
          WHERE id = ?
          LIMIT 1
        `,
        [userId]
      );
      return toUserRecord(rows[0]);
    },

updatePlatformUserStatus: async ({
      userId,
      nextStatus,
      operatorUserId,
      auditContext = null
    }) =>
      executeWithDeadlockRetry({
        operation: 'updatePlatformUserStatus',
        onExhausted: 'throw',
        execute: () =>
          dbClient.inTransaction(async (tx) => {
            const normalizedUserId = String(userId || '').trim();
            const normalizedNextStatus = normalizeOrgStatus(nextStatus);
            const normalizedOperatorUserId = String(operatorUserId || '').trim();
            if (
              !normalizedUserId
              || !normalizedOperatorUserId
              || !VALID_PLATFORM_USER_STATUS.has(normalizedNextStatus)
            ) {
              throw new Error(
                'updatePlatformUserStatus requires userId, nextStatus, and operatorUserId'
              );
            }

            const userRows = await tx.query(
              `
                SELECT u.id AS user_id,
                       pu.status AS platform_status
                FROM iam_users u
                INNER JOIN platform_users pu
                  ON pu.user_id = u.id
                WHERE u.id = ?
                LIMIT 1
                FOR UPDATE
              `,
              [normalizedUserId]
            );
            const user = userRows?.[0] || null;
            if (!user) {
              return null;
            }

            const previousStatus = normalizeOrgStatus(user.platform_status);
            if (!VALID_PLATFORM_USER_STATUS.has(previousStatus)) {
              throw new Error('platform-user-status-read-invalid');
            }
            let auditRecorded = false;
            if (previousStatus !== normalizedNextStatus) {
              const updateResult = await tx.query(
                `
                  UPDATE platform_users
                  SET status = ?,
                      updated_at = CURRENT_TIMESTAMP(3)
                  WHERE user_id = ?
                    AND status <> ?
                `,
                [normalizedNextStatus, normalizedUserId, normalizedNextStatus]
              );
              if (Number(updateResult?.affectedRows || 0) !== 1) {
                throw new Error('platform-user-status-write-not-applied');
              }

              if (normalizedNextStatus === 'disabled') {
                await tx.query(
                  `
                    UPDATE auth_sessions
                    SET status = 'revoked',
                        revoked_reason = ?,
                        updated_at = CURRENT_TIMESTAMP(3)
                    WHERE user_id = ?
                      AND entry_domain = 'platform'
                      AND status = 'active'
                  `,
                  ['platform-user-status-changed', normalizedUserId]
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
                          AND entry_domain = 'platform'
                      )
                  `,
                  [normalizedUserId]
                );
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
                  domain: 'platform',
                  tenantId: null,
                  requestId: String(auditContext.requestId || '').trim() || 'request_id_unset',
                  traceparent: auditContext.traceparent,
                  eventType: 'auth.platform.user.status.updated',
                  actorUserId: auditContext.actorUserId,
                  actorSessionId: auditContext.actorSessionId,
                  targetType: 'user',
                  targetId: normalizedUserId,
                  result: 'success',
                  beforeState: {
                    status: previousStatus
                  },
                  afterState: {
                    status: normalizedNextStatus
                  },
                  metadata: {
                    reason: normalizedAuditReason
                  }
                });
                auditRecorded = true;
              } catch (error) {
                const auditWriteError = new Error(
                  'platform user status audit write failed'
                );
                auditWriteError.code = 'ERR_AUDIT_WRITE_FAILED';
                auditWriteError.cause = error;
                throw auditWriteError;
              }
            }

            return {
              user_id: normalizedUserId,
              previous_status: previousStatus,
              current_status: normalizedNextStatus,
              audit_recorded: auditRecorded
            };
          })
      }),

softDeleteUser: async ({
      userId,
      operatorUserId,
      auditContext = null
    }) =>
      executeWithDeadlockRetry({
        operation: 'softDeleteUser',
        onExhausted: 'throw',
        execute: () =>
          dbClient.inTransaction(async (tx) => {
            const normalizedUserId = String(userId || '').trim();
            const normalizedOperatorUserId = String(operatorUserId || '').trim();
            if (!normalizedUserId || !normalizedOperatorUserId) {
              throw new Error('softDeleteUser requires userId and operatorUserId');
            }

            const userRows = await tx.query(
              `
                SELECT id AS user_id, status
                FROM iam_users
                WHERE BINARY id = ?
                LIMIT 1
                FOR UPDATE
              `,
              [normalizedUserId]
            );
            const user = userRows?.[0] || null;
            if (!user) {
              return null;
            }

            const previousStatus = normalizeUserStatus(user.status);
            if (!VALID_PLATFORM_USER_STATUS.has(previousStatus)) {
              throw new Error('platform-user-soft-delete-status-read-invalid');
            }

            let revokedSessionCount = 0;
            let revokedRefreshTokenCount = 0;
            if (previousStatus !== 'disabled') {
              const updateUserResult = await tx.query(
                `
                  UPDATE iam_users
                  SET status = 'disabled',
                      updated_at = CURRENT_TIMESTAMP(3)
                  WHERE BINARY id = ?
                    AND status <> 'disabled'
                `,
                [normalizedUserId]
              );
              if (Number(updateUserResult?.affectedRows || 0) !== 1) {
                throw new Error('platform-user-soft-delete-write-not-applied');
              }
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
                WHERE user_id = ?
                  AND status IN ('active', 'enabled')
              `,
              [normalizedUserId]
            );
            await tx.query(
              `
                UPDATE platform_user_roles
                SET status = 'disabled',
                    updated_at = CURRENT_TIMESTAMP(3)
                WHERE user_id = ?
                  AND status IN ('active', 'enabled')
              `,
              [normalizedUserId]
            );
            await tx.query(
              `
                UPDATE platform_users
                SET status = 'disabled',
                    updated_at = CURRENT_TIMESTAMP(3)
                WHERE user_id = ?
                  AND status IN ('active', 'enabled')
              `,
              [normalizedUserId]
            );
            await tx.query(
              `
                DELETE amr
                FROM tenant_membership_roles amr
                INNER JOIN tenant_memberships ut
                  ON ut.membership_id = amr.membership_id
                WHERE ut.user_id = ?
              `,
              [normalizedUserId]
            );

            const revokeSessionsResult = await tx.query(
              `
                UPDATE auth_sessions
                SET status = 'revoked',
                    revoked_reason = ?,
                    updated_at = CURRENT_TIMESTAMP(3)
                WHERE user_id = ?
                  AND status = 'active'
              `,
              ['user-soft-deleted', normalizedUserId]
            );
            revokedSessionCount = Number(revokeSessionsResult?.affectedRows || 0);

            const revokeRefreshTokensResult = await tx.query(
              `
                UPDATE auth_refresh_tokens
                SET status = 'revoked',
                    updated_at = CURRENT_TIMESTAMP(3)
                WHERE user_id = ?
                  AND status = 'active'
              `,
              [normalizedUserId]
            );
            revokedRefreshTokenCount = Number(
              revokeRefreshTokensResult?.affectedRows || 0
            );

            let auditRecorded = false;
            if (auditContext && typeof auditContext === 'object') {
              try {
                await recordAuditEventWithQueryClient({
                  queryClient: tx,
                  domain: 'platform',
                  tenantId: null,
                  requestId: String(auditContext.requestId || '').trim() || 'request_id_unset',
                  traceparent: auditContext.traceparent,
                  eventType: 'auth.platform.user.soft_deleted',
                  actorUserId: auditContext.actorUserId || normalizedOperatorUserId,
                  actorSessionId: auditContext.actorSessionId,
                  targetType: 'user',
                  targetId: normalizedUserId,
                  result: 'success',
                  beforeState: {
                    status: previousStatus
                  },
                  afterState: {
                    status: 'disabled'
                  },
                  metadata: {
                    revoked_session_count: revokedSessionCount,
                    revoked_refresh_token_count: revokedRefreshTokenCount
                  }
                });
                auditRecorded = true;
              } catch (error) {
                const auditWriteError = new Error(
                  'platform user soft-delete audit write failed'
                );
                auditWriteError.code = 'ERR_AUDIT_WRITE_FAILED';
                auditWriteError.cause = error;
                throw auditWriteError;
              }
            }

            return {
              user_id: normalizedUserId,
              previous_status: previousStatus,
              current_status: 'disabled',
              revoked_session_count: revokedSessionCount,
              revoked_refresh_token_count: revokedRefreshTokenCount,
              audit_recorded: auditRecorded
            };
          })
      }),

deleteUserById: async (userId) => {
      const normalizedUserId = String(userId || '').trim();
      if (!normalizedUserId) {
        return { deleted: false };
      }
      return executeWithDeadlockRetry({
        operation: 'deleteUserById',
        onExhausted: 'return-fallback',
        fallbackResult: { deleted: false },
        execute: () =>
          dbClient.inTransaction(async (tx) => {
            await tx.query(
              `
                DELETE FROM auth_refresh_tokens
                WHERE user_id = ?
              `,
              [normalizedUserId]
            );
            await tx.query(
              `
                DELETE FROM auth_sessions
                WHERE user_id = ?
              `,
              [normalizedUserId]
            );
            await tx.query(
              `
                DELETE FROM platform_user_roles
                WHERE user_id = ?
              `,
              [normalizedUserId]
            );
            await tx.query(
              `
                DELETE FROM platform_users
                WHERE user_id = ?
              `,
              [normalizedUserId]
            );
            await tx.query(
              `
                DELETE FROM tenant_memberships
                WHERE user_id = ?
              `,
              [normalizedUserId]
            );
            const result = await tx.query(
              `
                DELETE FROM iam_users
                WHERE id = ?
              `,
              [normalizedUserId]
            );
            return { deleted: Number(result?.affectedRows || 0) > 0 };
          })
      });
    }
});

module.exports = {
  createPlatformMysqlAuthStoreIdentityGovernance
};
