'use strict';

const createTenantMysqlAuthStoreUsershipGovernanceCreateTenantUsershipForUser = ({
  VALID_TENANT_MEMBERSHIP_STATUS,
  dbClient,
  executeWithDeadlockRetry,
  insertTenantUsershipHistoryTx,
  isDuplicateEntryError,
  normalizeTenantUsershipStatusForRead,
  randomUUID
} = {}) => ({
createTenantUsershipForUser: async ({ userId, tenantId, tenantName = null }) => {
      const normalizedUserId = String(userId || '').trim();
      const normalizedTenantId = String(tenantId || '').trim();
      if (!normalizedUserId || !normalizedTenantId) {
        throw new Error('createTenantUsershipForUser requires userId and tenantId');
      }
      const normalizedTenantName = tenantName === null || tenantName === undefined
        ? null
        : String(tenantName).trim() || null;
      return executeWithDeadlockRetry({
        operation: 'createTenantUsershipForUser',
        onExhausted: 'throw',
        execute: () =>
          dbClient.inTransaction(async (tx) => {
            const userRows = await tx.query(
              `
                SELECT id
                FROM iam_users
                WHERE id = ?
                LIMIT 1
                FOR UPDATE
              `,
              [normalizedUserId]
            );
            if (!Array.isArray(userRows) || userRows.length === 0) {
              return { created: false };
            }

            const existingRows = await tx.query(
              `
                SELECT membership_id,
                       user_id,
                       tenant_id,
                       tenant_name,
                       status,
                       display_name,
                       department_name,
                       can_view_user_management,
                       can_operate_user_management,
                       can_view_role_management,
                       can_operate_role_management,
                       joined_at,
                       left_at
                FROM tenant_memberships
                WHERE user_id = ? AND tenant_id = ?
                LIMIT 1
                FOR UPDATE
              `,
              [normalizedUserId, normalizedTenantId]
            );
            const existing = existingRows?.[0] || null;
            if (!existing) {
              const membershipId = randomUUID();
              let result;
              try {
                result = await tx.query(
                  `
                    INSERT INTO tenant_memberships (
                      membership_id,
                      user_id,
                      tenant_id,
                      tenant_name,
                      status,
                      display_name,
                      department_name,
                      joined_at,
                      left_at
                    )
                    VALUES (?, ?, ?, ?, 'active', NULL, NULL, CURRENT_TIMESTAMP(3), NULL)
                  `,
                  [
                    membershipId,
                    normalizedUserId,
                    normalizedTenantId,
                    normalizedTenantName
                  ]
                );
              } catch (error) {
                if (isDuplicateEntryError(error)) {
                  return { created: false };
                }
                throw error;
              }
              return { created: Number(result?.affectedRows || 0) > 0 };
            }

            const existingStatus = normalizeTenantUsershipStatusForRead(existing.status);
            if (!VALID_TENANT_MEMBERSHIP_STATUS.has(existingStatus)) {
              throw new Error(
                'createTenantUsershipForUser encountered unsupported existing status'
              );
            }
            if (existingStatus !== 'left') {
              return { created: false };
            }

            const previousMembershipId = String(existing.membership_id || '').trim();
            await insertTenantUsershipHistoryTx({
              txClient: tx,
              row: {
                ...existing,
                membership_id: previousMembershipId,
                user_id: normalizedUserId,
                tenant_id: normalizedTenantId
              },
              archivedReason: 'rejoin',
              archivedByUserId: null
            });

            await tx.query(
              `
                DELETE FROM tenant_membership_roles
                WHERE membership_id = ?
              `,
              [previousMembershipId]
            );

            const nextMembershipId = randomUUID();
            const updateResult = await tx.query(
              `
                UPDATE tenant_memberships
                SET membership_id = ?,
                    tenant_name = ?,
                    status = 'active',
                    can_view_user_management = 0,
                    can_operate_user_management = 0,
                    can_view_role_management = 0,
                    can_operate_role_management = 0,
                    joined_at = CURRENT_TIMESTAMP(3),
                    left_at = NULL,
                    updated_at = CURRENT_TIMESTAMP(3)
                WHERE user_id = ? AND tenant_id = ?
              `,
              [
                nextMembershipId,
                normalizedTenantName,
                normalizedUserId,
                normalizedTenantId
              ]
            );
            return { created: Number(updateResult?.affectedRows || 0) > 0 };
          })
      });
    }
});

module.exports = {
  createTenantMysqlAuthStoreUsershipGovernanceCreateTenantUsershipForUser
};
