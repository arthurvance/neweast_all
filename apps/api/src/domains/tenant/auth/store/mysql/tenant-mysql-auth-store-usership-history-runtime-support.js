'use strict';

const createTenantMysqlAuthStoreUsershipHistoryRuntimeSupport = ({
  createTenantUsershipHistoryUnavailableError,
  isMissingTenantUsershipHistoryTableError,
  normalizeTenantUsershipStatusForRead,
  VALID_TENANT_MEMBERSHIP_STATUS,
  toBoolean
} = {}) => {
  let tenantUsershipHistoryTableAvailable = true;

  const insertTenantUsershipHistoryTx = async ({
    txClient,
    row,
    archivedReason = null,
    archivedByUserId = null
  }) => {
    if (!tenantUsershipHistoryTableAvailable) {
      throw createTenantUsershipHistoryUnavailableError();
    }
    const normalizedRowStatus = normalizeTenantUsershipStatusForRead(row?.status);
    if (!VALID_TENANT_MEMBERSHIP_STATUS.has(normalizedRowStatus)) {
      throw new Error('insertTenantUsershipHistoryTx encountered unsupported status');
    }
    try {
      await txClient.query(
        `
          INSERT INTO auth_user_tenant_membership_history (
            membership_id,
            user_id,
            tenant_id,
            tenant_name,
            status,
            can_view_user_management,
            can_operate_user_management,
            can_view_role_management,
            can_operate_role_management,
            joined_at,
            left_at,
            archived_reason,
            archived_by_user_id
          )
          VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        `,
        [
          String(row?.membership_id || '').trim(),
          String(row?.user_id || '').trim(),
          String(row?.tenant_id || '').trim(),
          row?.tenant_name === null || row?.tenant_name === undefined
            ? null
            : String(row.tenant_name || '').trim() || null,
          normalizedRowStatus,
          toBoolean(row?.can_view_user_management) ? 1 : 0,
          toBoolean(row?.can_operate_user_management) ? 1 : 0,
          toBoolean(row?.can_view_role_management) ? 1 : 0,
          toBoolean(row?.can_operate_role_management) ? 1 : 0,
          row?.joined_at || row?.created_at || null,
          row?.left_at || null,
          archivedReason === null || archivedReason === undefined
            ? null
            : String(archivedReason || '').trim() || null,
          archivedByUserId === null || archivedByUserId === undefined
            ? null
            : String(archivedByUserId || '').trim() || null
        ]
      );
    } catch (error) {
      if (isMissingTenantUsershipHistoryTableError(error)) {
        tenantUsershipHistoryTableAvailable = false;
        throw createTenantUsershipHistoryUnavailableError();
      }
      throw error;
    }
  };

  const isTenantUsershipHistoryTableAvailable = () =>
    tenantUsershipHistoryTableAvailable;

  return {
    insertTenantUsershipHistoryTx,
    isTenantUsershipHistoryTableAvailable
  };
};

module.exports = {
  createTenantMysqlAuthStoreUsershipHistoryRuntimeSupport
};
