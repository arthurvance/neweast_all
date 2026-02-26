'use strict';

const createTenantMysqlAuthStoreUsershipGovernanceFindTenantUsershipByUserAndTenantId = ({
  dbClient,
  normalizeTenantUsershipStatusForRead,
  resolveOptionalTenantUserProfileField
} = {}) => ({
findTenantUsershipByUserAndTenantId: async ({ userId, tenantId }) => {
      const normalizedUserId = String(userId || '').trim();
      const normalizedTenantId = String(tenantId || '').trim();
      if (!normalizedUserId || !normalizedTenantId) {
        return null;
      }
      const rows = await dbClient.query(
        `
          SELECT ut.membership_id,
                 ut.user_id,
                 ut.tenant_id,
                 ut.tenant_name,
                 ut.status,
                 ut.display_name,
                 ut.department_name,
                 ut.joined_at,
                 ut.left_at,
                 u.phone
          FROM tenant_memberships ut
          LEFT JOIN iam_users u ON u.id = ut.user_id
          WHERE ut.user_id = ? AND ut.tenant_id = ?
          LIMIT 1
        `,
        [normalizedUserId, normalizedTenantId]
      );
      const row = rows?.[0];
      if (!row) {
        return null;
      }
      return {
        membership_id: String(row.membership_id || '').trim(),
        user_id: String(row.user_id || '').trim(),
        tenant_id: String(row.tenant_id || '').trim(),
        tenant_name: row.tenant_name ? String(row.tenant_name) : null,
        phone: String(row.phone || ''),
        status: normalizeTenantUsershipStatusForRead(row.status),
        display_name: resolveOptionalTenantUserProfileField(row.display_name),
        department_name: resolveOptionalTenantUserProfileField(
          row.department_name
        ),
        joined_at: row.joined_at ? new Date(row.joined_at).toISOString() : null,
        left_at: row.left_at ? new Date(row.left_at).toISOString() : null
      };
    }
});

module.exports = {
  createTenantMysqlAuthStoreUsershipGovernanceFindTenantUsershipByUserAndTenantId
};
