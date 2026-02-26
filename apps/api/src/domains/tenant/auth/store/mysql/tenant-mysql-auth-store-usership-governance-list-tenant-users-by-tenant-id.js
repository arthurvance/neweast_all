'use strict';

const createTenantMysqlAuthStoreUsershipGovernanceListTenantUsersByTenantId = ({
  dbClient,
  normalizeTenantUsershipStatusForRead,
  resolveOptionalTenantUserProfileField
} = {}) => ({
listTenantUsersByTenantId: async ({ tenantId, page = 1, pageSize = 50 }) => {
      const normalizedTenantId = String(tenantId || '').trim();
      if (!normalizedTenantId) {
        return [];
      }
      const normalizedPage = Number.parseInt(String(page || '1'), 10);
      const normalizedPageSize = Number.parseInt(String(pageSize || '50'), 10);
      const resolvedPage = Number.isFinite(normalizedPage) && normalizedPage > 0
        ? normalizedPage
        : 1;
      const resolvedPageSize = Number.isFinite(normalizedPageSize) && normalizedPageSize > 0
        ? Math.min(normalizedPageSize, 200)
        : 50;
      const offset = (resolvedPage - 1) * resolvedPageSize;

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
          WHERE ut.tenant_id = ?
          ORDER BY ut.joined_at DESC, ut.membership_id DESC
          LIMIT ? OFFSET ?
        `,
        [normalizedTenantId, resolvedPageSize, offset]
      );
      return (Array.isArray(rows) ? rows : []).map((row) => ({
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
      }));
    }
});

module.exports = {
  createTenantMysqlAuthStoreUsershipGovernanceListTenantUsersByTenantId
};
