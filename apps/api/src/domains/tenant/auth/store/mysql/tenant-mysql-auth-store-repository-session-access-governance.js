'use strict';

const createTenantMysqlAuthStoreRepositorySessionAccessGovernance = ({
  dbClient,
  runTenantUsershipQuery,
  toBoolean
} = {}) => ({
  ensureTenantDomainAccessForUser: async (userId) => {
    const normalizedUserId = String(userId || '').trim();
    if (!normalizedUserId) {
      return { inserted: false };
    }
    const tenantCountRows = await runTenantUsershipQuery({
      sqlWithOrgGuard: `
        SELECT COUNT(*) AS tenant_count
        FROM tenant_memberships ut
        LEFT JOIN tenants o ON o.id = ut.tenant_id
        WHERE ut.user_id = ?
          AND ut.status IN ('active', 'enabled')
          AND o.status IN ('active', 'enabled')
      `,
      sqlWithoutOrgGuard: `
        SELECT COUNT(*) AS tenant_count
        FROM tenant_memberships ut
        WHERE ut.user_id = ?
          AND ut.status IN ('active', 'enabled')
      `,
      params: [normalizedUserId]
    });
    const tenantCount = Number(tenantCountRows?.[0]?.tenant_count || 0);
    return {
      inserted: false,
      has_active_tenant_membership: tenantCount > 0
    };
  },

  findTenantPermissionByUserAndTenantId: async ({ userId, tenantId }) => {
    const normalizedUserId = String(userId);
    const normalizedTenantId = String(tenantId || '').trim();
    if (!normalizedTenantId) {
      return null;
    }

    const rows = await runTenantUsershipQuery({
      sqlWithOrgGuard: `
          SELECT tenant_id,
                 tenant_name,
                 can_view_user_management,
                 can_operate_user_management,
                 can_view_role_management,
                 can_operate_role_management
          FROM tenant_memberships ut
          LEFT JOIN tenants o ON o.id = ut.tenant_id
          WHERE ut.user_id = ?
            AND ut.tenant_id = ?
            AND ut.status IN ('active', 'enabled')
            AND o.status IN ('active', 'enabled')
          LIMIT 1
        `,
      sqlWithoutOrgGuard: `
          SELECT tenant_id,
                 tenant_name,
                 can_view_user_management,
                 can_operate_user_management,
                 can_view_role_management,
                 can_operate_role_management
          FROM tenant_memberships ut
          WHERE ut.user_id = ?
            AND ut.tenant_id = ?
            AND ut.status IN ('active', 'enabled')
          LIMIT 1
        `,
      params: [normalizedUserId, normalizedTenantId]
    });
    const row = rows?.[0];
    if (!row) {
      return null;
    }
    return {
      scopeLabel: `组织权限（${String(row.tenant_name || normalizedTenantId)}）`,
      canViewUserManagement: toBoolean(row.can_view_user_management),
      canOperateUserManagement: toBoolean(row.can_operate_user_management),
      canViewRoleManagement: toBoolean(row.can_view_role_management),
      canOperateRoleManagement: toBoolean(row.can_operate_role_management)
    };
  },

  listTenantOptionsByUserId: async (userId) => {
    const normalizedUserId = String(userId);
    const rows = await runTenantUsershipQuery({
      sqlWithOrgGuard: `
          SELECT tenant_id,
                 tenant_name,
                 u.phone AS owner_phone,
                 (
                   SELECT ut_owner.display_name
                   FROM tenant_memberships ut_owner
                   WHERE ut_owner.user_id = o.owner_user_id
                     AND ut_owner.tenant_id = o.id
                     AND ut_owner.display_name IS NOT NULL
                     AND TRIM(ut_owner.display_name) <> ''
                   ORDER BY ut_owner.joined_at DESC, ut_owner.membership_id DESC
                   LIMIT 1
                 ) AS owner_name
          FROM tenant_memberships ut
          LEFT JOIN tenants o ON o.id = ut.tenant_id
          LEFT JOIN iam_users u ON u.id = o.owner_user_id
          WHERE ut.user_id = ?
            AND ut.status IN ('active', 'enabled')
            AND o.status IN ('active', 'enabled')
          ORDER BY tenant_id ASC
        `,
      sqlWithoutOrgGuard: `
          SELECT tenant_id,
                 tenant_name,
                 NULL AS owner_phone,
                 NULL AS owner_name
          FROM tenant_memberships ut
          WHERE ut.user_id = ?
            AND ut.status IN ('active', 'enabled')
          ORDER BY tenant_id ASC
        `,
      params: [normalizedUserId]
    });

    return (Array.isArray(rows) ? rows : [])
      .map((row) => {
        const ownerName = row.owner_name ? String(row.owner_name).trim() : null;
        const ownerPhone = row.owner_phone ? String(row.owner_phone).trim() : null;
        return {
          tenantId: String(row.tenant_id || '').trim(),
          tenantName: row.tenant_name ? String(row.tenant_name) : null,
          ...(ownerName ? { ownerName } : {}),
          ...(ownerPhone ? { ownerPhone } : {})
        };
      })
      .filter((row) => row.tenantId.length > 0);
  },

  hasAnyTenantRelationshipByUserId: async (userId) => {
    const normalizedUserId = String(userId);
    const rows = await dbClient.query(
      `
        SELECT COUNT(*) AS tenant_count
        FROM tenant_memberships
        WHERE user_id = ?
      `,
      [normalizedUserId]
    );
    return Number(rows?.[0]?.tenant_count || 0) > 0;
  },
});

module.exports = {
  createTenantMysqlAuthStoreRepositorySessionAccessGovernance
};
