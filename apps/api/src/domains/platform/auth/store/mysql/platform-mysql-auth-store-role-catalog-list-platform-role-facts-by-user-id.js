'use strict';

const createPlatformMysqlAuthStoreRoleCatalogListPlatformRoleFactsByUserId = ({
  dbClient,
  toBoolean
} = {}) => ({
listPlatformRoleFactsByUserId: async ({ userId }) => {
      const normalizedUserId = String(userId || '').trim();
      if (!normalizedUserId) {
        return [];
      }
      const rows = await dbClient.query(
        `
          SELECT role_id,
                 status,
                 can_view_user_management,
                 can_operate_user_management,
                 can_view_tenant_management,
                 can_operate_tenant_management
          FROM platform_user_roles
          WHERE user_id = ?
          ORDER BY role_id ASC
        `,
        [normalizedUserId]
      );
      return (Array.isArray(rows) ? rows : []).map((row) => ({
        roleId: String(row?.role_id || '').trim(),
        role_id: String(row?.role_id || '').trim(),
        status: String(row?.status || 'active').trim().toLowerCase() || 'active',
        permission: {
          canViewUserManagement: toBoolean(row?.can_view_user_management),
          canOperateUserManagement: toBoolean(row?.can_operate_user_management),
          canViewTenantManagement: toBoolean(row?.can_view_tenant_management),
          canOperateTenantManagement: toBoolean(row?.can_operate_tenant_management)
        }
      }));
    }
});

module.exports = {
  createPlatformMysqlAuthStoreRoleCatalogListPlatformRoleFactsByUserId
};
