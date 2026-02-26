'use strict';

const createTenantMysqlAuthStoreUsershipGovernanceListTenantUsershipRoleBindings = ({
  createTenantUsershipRoleBindingDataError,
  dbClient,
  normalizeStrictTenantUsershipRoleIdFromBindingRow
} = {}) => ({
listTenantUsershipRoleBindings: async ({
      membershipId,
      tenantId
    } = {}) => {
      const normalizedMembershipId = String(membershipId || '').trim();
      const normalizedTenantId = String(tenantId || '').trim();
      if (!normalizedMembershipId || !normalizedTenantId) {
        return [];
      }
      const rows = await dbClient.query(
        `
          SELECT mr.role_id
          FROM tenant_membership_roles mr
          JOIN tenant_memberships ut ON ut.membership_id = mr.membership_id
          WHERE mr.membership_id = ?
            AND ut.tenant_id = ?
          ORDER BY mr.role_id ASC
        `,
        [normalizedMembershipId, normalizedTenantId]
      );
      const normalizedRoleIds = [];
      const seenRoleIds = new Set();
      for (const row of Array.isArray(rows) ? rows : []) {
        const normalizedRoleId = normalizeStrictTenantUsershipRoleIdFromBindingRow(
          row?.role_id,
          'tenant-membership-role-bindings-invalid-role-id'
        );
        if (seenRoleIds.has(normalizedRoleId)) {
          throw createTenantUsershipRoleBindingDataError(
            'tenant-membership-role-bindings-duplicate-role-id'
          );
        }
        seenRoleIds.add(normalizedRoleId);
        normalizedRoleIds.push(normalizedRoleId);
      }
      return normalizedRoleIds.sort((left, right) => left.localeCompare(right));
    }
});

module.exports = {
  createTenantMysqlAuthStoreUsershipGovernanceListTenantUsershipRoleBindings
};
