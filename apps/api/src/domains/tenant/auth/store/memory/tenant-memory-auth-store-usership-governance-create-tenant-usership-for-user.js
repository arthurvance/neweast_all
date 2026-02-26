'use strict';

const createTenantMemoryAuthStoreUsershipGovernanceCreateTenantUsershipForUser = ({
  VALID_TENANT_MEMBERSHIP_STATUS,
  appendTenantUsershipHistory,
  normalizeTenantUsershipStatusForRead,
  randomUUID,
  tenantUsershipRolesByMembershipId,
  tenantsByUserId,
  usersById
} = {}) => ({
createTenantUsershipForUser: async ({ userId, tenantId, tenantName = null }) => {
      const normalizedUserId = String(userId || '').trim();
      const normalizedTenantId = String(tenantId || '').trim();
      if (!normalizedUserId || !normalizedTenantId) {
        throw new Error('createTenantUsershipForUser requires userId and tenantId');
      }
      if (!usersById.has(normalizedUserId)) {
        return { created: false };
      }
      const normalizedTenantName = tenantName === null || tenantName === undefined
        ? null
        : String(tenantName).trim() || null;

      const tenantUserships = tenantsByUserId.get(normalizedUserId) || [];
      const existingMembership = tenantUserships.find(
        (tenant) => String(tenant?.tenantId || '').trim() === normalizedTenantId
      );
      if (existingMembership) {
        const currentStatus = normalizeTenantUsershipStatusForRead(existingMembership.status);
        if (!VALID_TENANT_MEMBERSHIP_STATUS.has(currentStatus)) {
          throw new Error('createTenantUsershipForUser encountered unsupported existing status');
        }
        if (currentStatus !== 'left') {
          return { created: false };
        }
        appendTenantUsershipHistory({
          membership: {
            ...existingMembership,
            userId: normalizedUserId,
            tenantId: normalizedTenantId
          },
          reason: 'rejoin',
          operatorUserId: null
        });
        const previousMembershipId = String(existingMembership.membershipId || '').trim();
        existingMembership.membershipId = randomUUID();
        existingMembership.tenantName = normalizedTenantName;
        existingMembership.status = 'active';
        existingMembership.leftAt = null;
        existingMembership.joinedAt = new Date().toISOString();
        existingMembership.permission = {
          scopeLabel: `组织权限（${normalizedTenantName || normalizedTenantId}）`,
          canViewUserManagement: false,
          canOperateUserManagement: false,
          canViewRoleManagement: false,
          canOperateRoleManagement: false
        };
        if (previousMembershipId) {
          tenantUsershipRolesByMembershipId.delete(previousMembershipId);
        }
        tenantUsershipRolesByMembershipId.set(
          String(existingMembership.membershipId || '').trim(),
          []
        );
        tenantsByUserId.set(normalizedUserId, tenantUserships);
        return { created: true };
      }

      const membershipId = randomUUID();
      tenantUserships.push({
        membershipId,
        tenantId: normalizedTenantId,
        tenantName: normalizedTenantName,
        status: 'active',
        displayName: null,
        departmentName: null,
        joinedAt: new Date().toISOString(),
        leftAt: null,
        permission: {
          scopeLabel: `组织权限（${normalizedTenantName || normalizedTenantId}）`,
          canViewUserManagement: false,
          canOperateUserManagement: false,
          canViewRoleManagement: false,
          canOperateRoleManagement: false
        }
      });
      tenantUsershipRolesByMembershipId.set(membershipId, []);
      tenantsByUserId.set(normalizedUserId, tenantUserships);
      return { created: true };
    }
});

module.exports = {
  createTenantMemoryAuthStoreUsershipGovernanceCreateTenantUsershipForUser
};
