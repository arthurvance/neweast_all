'use strict';

const createTenantMemoryAuthStoreUsershipGovernanceFindTenantUsershipByMembershipIdAndTenantId = ({
  findTenantUsershipStateByMembershipId,
  normalizeTenantUsershipStatusForRead,
  resolveOptionalTenantUserProfileField,
  usersById
} = {}) => ({
findTenantUsershipByMembershipIdAndTenantId: async ({
      membershipId,
      tenantId
    }) => {
      const normalizedMembershipId = String(membershipId || '').trim();
      const normalizedTenantId = String(tenantId || '').trim();
      if (!normalizedMembershipId || !normalizedTenantId) {
        return null;
      }
      const membershipState = findTenantUsershipStateByMembershipId(
        normalizedMembershipId
      );
      if (!membershipState) {
        return null;
      }
      const membership = membershipState.membership;
      if (String(membership?.tenantId || '').trim() !== normalizedTenantId) {
        return null;
      }
      const resolvedUserId = String(membershipState.userId || '').trim();
      const user = usersById.get(resolvedUserId);
      return {
        membership_id: normalizedMembershipId,
        user_id: resolvedUserId,
        tenant_id: normalizedTenantId,
        tenant_name: membership?.tenantName ? String(membership.tenantName) : null,
        phone: user?.phone ? String(user.phone) : '',
        status: normalizeTenantUsershipStatusForRead(membership?.status),
        display_name: resolveOptionalTenantUserProfileField(
          membership?.displayName
        ),
        department_name: resolveOptionalTenantUserProfileField(
          membership?.departmentName
        ),
        joined_at: membership?.joinedAt || null,
        left_at: membership?.leftAt || null
      };
    }
});

module.exports = {
  createTenantMemoryAuthStoreUsershipGovernanceFindTenantUsershipByMembershipIdAndTenantId
};
