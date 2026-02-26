'use strict';

const createTenantMemoryAuthStoreUsershipGovernanceFindTenantUsershipByUserAndTenantId = ({
  normalizeTenantUsershipStatusForRead,
  resolveOptionalTenantUserProfileField,
  tenantsByUserId,
  usersById
} = {}) => ({
findTenantUsershipByUserAndTenantId: async ({ userId, tenantId }) => {
      const normalizedUserId = String(userId || '').trim();
      const normalizedTenantId = String(tenantId || '').trim();
      if (!normalizedUserId || !normalizedTenantId) {
        return null;
      }
      const membership = (tenantsByUserId.get(normalizedUserId) || []).find(
        (item) => String(item?.tenantId || '').trim() === normalizedTenantId
      );
      if (!membership) {
        return null;
      }
      const user = usersById.get(normalizedUserId);
      return {
        membership_id: String(membership.membershipId || '').trim(),
        user_id: normalizedUserId,
        tenant_id: normalizedTenantId,
        tenant_name: membership.tenantName ? String(membership.tenantName) : null,
        phone: user?.phone ? String(user.phone) : '',
        status: normalizeTenantUsershipStatusForRead(membership.status),
        display_name: resolveOptionalTenantUserProfileField(membership.displayName),
        department_name: resolveOptionalTenantUserProfileField(
          membership.departmentName
        ),
        joined_at: membership.joinedAt || null,
        left_at: membership.leftAt || null
      };
    }
});

module.exports = {
  createTenantMemoryAuthStoreUsershipGovernanceFindTenantUsershipByUserAndTenantId
};
