'use strict';

const createTenantMemoryAuthStoreUsershipGovernanceListTenantUsersByTenantId = ({
  normalizeTenantUsershipStatusForRead,
  resolveOptionalTenantUserProfileField,
  tenantsByUserId,
  usersById
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
      const members = [];
      for (const [userId, memberships] of tenantsByUserId.entries()) {
        const user = usersById.get(String(userId));
        if (!user) {
          continue;
        }
        for (const membership of Array.isArray(memberships) ? memberships : []) {
          if (String(membership?.tenantId || '').trim() !== normalizedTenantId) {
            continue;
          }
          members.push({
            membership_id: String(membership.membershipId || '').trim(),
            user_id: String(userId),
            tenant_id: normalizedTenantId,
            tenant_name: membership?.tenantName ? String(membership.tenantName) : null,
            phone: String(user.phone || ''),
            status: normalizeTenantUsershipStatusForRead(membership?.status),
            display_name: resolveOptionalTenantUserProfileField(
              membership?.displayName
            ),
            department_name: resolveOptionalTenantUserProfileField(
              membership?.departmentName
            ),
            joined_at: membership?.joinedAt || null,
            left_at: membership?.leftAt || null
          });
        }
      }
      members.sort((left, right) => {
        const leftJoinedAt = Date.parse(String(left.joined_at || ''));
        const rightJoinedAt = Date.parse(String(right.joined_at || ''));
        const normalizedLeftJoinedAt = Number.isFinite(leftJoinedAt) ? leftJoinedAt : 0;
        const normalizedRightJoinedAt = Number.isFinite(rightJoinedAt) ? rightJoinedAt : 0;
        if (normalizedLeftJoinedAt !== normalizedRightJoinedAt) {
          return normalizedRightJoinedAt - normalizedLeftJoinedAt;
        }
        return String(right.membership_id || '').localeCompare(
          String(left.membership_id || '')
        );
      });
      const offset = (resolvedPage - 1) * resolvedPageSize;
      return members.slice(offset, offset + resolvedPageSize);
    }
});

module.exports = {
  createTenantMemoryAuthStoreUsershipGovernanceListTenantUsersByTenantId
};
