'use strict';

const createTenantMemoryAuthStoreUsershipGovernanceUpdateTenantUsershipProfile = ({
  MAINLAND_PHONE_PATTERN,
  MAX_TENANT_USER_DEPARTMENT_NAME_LENGTH,
  MAX_TENANT_USER_DISPLAY_NAME_LENGTH,
  findTenantUsershipStateByMembershipId,
  isStrictOptionalTenantUserProfileField,
  normalizeOptionalTenantUserProfileField,
  normalizeTenantUsershipStatusForRead,
  resolveOptionalTenantUserProfileField,
  usersById
} = {}) => ({
updateTenantUsershipProfile: async ({
      membershipId,
      tenantId,
      displayName,
      departmentNameProvided = false,
      departmentName = null
    }) => {
      const normalizedMembershipId = String(membershipId || '').trim();
      const normalizedTenantId = String(tenantId || '').trim();
      const normalizedDisplayName = normalizeOptionalTenantUserProfileField({
        value: displayName,
        maxLength: MAX_TENANT_USER_DISPLAY_NAME_LENGTH
      });
      if (
        !normalizedMembershipId
        || !normalizedTenantId
        || normalizedDisplayName === null
      ) {
        throw new Error(
          'updateTenantUsershipProfile requires membershipId, tenantId and displayName'
        );
      }
      const shouldUpdateDepartmentName = departmentNameProvided === true;
      let normalizedDepartmentName = null;
      if (shouldUpdateDepartmentName) {
        if (departmentName === null) {
          normalizedDepartmentName = null;
        } else {
          normalizedDepartmentName = normalizeOptionalTenantUserProfileField({
            value: departmentName,
            maxLength: MAX_TENANT_USER_DEPARTMENT_NAME_LENGTH
          });
          if (normalizedDepartmentName === null) {
            throw new Error('updateTenantUsershipProfile departmentName is invalid');
          }
        }
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
      const rawUserPhone = user?.phone === null || user?.phone === undefined
        ? ''
        : String(user.phone);
      const normalizedUserPhone = rawUserPhone.trim();
      if (
        !normalizedUserPhone
        || rawUserPhone !== normalizedUserPhone
        || !MAINLAND_PHONE_PATTERN.test(normalizedUserPhone)
      ) {
        const dependencyError = new Error(
          'updateTenantUsershipProfile dependency unavailable: user-profile-missing'
        );
        dependencyError.code =
          'ERR_TENANT_MEMBERSHIP_PROFILE_DEPENDENCY_UNAVAILABLE';
        throw dependencyError;
      }
      if (
        !shouldUpdateDepartmentName
        && !isStrictOptionalTenantUserProfileField({
          value: membership?.departmentName,
          maxLength: MAX_TENANT_USER_DEPARTMENT_NAME_LENGTH
        })
      ) {
        const dependencyError = new Error(
          'updateTenantUsershipProfile dependency unavailable: membership-profile-invalid'
        );
        dependencyError.code =
          'ERR_TENANT_MEMBERSHIP_PROFILE_DEPENDENCY_UNAVAILABLE';
        throw dependencyError;
      }
      membership.displayName = normalizedDisplayName;
      if (shouldUpdateDepartmentName) {
        membership.departmentName = normalizedDepartmentName;
      }
      return {
        membership_id: normalizedMembershipId,
        user_id: resolvedUserId,
        tenant_id: normalizedTenantId,
        tenant_name: membership?.tenantName ? String(membership.tenantName) : null,
        phone: normalizedUserPhone,
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
  createTenantMemoryAuthStoreUsershipGovernanceUpdateTenantUsershipProfile
};
