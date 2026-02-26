'use strict';

const createSharedMemoryAuthStoreSeedUserBootstrapRuntimeSupport = ({
  dedupePlatformRolesByRoleId,
  mergePlatformPermission,
  mergePlatformPermissionFromRoles,
  normalizeOptionalTenantUserProfileField,
  normalizePlatformPermission,
  normalizePlatformRole,
  normalizeTenantUsershipStatus,
  randomUUID,
  resolveOptionalTenantUserProfileField
} = {}) => {
  const bootstrapSeedUsers = ({
    seedUsers = [],
    hashPassword,
    usersByPhone,
    usersById,
    domainsByUserId,
    platformDomainKnownByUserId,
    tenantsByUserId,
    platformProfilesByUserId,
    platformRolesByUserId,
    platformPermissionsByUserId,
    MAX_TENANT_USER_DISPLAY_NAME_LENGTH,
    MAX_TENANT_USER_DEPARTMENT_NAME_LENGTH
  } = {}) => {
    for (const user of seedUsers) {
      const seedCreatedAtCandidate = user.createdAt || user.created_at || null;
      const seedCreatedAtDate = seedCreatedAtCandidate
        ? new Date(seedCreatedAtCandidate)
        : new Date();
      const resolvedCreatedAt = Number.isNaN(seedCreatedAtDate.getTime())
        ? new Date().toISOString()
        : seedCreatedAtDate.toISOString();
      const normalizedUser = {
        id: String(user.id),
        phone: user.phone,
        status: (user.status || 'active').toLowerCase(),
        sessionVersion: Number(user.sessionVersion || 1),
        passwordHash: user.passwordHash || hashPassword(user.password),
        createdAt: resolvedCreatedAt
      };

      usersByPhone.set(normalizedUser.phone, normalizedUser);
      usersById.set(normalizedUser.id, normalizedUser);

      const rawDomains = Array.isArray(user.domains) ? user.domains : ['platform', 'tenant'];
      const domainSet = new Set(
        rawDomains
          .map((domain) => String(domain || '').trim().toLowerCase())
          .filter((domain) => domain === 'platform' || domain === 'tenant')
      );
      domainsByUserId.set(normalizedUser.id, domainSet);
      if (domainSet.has('platform')) {
        platformDomainKnownByUserId.add(normalizedUser.id);
      }

      const rawTenants = Array.isArray(user.tenants) ? user.tenants : [];
      tenantsByUserId.set(
        normalizedUser.id,
        rawTenants
          .filter((tenant) => tenant && tenant.tenantId)
          .map((tenant) => ({
            membershipId: (
              tenant.membershipId
              || tenant.membership_id
              || tenant.usershipId
            )
              ? String(
                tenant.membershipId
                || tenant.membership_id
                || tenant.usershipId
              )
              : randomUUID(),
            tenantId: String(tenant.tenantId),
            tenantName: tenant.tenantName ? String(tenant.tenantName) : null,
            status: normalizeTenantUsershipStatus(tenant.status || 'active'),
            displayName: resolveOptionalTenantUserProfileField(
              tenant.displayName ?? tenant.display_name ?? null
            ),
            departmentName: resolveOptionalTenantUserProfileField(
              tenant.departmentName ?? tenant.department_name ?? null
            ),
            joinedAt: tenant.joinedAt || tenant.joined_at || new Date().toISOString(),
            leftAt: tenant.leftAt || tenant.left_at || null,
            permission: tenant.permission
              ? {
                scopeLabel: tenant.permission.scopeLabel || null,
                canViewUserManagement: Boolean(tenant.permission.canViewUserManagement),
                canOperateUserManagement: Boolean(tenant.permission.canOperateUserManagement),
                canViewRoleManagement: Boolean(tenant.permission.canViewRoleManagement),
                canOperateRoleManagement: Boolean(tenant.permission.canOperateRoleManagement)
              }
              : null
          }))
      );

      const rawPlatformProfile =
        (user.platformProfile && typeof user.platformProfile === 'object')
        || (user.platform_profile && typeof user.platform_profile === 'object')
          ? (user.platformProfile || user.platform_profile)
          : null;
      if (rawPlatformProfile) {
        const normalizedProfileName = normalizeOptionalTenantUserProfileField({
          value: rawPlatformProfile.name,
          maxLength: MAX_TENANT_USER_DISPLAY_NAME_LENGTH
        });
        const normalizedProfileDepartment = normalizeOptionalTenantUserProfileField({
          value: rawPlatformProfile.department,
          maxLength: MAX_TENANT_USER_DEPARTMENT_NAME_LENGTH
        });
        platformProfilesByUserId.set(normalizedUser.id, {
          name: normalizedProfileName,
          department: normalizedProfileDepartment
        });
      }

      const rawPlatformRoles = Array.isArray(user.platformRoles) ? user.platformRoles : [];
      const normalizedPlatformRoles = dedupePlatformRolesByRoleId(
        rawPlatformRoles
          .map((role) => normalizePlatformRole(role))
          .filter(Boolean)
      );
      platformRolesByUserId.set(normalizedUser.id, normalizedPlatformRoles);

      let platformPermission = normalizePlatformPermission(user.platformPermission);
      platformPermission = mergePlatformPermission(
        platformPermission,
        mergePlatformPermissionFromRoles(normalizedPlatformRoles)
      );

      if (platformPermission) {
        platformPermissionsByUserId.set(normalizedUser.id, { ...platformPermission });
      }
    }
  };

  return {
    bootstrapSeedUsers
  };
};

module.exports = {
  createSharedMemoryAuthStoreSeedUserBootstrapRuntimeSupport
};
