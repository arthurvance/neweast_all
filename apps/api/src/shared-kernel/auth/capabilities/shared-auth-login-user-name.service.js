'use strict';

const createSharedAuthLoginUserNameCapabilities = ({
  userRepository,
  authStore,
  normalizeTenantId,
  normalizeTenantUsershipRecordFromStore,
  normalizeAuditStringOrNull
} = {}) => {
  const resolveLoginUserName = async ({
    userId,
    entryDomain,
    activeTenantId = null
  } = {}) => {
    const normalizedUserId = String(userId || '').trim();
    if (!normalizedUserId) {
      return null;
    }

    if (entryDomain === 'platform') {
      if (typeof userRepository.getPlatformUserById !== 'function') {
        return null;
      }
      try {
        const userProfile = await userRepository.getPlatformUserById({
          userId: normalizedUserId
        });
        return normalizeAuditStringOrNull(userProfile?.name, 64);
      } catch (_error) {
        return null;
      }
    }

    if (entryDomain === 'tenant') {
      const normalizedTenantId = normalizeTenantId(activeTenantId);
      if (!normalizedTenantId) {
        return null;
      }
      if (typeof authStore.findTenantUsershipByUserAndTenantId !== 'function') {
        return null;
      }
      try {
        const membership = await authStore.findTenantUsershipByUserAndTenantId({
          userId: normalizedUserId,
          tenantId: normalizedTenantId
        });
        const normalizedMembership = normalizeTenantUsershipRecordFromStore({
          membership,
          expectedUserId: normalizedUserId,
          expectedTenantId: normalizedTenantId
        });
        if (!normalizedMembership || normalizedMembership.status !== 'active') {
          return null;
        }
        return normalizeAuditStringOrNull(normalizedMembership.display_name, 64);
      } catch (_error) {
        return null;
      }
    }

    return null;
  };

  return {
    resolveLoginUserName
  };
};

module.exports = {
  createSharedAuthLoginUserNameCapabilities
};
