'use strict';

const createTenantRoleStatusResyncCapabilities = ({
  authStore,
  errors,
  AuthProblemError,
  hasOwnProperty,
  resolveRawCamelSnakeField,
  normalizeTenantId,
  normalizeStrictAddressableTenantRoleIdFromInput,
  normalizePlatformRoleIdKey,
  loadTenantRolePermissionGrantsByRoleIds,
  invalidateSessionCacheByUserId,
  addAuditEvent,
  TENANT_ROLE_SCOPE,
  MAX_ROLE_PERMISSION_ATOMIC_AFFECTED_USERS,
  CONTROL_CHAR_PATTERN
} = {}) => {
  const toDistinctNormalizedUserIds = (userIds = []) =>
    [...new Set(
      (Array.isArray(userIds) ? userIds : [])
        .map((userId) => String(userId || '').trim())
        .filter((userId) => userId.length > 0)
    )];

  const normalizeStrictDistinctUserIdsFromDependency = ({
    userIds,
    dependencyReason = 'tenant-role-permission-grants-update-affected-user-ids-invalid'
  } = {}) => {
    if (!Array.isArray(userIds)) {
      throw errors.tenantUserDependencyUnavailable({
        reason: dependencyReason
      });
    }
    const normalizedUserIds = [];
    const seenUserIds = new Set();
    for (const userId of userIds) {
      if (typeof userId !== 'string') {
        throw errors.tenantUserDependencyUnavailable({
          reason: dependencyReason
        });
      }
      const normalizedUserId = userId.trim();
      if (
        userId !== normalizedUserId
        || !normalizedUserId
        || CONTROL_CHAR_PATTERN.test(normalizedUserId)
      ) {
        throw errors.tenantUserDependencyUnavailable({
          reason: dependencyReason
        });
      }
      if (seenUserIds.has(normalizedUserId)) {
        continue;
      }
      seenUserIds.add(normalizedUserId);
      normalizedUserIds.push(normalizedUserId);
    }
    return normalizedUserIds;
  };

  const normalizeStrictNonNegativeIntegerFromDependency = ({
    value,
    dependencyReason = 'tenant-role-permission-grants-update-affected-user-count-invalid'
  } = {}) => {
    if (typeof value !== 'number' || !Number.isInteger(value) || value < 0) {
      throw errors.tenantUserDependencyUnavailable({
        reason: dependencyReason
      });
    }
    return value;
  };

  const resyncTenantRoleStatusAffectedSnapshots = async ({
    tenantId,
    roleId,
    requestId = 'request_id_unset',
    operatorUserId = null,
    operatorSessionId = null
  } = {}) => {
    const normalizedTenantId = normalizeTenantId(tenantId);
    const normalizedRoleId = normalizeStrictAddressableTenantRoleIdFromInput(roleId);
    if (!normalizedTenantId) {
      throw errors.invalidPayload();
    }
    if (typeof authStore?.replaceTenantRolePermissionGrantsAndSyncSnapshots !== 'function') {
      throw errors.tenantUserDependencyUnavailable({
        reason: 'tenant-role-status-resync-unsupported'
      });
    }

    let currentPermissionCodes = [];
    try {
      const grantsByRoleIdKey = await loadTenantRolePermissionGrantsByRoleIds({
        roleIds: [normalizedRoleId]
      });
      currentPermissionCodes =
        grantsByRoleIdKey.get(normalizePlatformRoleIdKey(normalizedRoleId)) || [];
    } catch (error) {
      if (error instanceof AuthProblemError) {
        throw error;
      }
      throw errors.tenantUserDependencyUnavailable({
        reason: 'tenant-role-status-permission-grants-query-failed'
      });
    }

    let syncResult = null;
    try {
      syncResult = await authStore.replaceTenantRolePermissionGrantsAndSyncSnapshots({
        tenantId: normalizedTenantId,
        roleId: normalizedRoleId,
        permissionCodes: currentPermissionCodes,
        operatorUserId,
        operatorSessionId,
        maxAffectedMemberships: MAX_ROLE_PERMISSION_ATOMIC_AFFECTED_USERS
      });
    } catch (error) {
      if (error instanceof AuthProblemError) {
        throw error;
      }
      if (
        String(error?.code || '').trim()
        === 'ERR_TENANT_ROLE_PERMISSION_AFFECTED_MEMBERSHIPS_OVER_LIMIT'
      ) {
        throw errors.tenantUserDependencyUnavailable({
          reason: 'tenant-role-status-affected-memberships-over-limit'
        });
      }
      if (String(error?.code || '').trim() === 'ERR_TENANT_ROLE_PERMISSION_SYNC_FAILED') {
        throw errors.tenantUserDependencyUnavailable({
          reason: String(error?.syncReason || 'tenant-role-status-resync-failed')
        });
      }
      throw errors.tenantUserDependencyUnavailable({
        reason: 'tenant-role-status-resync-failed'
      });
    }

    if (!syncResult) {
      return {
        affectedUserCount: 0,
        affectedMembershipCount: 0
      };
    }

    const affectedUserIdsRaw = (
      resolveRawCamelSnakeField(syncResult, 'affectedUserIds', 'affected_user_ids')
    );
    const affectedUserIds = toDistinctNormalizedUserIds(affectedUserIdsRaw);
    const hasExplicitAffectedMembershipCount = (
      hasOwnProperty(syncResult, 'affectedMembershipCount')
      || hasOwnProperty(syncResult, 'affected_membership_count')
    );
    const affectedMembershipCount = hasExplicitAffectedMembershipCount
      ? normalizeStrictNonNegativeIntegerFromDependency({
        value: resolveRawCamelSnakeField(
          syncResult,
          'affectedMembershipCount',
          'affected_membership_count'
        ),
        dependencyReason: 'tenant-role-status-affected-membership-count-invalid'
      })
      : affectedUserIds.length;
    for (const affectedUserId of affectedUserIds) {
      invalidateSessionCacheByUserId(affectedUserId);
    }

    addAuditEvent({
      type: 'auth.role.catalog.status.sync',
      requestId,
      userId: operatorUserId || 'unknown',
      sessionId: operatorSessionId || 'unknown',
      detail: 'tenant role status change resynced affected tenant snapshots',
      metadata: {
        role_id: normalizedRoleId,
        scope: TENANT_ROLE_SCOPE,
        tenant_id: normalizedTenantId,
        affected_user_count: affectedUserIds.length,
        affected_membership_count: affectedMembershipCount
      }
    });

    return {
      affectedUserCount: affectedUserIds.length,
      affectedMembershipCount
    };
  };

  return {
    normalizeStrictDistinctUserIdsFromDependency,
    normalizeStrictNonNegativeIntegerFromDependency,
    resyncTenantRoleStatusAffectedSnapshots
  };
};

module.exports = {
  createTenantRoleStatusResyncCapabilities
};
