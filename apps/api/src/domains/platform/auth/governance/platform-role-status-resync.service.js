'use strict';

const createPlatformRoleStatusResyncCapabilities = ({
  authStore,
  errors,
  AuthProblemError,
  normalizeRequiredStringField,
  resolveRawRoleIdCandidate,
  normalizePlatformRoleIdKey,
  normalizePlatformRoleCatalogStatus,
  normalizePlatformRoleCatalogScope,
  normalizeTenantId,
  resolveRawCamelSnakeField,
  loadPlatformRolePermissionGrantsByRoleIds,
  invalidateSessionCacheByUserId,
  toPlatformPermissionSnapshotFromCodes,
  addAuditEvent,
  VALID_PLATFORM_ROLE_FACT_STATUS,
  PLATFORM_ROLE_CATALOG_SCOPE,
  CONTROL_CHAR_PATTERN
} = {}) => {
  const toDistinctNormalizedUserIds = (userIds = []) =>
    [...new Set(
      (Array.isArray(userIds) ? userIds : [])
        .map((userId) => String(userId || '').trim())
        .filter((userId) => userId.length > 0)
    )];

  const normalizeStrictDistinctUserIdsFromPlatformDependency = ({
    userIds,
    dependencyReason = 'platform-role-permission-grants-update-affected-user-ids-invalid'
  } = {}) => {
    if (!Array.isArray(userIds)) {
      throw errors.platformSnapshotDegraded({
        reason: dependencyReason
      });
    }
    const normalizedUserIds = [];
    const seenUserIds = new Set();
    for (const userId of userIds) {
      if (typeof userId !== 'string') {
        throw errors.platformSnapshotDegraded({
          reason: dependencyReason
        });
      }
      const normalizedUserId = userId.trim();
      if (
        userId !== normalizedUserId
        || !normalizedUserId
        || CONTROL_CHAR_PATTERN.test(normalizedUserId)
      ) {
        throw errors.platformSnapshotDegraded({
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

  const normalizeStrictNonNegativeIntegerFromPlatformDependency = ({
    value,
    dependencyReason = 'platform-role-permission-grants-update-affected-user-count-invalid'
  } = {}) => {
    if (typeof value !== 'number' || !Number.isInteger(value) || value < 0) {
      throw errors.platformSnapshotDegraded({
        reason: dependencyReason
      });
    }
    return value;
  };

  const normalizeStoredRoleFactsForPermissionResync = (roleFacts = []) => {
    const normalizedStoredRoleFacts = [];
    for (const roleFact of Array.isArray(roleFacts) ? roleFacts : []) {
      let normalizedRoleFactRoleId;
      try {
        normalizedRoleFactRoleId = normalizeRequiredStringField(
          resolveRawRoleIdCandidate(roleFact),
          errors.invalidPayload
        );
      } catch (_error) {
        throw errors.platformSnapshotDegraded({
          reason: 'platform-role-permission-role-facts-invalid'
        });
      }
      const normalizedRoleFactRoleIdKey =
        normalizePlatformRoleIdKey(normalizedRoleFactRoleId);
      const normalizedRoleFactStatusInput = String(
        roleFact?.status || 'active'
      ).trim().toLowerCase();
      if (!VALID_PLATFORM_ROLE_FACT_STATUS.has(normalizedRoleFactStatusInput)) {
        throw errors.platformSnapshotDegraded({
          reason: 'platform-role-permission-role-facts-invalid'
        });
      }
      const normalizedRoleFactStatus = normalizedRoleFactStatusInput === 'enabled'
        ? 'active'
        : normalizedRoleFactStatusInput;
      normalizedStoredRoleFacts.push({
        roleIdKey: normalizedRoleFactRoleIdKey,
        status: normalizedRoleFactStatus
      });
    }
    return normalizedStoredRoleFacts;
  };

  const cloneRoleFactsSnapshotForRollback = (roleFacts = []) =>
    (Array.isArray(roleFacts) ? roleFacts : []).map((roleFact) => ({
      roleId: String(roleFact?.roleId || roleFact?.role_id || '').trim(),
      role_id: String(roleFact?.roleId || roleFact?.role_id || '').trim(),
      status: String(roleFact?.status || 'active').trim().toLowerCase() || 'active',
      permission:
        roleFact?.permission
        && typeof roleFact.permission === 'object'
        && !Array.isArray(roleFact.permission)
          ? {
            canViewUserManagement: Boolean(
              roleFact.permission.canViewUserManagement
              ?? roleFact.permission.can_view_user_management
            ),
            canOperateUserManagement: Boolean(
              roleFact.permission.canOperateUserManagement
              ?? roleFact.permission.can_operate_user_management
            ),
            canViewTenantManagement: Boolean(
              roleFact.permission.canViewTenantManagement
              ?? roleFact.permission.can_view_tenant_management
            ),
            canOperateTenantManagement: Boolean(
              roleFact.permission.canOperateTenantManagement
              ?? roleFact.permission.can_operate_tenant_management
            )
          }
          : null
    }));

  const normalizeRoleCatalogStatusForResync = (status) => {
    const normalizedStatus = normalizePlatformRoleCatalogStatus(status);
    return normalizedStatus || 'disabled';
  };

  const isPlatformCatalogRoleActiveForPermissionResync = (catalogEntry = null) => {
    if (!catalogEntry || typeof catalogEntry !== 'object') {
      return false;
    }
    const normalizedScope = normalizePlatformRoleCatalogScope(
      resolveRawCamelSnakeField(catalogEntry, 'scope', 'scope')
    );
    const normalizedTenantId = normalizeTenantId(
      resolveRawCamelSnakeField(catalogEntry, 'tenantId', 'tenant_id')
    );
    const normalizedStatus = normalizeRoleCatalogStatusForResync(
      resolveRawCamelSnakeField(catalogEntry, 'status', 'status')
    );
    return normalizedScope === PLATFORM_ROLE_CATALOG_SCOPE
      && !normalizedTenantId
      && (normalizedStatus === 'active' || normalizedStatus === 'enabled');
  };

  const resyncPlatformRoleStatusAffectedSnapshots = async ({
    roleId,
    requestId = 'request_id_unset'
  } = {}) => {
    const normalizedRoleId = normalizeRequiredStringField(
      roleId,
      errors.invalidPayload
    ).toLowerCase();
    if (
      typeof authStore.listUserIdsByPlatformRoleId !== 'function'
      || typeof authStore.listPlatformRoleFactsByUserId !== 'function'
      || typeof authStore.replacePlatformRolesAndSyncSnapshot !== 'function'
      || typeof authStore.findPlatformRoleCatalogEntriesByRoleIds !== 'function'
    ) {
      throw errors.platformSnapshotDegraded({
        reason: 'platform-role-status-resync-unsupported'
      });
    }

    let affectedUserIds = [];
    try {
      affectedUserIds = await authStore.listUserIdsByPlatformRoleId({
        roleId: normalizedRoleId
      });
    } catch (_error) {
      throw errors.platformSnapshotDegraded({
        reason: 'platform-role-status-affected-users-query-failed'
      });
    }
    const normalizedAffectedUserIds = toDistinctNormalizedUserIds(affectedUserIds);
    if (normalizedAffectedUserIds.length === 0) {
      return {
        affectedUserCount: 0,
        affectedMembershipCount: 0
      };
    }

    const preSyncRoleFactsByUserId = new Map();
    const normalizedRoleFactsByUserId = new Map();
    const normalizedAllRoleIds = new Set();
    for (const normalizedAffectedUserId of normalizedAffectedUserIds) {
      let roleFacts = [];
      try {
        roleFacts = await authStore.listPlatformRoleFactsByUserId({
          userId: normalizedAffectedUserId
        });
      } catch (_error) {
        throw errors.platformSnapshotDegraded({
          reason: 'platform-role-status-role-facts-query-failed'
        });
      }
      preSyncRoleFactsByUserId.set(
        normalizedAffectedUserId,
        cloneRoleFactsSnapshotForRollback(roleFacts)
      );
      const normalizedStoredRoleFacts = normalizeStoredRoleFactsForPermissionResync(roleFacts);
      normalizedRoleFactsByUserId.set(
        normalizedAffectedUserId,
        normalizedStoredRoleFacts
      );
      for (const roleFact of normalizedStoredRoleFacts) {
        normalizedAllRoleIds.add(roleFact.roleIdKey);
      }
    }

    let grantsByRoleIdKey = new Map();
    try {
      grantsByRoleIdKey = await loadPlatformRolePermissionGrantsByRoleIds({
        roleIds: [...normalizedAllRoleIds]
      });
    } catch (error) {
      if (error instanceof AuthProblemError) {
        throw error;
      }
      throw errors.platformSnapshotDegraded({
        reason: 'platform-role-status-permission-grants-query-failed'
      });
    }

    let catalogEntries = [];
    try {
      catalogEntries = await authStore.findPlatformRoleCatalogEntriesByRoleIds({
        roleIds: [...normalizedAllRoleIds]
      });
    } catch (_error) {
      throw errors.platformSnapshotDegraded({
        reason: 'platform-role-status-catalog-query-failed'
      });
    }
    const activeCatalogRoleIdSet = new Set(
      (Array.isArray(catalogEntries) ? catalogEntries : [])
        .filter((catalogEntry) =>
          isPlatformCatalogRoleActiveForPermissionResync(catalogEntry)
        )
        .map((catalogEntry) =>
          normalizePlatformRoleIdKey(
            resolveRawCamelSnakeField(catalogEntry, 'roleId', 'role_id')
          )
        )
        .filter((roleIdKey) => roleIdKey.length > 0)
    );

    const syncedUserIds = [];
    try {
      for (const normalizedAffectedUserId of normalizedAffectedUserIds) {
        const normalizedStoredRoleFacts =
          normalizedRoleFactsByUserId.get(normalizedAffectedUserId) || [];
        const nextRoleFacts = normalizedStoredRoleFacts.map((roleFact) => {
          const permissionCodes = activeCatalogRoleIdSet.has(roleFact.roleIdKey)
            ? (grantsByRoleIdKey.get(roleFact.roleIdKey) || [])
            : [];
          return {
            roleId: roleFact.roleIdKey,
            status: roleFact.status,
            permission: toPlatformPermissionSnapshotFromCodes(permissionCodes)
          };
        });
        let syncResult;
        try {
          syncResult = await authStore.replacePlatformRolesAndSyncSnapshot({
            userId: normalizedAffectedUserId,
            roles: nextRoleFacts
          });
        } catch (_error) {
          throw errors.platformSnapshotDegraded({
            reason: 'platform-role-status-resync-failed'
          });
        }
        const syncReason = String(syncResult?.reason || 'unknown').trim().toLowerCase();
        if (syncReason !== 'ok') {
          throw errors.platformSnapshotDegraded({
            reason: syncReason || 'platform-role-status-resync-failed'
          });
        }
        syncedUserIds.push(normalizedAffectedUserId);
        invalidateSessionCacheByUserId(normalizedAffectedUserId);
      }
    } catch (error) {
      try {
        for (const syncedUserId of [...syncedUserIds].reverse()) {
          const rollbackRoleFacts = preSyncRoleFactsByUserId.get(syncedUserId) || [];
          const rollbackResult = await authStore.replacePlatformRolesAndSyncSnapshot({
            userId: syncedUserId,
            roles: rollbackRoleFacts
          });
          const rollbackReason = String(
            rollbackResult?.reason || 'unknown'
          ).trim().toLowerCase();
          if (rollbackReason !== 'ok') {
            throw new Error(
              `platform-role-status-resync-rollback-failed:${rollbackReason || 'unknown'}`
            );
          }
          invalidateSessionCacheByUserId(syncedUserId);
        }
      } catch (_rollbackError) {
        throw errors.platformSnapshotDegraded({
          reason: 'platform-role-status-compensation-failed'
        });
      }
      if (error instanceof AuthProblemError) {
        throw error;
      }
      throw errors.platformSnapshotDegraded({
        reason: 'platform-role-status-resync-failed'
      });
    }

    addAuditEvent({
      type: 'auth.role.catalog.status.sync',
      requestId,
      userId: 'system',
      sessionId: 'system',
      detail: 'platform role status change resynced affected platform snapshots',
      metadata: {
        role_id: normalizedRoleId,
        scope: PLATFORM_ROLE_CATALOG_SCOPE,
        tenant_id: null,
        affected_user_count: syncedUserIds.length,
        affected_membership_count: 0
      }
    });

    return {
      affectedUserCount: syncedUserIds.length,
      affectedMembershipCount: 0
    };
  };

  return {
    toDistinctNormalizedUserIds,
    normalizeStrictDistinctUserIdsFromPlatformDependency,
    normalizeStrictNonNegativeIntegerFromPlatformDependency,
    normalizeStoredRoleFactsForPermissionResync,
    cloneRoleFactsSnapshotForRollback,
    normalizeRoleCatalogStatusForResync,
    resyncPlatformRoleStatusAffectedSnapshots
  };
};

module.exports = {
  createPlatformRoleStatusResyncCapabilities
};
