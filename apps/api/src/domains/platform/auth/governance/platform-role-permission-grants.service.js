'use strict';

const createPlatformRolePermissionGrantCapabilities = ({
  authStore,
  errors,
  AuthProblemError,
  hasOwnProperty,
  normalizeRequiredStringField,
  normalizeStrictRequiredStringField,
  normalizePlatformRoleIdKey,
  loadValidatedPlatformRoleCatalogEntriesForRoleFacts,
  loadPlatformRolePermissionGrantsByRoleIds,
  listSupportedPlatformPermissionCodes,
  listPlatformPermissionCatalogItems,
  normalizePlatformPermissionCode,
  toPlatformPermissionCodeKey,
  isPlatformPermissionCode,
  SUPPORTED_PLATFORM_PERMISSION_CODE_SET,
  CONTROL_CHAR_PATTERN,
  MAX_ROLE_PERMISSION_CODES_PER_REQUEST,
  MAX_ROLE_PERMISSION_ATOMIC_AFFECTED_USERS,
  resolveRawCamelSnakeField,
  normalizeStrictDistinctUserIdsFromPlatformDependency,
  normalizeStrictNonNegativeIntegerFromPlatformDependency,
  toDistinctNormalizedUserIds,
  invalidateSessionCacheByUserId,
  normalizeStoredRoleFactsForPermissionResync,
  cloneRoleFactsSnapshotForRollback,
  toPlatformPermissionSnapshotFromCodes,
  recordPersistentAuditEvent,
  normalizeAuditStringOrNull,
  addAuditEvent
} = {}) => {
  const listPlatformPermissionCatalog = () =>
    listSupportedPlatformPermissionCodes();

  const listPlatformPermissionCatalogEntries = () =>
    listPlatformPermissionCatalogItems();

  const listPlatformRolePermissionGrants = async ({ roleId }) => {
    const normalizedRoleId = normalizeRequiredStringField(
      roleId,
      errors.invalidPayload
    ).toLowerCase();
    const {
      requestedRoleIds
    } = await loadValidatedPlatformRoleCatalogEntriesForRoleFacts({
      roles: [{ roleId: normalizedRoleId }],
      allowDisabledRoles: true
    });
    const grantsByRoleIdKey = await loadPlatformRolePermissionGrantsByRoleIds({
      roleIds: requestedRoleIds
    });
    const grants = grantsByRoleIdKey.get(normalizePlatformRoleIdKey(normalizedRoleId)) || [];
    return {
      role_id: normalizedRoleId,
      permission_codes: grants,
      available_permission_codes: listPlatformPermissionCatalog(),
      available_permissions: listPlatformPermissionCatalogEntries()
    };
  };

  const replacePlatformRolePermissionGrants = async ({
    requestId,
    traceparent = null,
    roleId,
    permissionCodes = [],
    operatorUserId = null,
    operatorSessionId = null
  }) => {
    const normalizedRoleId = normalizeRequiredStringField(
      roleId,
      errors.invalidPayload
    ).toLowerCase();
    const normalizedTargetRoleIdKey = normalizePlatformRoleIdKey(normalizedRoleId);
    if (!Array.isArray(permissionCodes)) {
      throw errors.invalidPayload();
    }
    if (permissionCodes.length > MAX_ROLE_PERMISSION_CODES_PER_REQUEST) {
      throw errors.invalidPayload();
    }
    const dedupedPermissionCodes = new Map();
    for (const permissionCode of permissionCodes) {
      const normalizedPermissionCode = normalizePlatformPermissionCode(permissionCode);
      if (!normalizedPermissionCode) {
        throw errors.invalidPayload();
      }
      const permissionCodeKey = toPlatformPermissionCodeKey(normalizedPermissionCode);
      if (
        !isPlatformPermissionCode(normalizedPermissionCode)
        || !SUPPORTED_PLATFORM_PERMISSION_CODE_SET.has(permissionCodeKey)
      ) {
        throw errors.invalidPayload();
      }
      dedupedPermissionCodes.set(permissionCodeKey, permissionCodeKey);
    }
    const normalizedPermissionCodes = [...dedupedPermissionCodes.values()];

    await loadValidatedPlatformRoleCatalogEntriesForRoleFacts({
      roles: [{ roleId: normalizedRoleId }],
      allowDisabledRoles: true
    });
    let previousPermissionCodesForAudit = null;
    let previousTargetRolePermissionCodes = null;
    try {
      const previousGrantsByRoleIdKey = await loadPlatformRolePermissionGrantsByRoleIds({
        roleIds: [normalizedRoleId]
      });
      const resolvedPreviousPermissionCodes =
        previousGrantsByRoleIdKey.get(normalizedTargetRoleIdKey) || [];
      previousPermissionCodesForAudit = [...resolvedPreviousPermissionCodes];
      previousTargetRolePermissionCodes = [...resolvedPreviousPermissionCodes];
    } catch (_error) {
      previousPermissionCodesForAudit = null;
      previousTargetRolePermissionCodes = null;
    }

    if (typeof authStore.replacePlatformRolePermissionGrantsAndSyncSnapshots === 'function') {
      let atomicWriteResult;
      try {
        atomicWriteResult =
          await authStore.replacePlatformRolePermissionGrantsAndSyncSnapshots({
            roleId: normalizedRoleId,
            permissionCodes: normalizedPermissionCodes,
            operatorUserId,
            operatorSessionId,
            auditContext: {
              requestId: normalizeAuditStringOrNull(requestId, 128) || 'request_id_unset',
              traceparent: normalizeAuditStringOrNull(traceparent, 128),
              actorUserId: normalizeAuditStringOrNull(operatorUserId, 64),
              actorSessionId: normalizeAuditStringOrNull(operatorSessionId, 128)
            },
            maxAffectedUsers: MAX_ROLE_PERMISSION_ATOMIC_AFFECTED_USERS
          });
      } catch (error) {
        if (error instanceof AuthProblemError) {
          throw error;
        }
        if (String(error?.code || '').trim()
          === 'ERR_PLATFORM_ROLE_PERMISSION_AFFECTED_USERS_OVER_LIMIT') {
          throw errors.platformSnapshotDegraded({
            reason: 'platform-role-permission-affected-users-over-limit'
          });
        }
        if (String(error?.code || '').trim() === 'ERR_PLATFORM_ROLE_PERMISSION_SYNC_FAILED') {
          throw errors.platformSnapshotDegraded({
            reason: String(error?.syncReason || 'platform-role-permission-resync-failed')
          });
        }
        if (String(error?.code || '').trim() === 'ERR_AUDIT_WRITE_FAILED') {
          throw errors.platformSnapshotDegraded({
            reason: 'audit-write-failed'
          });
        }
        const normalizedErrorMessage = String(error?.message || '')
          .trim()
          .toLowerCase();
        throw errors.platformSnapshotDegraded({
          reason: normalizedErrorMessage.includes('deadlock')
            ? 'db-deadlock'
            : 'platform-role-permission-atomic-write-failed'
        });
      }

      if (!atomicWriteResult) {
        throw errors.roleNotFound();
      }

      const rawResolvedRoleId = (
        resolveRawCamelSnakeField(
          atomicWriteResult,
          'roleId',
          'role_id'
        )
      );
      const resolvedRoleId = normalizeStrictRequiredStringField(rawResolvedRoleId).toLowerCase();
      if (!resolvedRoleId || resolvedRoleId !== normalizedRoleId) {
        throw errors.platformSnapshotDegraded({
          reason: 'platform-role-permission-grants-update-role-mismatch'
        });
      }

      const savedPermissionCodes = Array.isArray(atomicWriteResult?.permissionCodes)
        ? atomicWriteResult.permissionCodes
        : Array.isArray(atomicWriteResult?.permission_codes)
          ? atomicWriteResult.permission_codes
          : [];
      const normalizedSavedPermissionCodeKeys = [];
      const seenSavedPermissionCodeKeys = new Set();
      for (const permissionCode of savedPermissionCodes) {
        const normalizedPermissionCode = normalizeStrictRequiredStringField(permissionCode);
        const permissionCodeKey = toPlatformPermissionCodeKey(normalizedPermissionCode);
        if (
          !normalizedPermissionCode
          || CONTROL_CHAR_PATTERN.test(normalizedPermissionCode)
          || seenSavedPermissionCodeKeys.has(permissionCodeKey)
          || !isPlatformPermissionCode(normalizedPermissionCode)
          || !SUPPORTED_PLATFORM_PERMISSION_CODE_SET.has(permissionCodeKey)
        ) {
          throw errors.platformSnapshotDegraded({
            reason: 'platform-role-permission-grants-update-invalid'
          });
        }
        seenSavedPermissionCodeKeys.add(permissionCodeKey);
        normalizedSavedPermissionCodeKeys.push(permissionCodeKey);
      }
      normalizedSavedPermissionCodeKeys.sort((left, right) => left.localeCompare(right));
      const expectedPermissionCodeKeys = [...normalizedPermissionCodes]
        .sort((left, right) => left.localeCompare(right));
      const hasPermissionCodesMismatch = (
        expectedPermissionCodeKeys.length !== normalizedSavedPermissionCodeKeys.length
        || expectedPermissionCodeKeys.some(
          (permissionCode, index) => permissionCode !== normalizedSavedPermissionCodeKeys[index]
        )
      );
      if (hasPermissionCodesMismatch) {
        throw errors.platformSnapshotDegraded({
          reason: 'platform-role-permission-grants-update-mismatch'
        });
      }
      const hasAffectedUserIds = (
        hasOwnProperty(atomicWriteResult, 'affectedUserIds')
        || hasOwnProperty(atomicWriteResult, 'affected_user_ids')
      );
      const hasExplicitAffectedUserCount = (
        hasOwnProperty(atomicWriteResult, 'affectedUserCount')
        || hasOwnProperty(atomicWriteResult, 'affected_user_count')
      );
      if (!hasAffectedUserIds || !hasExplicitAffectedUserCount) {
        throw errors.platformSnapshotDegraded({
          reason: 'platform-role-permission-grants-update-affected-user-metadata-missing'
        });
      }
      const affectedUserIds = normalizeStrictDistinctUserIdsFromPlatformDependency({
        userIds: resolveRawCamelSnakeField(
          atomicWriteResult,
          'affectedUserIds',
          'affected_user_ids'
        ),
        dependencyReason: 'platform-role-permission-grants-update-affected-user-ids-invalid'
      });
      const resyncedUserCount = normalizeStrictNonNegativeIntegerFromPlatformDependency({
        value: resolveRawCamelSnakeField(
          atomicWriteResult,
          'affectedUserCount',
          'affected_user_count'
        ),
        dependencyReason: 'platform-role-permission-grants-update-affected-user-count-invalid'
      });
      if (
        hasExplicitAffectedUserCount
        && resyncedUserCount !== affectedUserIds.length
      ) {
        throw errors.platformSnapshotDegraded({
          reason: 'platform-role-permission-grants-update-affected-user-count-invalid'
        });
      }
      for (const affectedUserId of affectedUserIds) {
        invalidateSessionCacheByUserId(affectedUserId);
      }

      addAuditEvent({
        type: 'auth.platform_role_permission_grants.updated',
        requestId,
        userId: operatorUserId || 'unknown',
        sessionId: operatorSessionId || 'unknown',
        detail: 'platform role permission grants replaced and affected snapshots resynced',
        metadata: {
          role_id: normalizedRoleId,
          permission_codes: normalizedSavedPermissionCodeKeys,
          affected_user_count: resyncedUserCount
        }
      });
      const storeAuditRecorded = (
        atomicWriteResult?.auditRecorded === true
        || atomicWriteResult?.audit_recorded === true
      );
      if (!storeAuditRecorded) {
        await recordPersistentAuditEvent({
          domain: 'platform',
          tenantId: null,
          requestId: normalizeAuditStringOrNull(requestId, 128) || 'request_id_unset',
          traceparent: normalizeAuditStringOrNull(traceparent, 128),
          eventType: 'auth.platform_role_permission_grants.updated',
          actorUserId: normalizeAuditStringOrNull(operatorUserId, 64),
          actorSessionId: normalizeAuditStringOrNull(operatorSessionId, 128),
          targetType: 'role_permission_grants',
          targetId: normalizedRoleId,
          result: 'success',
          beforeState: {
            permission_codes: Array.isArray(previousPermissionCodesForAudit)
              ? [...previousPermissionCodesForAudit]
              : null
          },
          afterState: {
            permission_codes: [...normalizedSavedPermissionCodeKeys]
          },
          metadata: {
            affected_user_count: resyncedUserCount
          }
        });
      }

      return {
        role_id: normalizedRoleId,
        permission_codes: normalizedSavedPermissionCodeKeys,
        affected_user_count: resyncedUserCount
      };
    }

    if (typeof authStore.replacePlatformRolePermissionGrants !== 'function') {
      throw errors.platformSnapshotDegraded({
        reason: 'platform-role-permission-grants-unsupported'
      });
    }
    if (
      typeof authStore.listUserIdsByPlatformRoleId !== 'function'
      || typeof authStore.listPlatformRoleFactsByUserId !== 'function'
      || typeof authStore.replacePlatformRolesAndSyncSnapshot !== 'function'
    ) {
      throw errors.platformSnapshotDegraded({
        reason: 'platform-role-permission-resync-unsupported'
      });
    }

    let affectedUserIds = [];
    try {
      affectedUserIds = await authStore.listUserIdsByPlatformRoleId({
        roleId: normalizedRoleId
      });
    } catch (_error) {
      throw errors.platformSnapshotDegraded({
        reason: 'platform-role-permission-affected-users-query-failed'
      });
    }
    const precheckedAffectedUserIds = toDistinctNormalizedUserIds(affectedUserIds);
    for (const normalizedAffectedUserId of precheckedAffectedUserIds) {
      try {
        await authStore.listPlatformRoleFactsByUserId({
          userId: normalizedAffectedUserId
        });
      } catch (_error) {
        throw errors.platformSnapshotDegraded({
          reason: 'platform-role-permission-role-facts-query-failed'
        });
      }
    }

    if (!Array.isArray(previousTargetRolePermissionCodes)) {
      try {
        const previousTargetRoleGrantsByRoleIdKey =
          await loadPlatformRolePermissionGrantsByRoleIds({
            roleIds: [normalizedRoleId]
          });
        previousTargetRolePermissionCodes =
          previousTargetRoleGrantsByRoleIdKey.get(normalizedTargetRoleIdKey) || [];
        previousPermissionCodesForAudit = [...previousTargetRolePermissionCodes];
      } catch (error) {
        if (error instanceof AuthProblemError) {
          throw error;
        }
        throw errors.platformSnapshotDegraded({
          reason: 'platform-role-permission-grants-query-failed'
        });
      }
    }

    let savedPermissionCodes = [];
    let grantsWriteApplied = false;
    const preSyncRoleFactsByUserId = new Map();
    const normalizedRoleFactsByUserId = new Map();
    const syncedUserIds = [];
    try {
      const saved = await authStore.replacePlatformRolePermissionGrants({
        roleId: normalizedRoleId,
        permissionCodes: normalizedPermissionCodes,
        operatorUserId,
        operatorSessionId
      });
      if (!saved) {
        throw errors.roleNotFound();
      }
      savedPermissionCodes = [...new Set(
        (Array.isArray(saved) ? saved : [])
          .map((permissionCode) => normalizePlatformPermissionCode(permissionCode))
          .filter((permissionCode) => permissionCode.length > 0)
      )];
      grantsWriteApplied = true;

      let postWriteAffectedUserIds = [];
      try {
        postWriteAffectedUserIds = await authStore.listUserIdsByPlatformRoleId({
          roleId: normalizedRoleId
        });
      } catch (_error) {
        throw errors.platformSnapshotDegraded({
          reason: 'platform-role-permission-affected-users-query-failed'
        });
      }
      const normalizedAffectedUserIds = [...new Set([
        ...precheckedAffectedUserIds,
        ...toDistinctNormalizedUserIds(postWriteAffectedUserIds)
      ])];

      const normalizedAllRoleIds = new Set();
      for (const normalizedAffectedUserId of normalizedAffectedUserIds) {
        let roleFacts = [];
        try {
          roleFacts = await authStore.listPlatformRoleFactsByUserId({
            userId: normalizedAffectedUserId
          });
        } catch (_error) {
          throw errors.platformSnapshotDegraded({
            reason: 'platform-role-permission-role-facts-query-failed'
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
          reason: 'platform-role-permission-grants-query-failed'
        });
      }

      for (const normalizedAffectedUserId of normalizedAffectedUserIds) {
        const normalizedStoredRoleFacts =
          normalizedRoleFactsByUserId.get(normalizedAffectedUserId) || [];
        const nextRoleFacts = normalizedStoredRoleFacts.map((roleFact) => {
          const permissionCodes = grantsByRoleIdKey.get(roleFact.roleIdKey) || [];
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
            reason: 'platform-role-permission-resync-failed'
          });
        }
        const syncReason = String(syncResult?.reason || 'unknown').trim().toLowerCase();
        if (syncReason !== 'ok') {
          throw errors.platformSnapshotDegraded({
            reason: syncReason || 'platform-role-permission-resync-failed'
          });
        }
        syncedUserIds.push(normalizedAffectedUserId);
        invalidateSessionCacheByUserId(normalizedAffectedUserId);
      }
    } catch (error) {
      if (grantsWriteApplied) {
        try {
          const restoredGrants = await authStore.replacePlatformRolePermissionGrants({
            roleId: normalizedRoleId,
            permissionCodes: previousTargetRolePermissionCodes,
            operatorUserId,
            operatorSessionId
          });
          if (!restoredGrants) {
            throw new Error('platform-role-permission-grants-rollback-role-not-found');
          }
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
              throw new Error(`platform-role-permission-resync-rollback-failed:${rollbackReason}`);
            }
            invalidateSessionCacheByUserId(syncedUserId);
          }
        } catch (_rollbackError) {
          throw errors.platformSnapshotDegraded({
            reason: 'platform-role-permission-compensation-failed'
          });
        }
      }
      if (error instanceof AuthProblemError) {
        throw error;
      }
      throw errors.platformSnapshotDegraded({
        reason: 'platform-role-permission-resync-failed'
      });
    }
    const resyncedUserCount = syncedUserIds.length;

    addAuditEvent({
      type: 'auth.platform_role_permission_grants.updated',
      requestId,
      userId: operatorUserId || 'unknown',
      sessionId: operatorSessionId || 'unknown',
      detail: 'platform role permission grants replaced and affected snapshots resynced',
      metadata: {
        role_id: normalizedRoleId,
        permission_codes: savedPermissionCodes,
        affected_user_count: resyncedUserCount
      }
    });
    await recordPersistentAuditEvent({
      domain: 'platform',
      tenantId: null,
      requestId: normalizeAuditStringOrNull(requestId, 128) || 'request_id_unset',
      traceparent: normalizeAuditStringOrNull(traceparent, 128),
      eventType: 'auth.platform_role_permission_grants.updated',
      actorUserId: normalizeAuditStringOrNull(operatorUserId, 64),
      actorSessionId: normalizeAuditStringOrNull(operatorSessionId, 128),
      targetType: 'role_permission_grants',
      targetId: normalizedRoleId,
      result: 'success',
      beforeState: {
        permission_codes: Array.isArray(previousPermissionCodesForAudit)
          ? [...previousPermissionCodesForAudit]
          : null
      },
      afterState: {
        permission_codes: [...savedPermissionCodes]
      },
      metadata: {
        affected_user_count: resyncedUserCount
      }
    });

    return {
      role_id: normalizedRoleId,
      permission_codes: savedPermissionCodes,
      affected_user_count: resyncedUserCount
    };
  };

  return {
    listPlatformRolePermissionGrants,
    replacePlatformRolePermissionGrants
  };
};

module.exports = {
  createPlatformRolePermissionGrantCapabilities
};
