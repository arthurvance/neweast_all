'use strict';

const createPlatformRoleFactsGovernanceCapabilities = ({
  authStore,
  errors,
  isPlainObject,
  hasOwnProperty,
  hasTopLevelPlatformRolePermissionField,
  assertOptionalBooleanRolePermission,
  resolveRawRoleIdCandidate,
  normalizeRequiredStringField,
  normalizePlatformRoleIdKey,
  normalizeAuditStringOrNull,
  resolveRawCamelSnakeField,
  toPlatformPermissionSnapshotFromCodes,
  loadValidatedPlatformRoleCatalogEntriesForRoleFacts,
  loadPlatformRolePermissionGrantsByRoleIds,
  authorizeRoute,
  isDuplicateRoleFactEntryError,
  isDataTooLongRoleFactError,
  addAuditEvent,
  recordPersistentAuditEvent,
  invalidateSessionCacheByUserId,
  VALID_PLATFORM_ROLE_FACT_STATUS,
  PLATFORM_ROLE_ASSIGNMENT_ALLOWED_FIELDS,
  PLATFORM_ROLE_FACTS_REPLACE_PERMISSION_CODE,
  MAX_PLATFORM_ROLE_ID_LENGTH,
  MAX_PLATFORM_ROLE_FACTS_PER_USER
} = {}) => {
  const normalizePlatformRoleFactsForReplace = async ({
    roles = [],
    enforceRoleCatalogValidation = false
  }) => {
    const normalizedRoleFacts = [];
    const distinctRoleIds = new Set();

    for (const role of roles) {
      if (!isPlainObject(role)) {
        throw errors.invalidPayload();
      }

      const unknownRoleKeys = Object.keys(role).filter(
        (key) => !PLATFORM_ROLE_ASSIGNMENT_ALLOWED_FIELDS.has(key) && key !== 'permission'
      );
      if (enforceRoleCatalogValidation && unknownRoleKeys.length > 0) {
        throw errors.invalidPayload();
      }

      const hasPermissionField = hasOwnProperty(role, 'permission');
      if (
        enforceRoleCatalogValidation
        && (hasPermissionField || hasTopLevelPlatformRolePermissionField(role))
      ) {
        throw errors.invalidPayload();
      }
      if (!enforceRoleCatalogValidation && hasPermissionField && !isPlainObject(role.permission)) {
        throw errors.invalidPayload();
      }
      if (!enforceRoleCatalogValidation && hasTopLevelPlatformRolePermissionField(role)) {
        throw errors.invalidPayload();
      }

      const rawRoleId = resolveRawRoleIdCandidate(role);
      const normalizedRoleId = normalizeRequiredStringField(
        rawRoleId,
        errors.invalidPayload
      );
      const normalizedRoleIdKey = normalizePlatformRoleIdKey(normalizedRoleId);
      if (normalizedRoleIdKey.length > MAX_PLATFORM_ROLE_ID_LENGTH) {
        throw errors.invalidPayload();
      }
      if (distinctRoleIds.has(normalizedRoleIdKey)) {
        throw errors.invalidPayload();
      }
      distinctRoleIds.add(normalizedRoleIdKey);

      let normalizedRoleStatus = 'active';
      if (hasOwnProperty(role, 'status')) {
        if (typeof role.status !== 'string') {
          throw errors.invalidPayload();
        }
        normalizedRoleStatus = role.status.trim().toLowerCase();
        if (!normalizedRoleStatus) {
          throw errors.invalidPayload();
        }
      }
      if (!VALID_PLATFORM_ROLE_FACT_STATUS.has(normalizedRoleStatus)) {
        throw errors.invalidPayload();
      }
      const resolvedRoleStatus = normalizedRoleStatus === 'enabled'
        ? 'active'
        : normalizedRoleStatus;
      if (enforceRoleCatalogValidation && resolvedRoleStatus !== 'active') {
        throw errors.invalidPayload();
      }

      if (!enforceRoleCatalogValidation) {
        const rolePermissionSource = hasPermissionField ? role.permission : {};
        assertOptionalBooleanRolePermission(
          rolePermissionSource?.canViewUserManagement ?? rolePermissionSource?.can_view_user_management,
          errors.invalidPayload
        );
        assertOptionalBooleanRolePermission(
          rolePermissionSource?.canOperateUserManagement ?? rolePermissionSource?.can_operate_user_management,
          errors.invalidPayload
        );
        assertOptionalBooleanRolePermission(
          rolePermissionSource?.canViewTenantManagement ?? rolePermissionSource?.can_view_tenant_management,
          errors.invalidPayload
        );
        assertOptionalBooleanRolePermission(
          rolePermissionSource?.canOperateTenantManagement ?? rolePermissionSource?.can_operate_tenant_management,
          errors.invalidPayload
        );
        normalizedRoleFacts.push({
          roleId: normalizedRoleIdKey,
          status: resolvedRoleStatus,
          permission: {
            canViewUserManagement: Boolean(
              rolePermissionSource?.canViewUserManagement
              ?? rolePermissionSource?.can_view_user_management
            ),
            canOperateUserManagement: Boolean(
              rolePermissionSource?.canOperateUserManagement
              ?? rolePermissionSource?.can_operate_user_management
            ),
            canViewTenantManagement: Boolean(
              rolePermissionSource?.canViewTenantManagement
              ?? rolePermissionSource?.can_view_tenant_management
            ),
            canOperateTenantManagement: Boolean(
              rolePermissionSource?.canOperateTenantManagement
              ?? rolePermissionSource?.can_operate_tenant_management
            )
          }
        });
        continue;
      }

      normalizedRoleFacts.push({
        roleId: normalizedRoleIdKey,
        status: resolvedRoleStatus
      });
    }

    if (!enforceRoleCatalogValidation) {
      return normalizedRoleFacts;
    }

    const { requestedRoleIds } =
      await loadValidatedPlatformRoleCatalogEntriesForRoleFacts({
        roles: normalizedRoleFacts
      });
    const grantsByRoleIdKey = await loadPlatformRolePermissionGrantsByRoleIds({
      roleIds: requestedRoleIds
    });

    return normalizedRoleFacts.map((roleFact) => {
      const roleIdKey = normalizePlatformRoleIdKey(roleFact.roleId);
      const permissionCodes = grantsByRoleIdKey.get(roleIdKey) || [];
      return {
        roleId: roleFact.roleId,
        status: 'active',
        permission: toPlatformPermissionSnapshotFromCodes(permissionCodes)
      };
    });
  };

  const replacePlatformRolesAndSyncSnapshot = async ({
    requestId,
    accessToken = null,
    userId,
    roles,
    authorizationContext = null,
    traceparent = null,
    enforceRoleCatalogValidation = false
  }) => {
    if (typeof authStore.replacePlatformRolesAndSyncSnapshot !== 'function') {
      throw new Error('authStore.replacePlatformRolesAndSyncSnapshot is required');
    }

    const normalizedAccessToken = typeof accessToken === 'string'
      ? accessToken.trim()
      : '';
    if (normalizedAccessToken.length === 0) {
      throw errors.invalidAccess();
    }
    const authorizedRoute = await authorizeRoute({
      requestId,
      accessToken: normalizedAccessToken,
      permissionCode: PLATFORM_ROLE_FACTS_REPLACE_PERMISSION_CODE,
      scope: 'platform',
      authorizationContext
    });
    const operatorUserId = String(
      authorizedRoute?.user_id || authorizedRoute?.user?.id || ''
    ).trim() || null;
    const operatorSessionId = String(
      authorizedRoute?.session_id || authorizedRoute?.session?.sessionId || ''
    ).trim() || null;
    const normalizedTraceparent = normalizeAuditStringOrNull(traceparent, 128);

    const normalizedUserId = normalizeRequiredStringField(
      userId,
      errors.invalidPayload
    );
    if (!Array.isArray(roles)) {
      throw errors.invalidPayload();
    }
    if (enforceRoleCatalogValidation && roles.length === 0) {
      throw errors.invalidPayload();
    }
    if (roles.length > MAX_PLATFORM_ROLE_FACTS_PER_USER) {
      throw errors.invalidPayload();
    }
    const rolesForPersistence = await normalizePlatformRoleFactsForReplace({
      roles,
      enforceRoleCatalogValidation
    });

    const hasUserLookup = typeof authStore.findUserById === 'function';
    const previousUser = hasUserLookup
      ? await authStore.findUserById(normalizedUserId)
      : null;
    if (hasUserLookup && !previousUser) {
      throw errors.invalidPayload();
    }

    let result;
    try {
      result = await authStore.replacePlatformRolesAndSyncSnapshot({
        userId: normalizedUserId,
        roles: rolesForPersistence
      });
    } catch (error) {
      if (
        error instanceof Error
        && String(error.message || '').includes('invalid platform role status')
      ) {
        throw errors.invalidPayload();
      }
      if (isDuplicateRoleFactEntryError(error) || isDataTooLongRoleFactError(error)) {
        throw errors.invalidPayload();
      }
      throw error;
    }

    const syncReason = String(result?.reason || 'unknown').trim().toLowerCase();
    if (syncReason === 'invalid-user-id') {
      throw errors.invalidPayload();
    }
    if (syncReason === 'db-deadlock' || syncReason === 'concurrent-role-facts-update') {
      throw errors.platformSnapshotDegraded({
        reason: syncReason
      });
    }
    if (syncReason !== 'ok') {
      throw errors.platformSnapshotDegraded({
        reason: syncReason || 'unknown'
      });
    }

    const nextUser = hasUserLookup
      ? await authStore.findUserById(normalizedUserId)
      : null;
    const sessionVersionChanged = Boolean(
      previousUser
      && nextUser
      && Number(nextUser.sessionVersion) !== Number(previousUser.sessionVersion)
    );

    if (sessionVersionChanged || !hasUserLookup) {
      invalidateSessionCacheByUserId(normalizedUserId);
    }

    addAuditEvent({
      type: 'auth.platform_role_facts.updated',
      requestId,
      userId: normalizedUserId,
      sessionId: operatorSessionId || 'unknown',
      detail: 'platform role facts replaced and snapshot synced',
      metadata: {
        actor_user_id: operatorUserId,
        actor_session_id: operatorSessionId,
        target_user_id: normalizedUserId,
        session_version_changed: sessionVersionChanged,
        sync_reason: syncReason || 'unknown'
      }
    });

    const toPlatformRoleFactsAuditState = (userRecord = null) => {
      const roleFacts = Array.isArray(userRecord?.platformRoles)
        ? userRecord.platformRoles
        : Array.isArray(userRecord?.platform_roles)
          ? userRecord.platform_roles
          : [];
      return roleFacts
        .map((roleFact) => ({
          role_id: normalizeAuditStringOrNull(
            resolveRawCamelSnakeField(roleFact, 'roleId', 'role_id'),
            64
          ),
          status: normalizeAuditStringOrNull(
            resolveRawCamelSnakeField(roleFact, 'status', 'status'),
            16
          ) || 'active'
        }))
        .filter((roleFact) => roleFact.role_id)
        .sort((left, right) => left.role_id.localeCompare(right.role_id));
    };

    const previousSessionVersion = Number(
      resolveRawCamelSnakeField(previousUser, 'sessionVersion', 'session_version') || 0
    );
    const nextSessionVersion = Number(
      resolveRawCamelSnakeField(nextUser, 'sessionVersion', 'session_version')
        || previousSessionVersion
    );

    await recordPersistentAuditEvent({
      domain: 'platform',
      tenantId: null,
      requestId: normalizeAuditStringOrNull(requestId, 128) || 'request_id_unset',
      traceparent: normalizedTraceparent,
      eventType: 'auth.platform_role_facts.updated',
      actorUserId: normalizeAuditStringOrNull(operatorUserId, 64),
      actorSessionId: normalizeAuditStringOrNull(operatorSessionId, 128),
      targetType: 'user',
      targetId: normalizedUserId,
      result: 'success',
      beforeState: {
        session_version: previousSessionVersion,
        role_facts: toPlatformRoleFactsAuditState(previousUser)
      },
      afterState: {
        session_version: nextSessionVersion,
        role_facts: toPlatformRoleFactsAuditState(nextUser)
      },
      metadata: {
        session_version_changed: sessionVersionChanged,
        sync_reason: syncReason || 'unknown'
      }
    });

    return result;
  };

  return {
    replacePlatformRolesAndSyncSnapshot
  };
};

module.exports = {
  createPlatformRoleFactsGovernanceCapabilities
};
