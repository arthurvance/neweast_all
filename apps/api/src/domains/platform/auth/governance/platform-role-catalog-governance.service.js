'use strict';

const createPlatformRoleCatalogGovernanceCapabilities = ({
  authStore,
  errors,
  isPlainObject,
  assertStoreMethod,
  normalizeRequiredStringField,
  normalizePlatformRoleCatalogStatus,
  normalizePlatformRoleCatalogScope,
  normalizePlatformRoleCatalogTenantIdForScope,
  normalizeAuditStringOrNull,
  resolveRawCamelSnakeField,
  recordPersistentAuditEvent,
  resyncRoleStatusAffectedSnapshots,
  VALID_PLATFORM_ROLE_CATALOG_STATUS,
  VALID_PLATFORM_ROLE_CATALOG_SCOPE,
  PLATFORM_ROLE_CATALOG_SCOPE
} = {}) => {
  const createPlatformRoleCatalogEntry = async ({
    requestId = 'request_id_unset',
    traceparent = null,
    roleId,
    code,
    name,
    status = 'active',
    scope = PLATFORM_ROLE_CATALOG_SCOPE,
    tenantId = null,
    isSystem = false,
    operatorUserId = null,
    operatorSessionId = null
  }) => {
    const normalizedRoleId = normalizeRequiredStringField(
      roleId,
      errors.invalidPayload
    ).toLowerCase();
    const normalizedCode = normalizeRequiredStringField(
      code,
      errors.invalidPayload
    );
    const normalizedName = normalizeRequiredStringField(
      name,
      errors.invalidPayload
    );
    const normalizedStatus = normalizePlatformRoleCatalogStatus(status);
    const normalizedScope = normalizePlatformRoleCatalogScope(scope);
    if (
      !VALID_PLATFORM_ROLE_CATALOG_STATUS.has(normalizedStatus)
      || !VALID_PLATFORM_ROLE_CATALOG_SCOPE.has(normalizedScope)
    ) {
      throw errors.invalidPayload();
    }
    const normalizedTenantId = normalizePlatformRoleCatalogTenantIdForScope({
      scope: normalizedScope,
      tenantId
    });
    const normalizedRequestId =
      normalizeAuditStringOrNull(requestId, 128) || 'request_id_unset';
    const normalizedTraceparent = normalizeAuditStringOrNull(traceparent, 128);
    const normalizedOperatorUserId = normalizeAuditStringOrNull(operatorUserId, 64);
    const normalizedOperatorSessionId = normalizeAuditStringOrNull(operatorSessionId, 128);

    assertStoreMethod(authStore, 'createPlatformRoleCatalogEntry', 'authStore');
    let createdRole = null;
    try {
      createdRole = await authStore.createPlatformRoleCatalogEntry({
        roleId: normalizedRoleId,
        code: normalizedCode,
        name: normalizedName,
        status: normalizedStatus === 'enabled' ? 'active' : normalizedStatus,
        scope: normalizedScope,
        tenantId: normalizedTenantId,
        isSystem: Boolean(isSystem),
        operatorUserId: normalizedOperatorUserId,
        operatorSessionId: normalizedOperatorSessionId,
        auditContext: {
          requestId: normalizedRequestId,
          traceparent: normalizedTraceparent,
          actorUserId: normalizedOperatorUserId,
          actorSessionId: normalizedOperatorSessionId
        }
      });
    } catch (error) {
      if (String(error?.code || '').trim() === 'ERR_AUDIT_WRITE_FAILED') {
        throw errors.auditDependencyUnavailable({
          reason: 'audit-write-failed'
        });
      }
      throw error;
    }
    if (!isPlainObject(createdRole)) {
      throw errors.auditDependencyUnavailable({
        reason: 'platform-role-create-result-invalid'
      });
    }
    const resolvedCreatedRoleId = normalizeAuditStringOrNull(
      resolveRawCamelSnakeField(createdRole, 'roleId', 'role_id'),
      64
    );
    if (!resolvedCreatedRoleId) {
      throw errors.auditDependencyUnavailable({
        reason: 'platform-role-create-result-invalid'
      });
    }
    if (resolvedCreatedRoleId !== normalizedRoleId) {
      throw errors.auditDependencyUnavailable({
        reason: 'platform-role-create-result-target-mismatch'
      });
    }
    const storeAuditRecorded = (
      createdRole?.auditRecorded === true
      || createdRole?.audit_recorded === true
    );
    if (!storeAuditRecorded) {
      await recordPersistentAuditEvent({
        domain: normalizedScope === 'tenant' ? 'tenant' : 'platform',
        tenantId: normalizedScope === 'tenant' ? normalizedTenantId : null,
        requestId: normalizedRequestId,
        traceparent: normalizedTraceparent,
        eventType: 'auth.role.catalog.created',
        actorUserId: normalizedOperatorUserId,
        actorSessionId: normalizedOperatorSessionId,
        targetType: 'role',
        targetId: normalizedRoleId,
        result: 'success',
        beforeState: null,
        afterState: {
          role_id: normalizedRoleId,
          code: normalizeAuditStringOrNull(
            resolveRawCamelSnakeField(createdRole, 'code', 'code'),
            64
          ) || normalizedCode,
          name: normalizeAuditStringOrNull(
            resolveRawCamelSnakeField(createdRole, 'name', 'name'),
            128
          ) || normalizedName,
          status: normalizePlatformRoleCatalogStatus(
            resolveRawCamelSnakeField(createdRole, 'status', 'status')
              || (normalizedStatus === 'enabled' ? 'active' : normalizedStatus)
          ),
          scope: normalizedScope,
          tenant_id: normalizedScope === 'tenant' ? normalizedTenantId : null,
          is_system: Boolean(
            resolveRawCamelSnakeField(createdRole, 'isSystem', 'is_system')
              ?? Boolean(isSystem)
          )
        },
        metadata: {
          scope: normalizedScope
        }
      });
    }
    const createdRoleResponse = {
      ...(createdRole || {})
    };
    delete createdRoleResponse.auditRecorded;
    delete createdRoleResponse.audit_recorded;
    return createdRoleResponse;
  };

  const updatePlatformRoleCatalogEntry = async ({
    requestId = 'request_id_unset',
    traceparent = null,
    roleId,
    scope = PLATFORM_ROLE_CATALOG_SCOPE,
    tenantId = null,
    code = undefined,
    name = undefined,
    status = undefined,
    operatorUserId = null,
    operatorSessionId = null
  }) => {
    const normalizedRoleId = normalizeRequiredStringField(
      roleId,
      errors.invalidPayload
    ).toLowerCase();
    const normalizedScope = normalizePlatformRoleCatalogScope(scope);
    if (!VALID_PLATFORM_ROLE_CATALOG_SCOPE.has(normalizedScope)) {
      throw errors.invalidPayload();
    }
    const normalizedTenantId = normalizePlatformRoleCatalogTenantIdForScope({
      scope: normalizedScope,
      tenantId
    });
    const normalizedRequestId =
      normalizeAuditStringOrNull(requestId, 128) || 'request_id_unset';
    const normalizedTraceparent = normalizeAuditStringOrNull(traceparent, 128);
    const normalizedOperatorUserId = normalizeAuditStringOrNull(operatorUserId, 64);
    const normalizedOperatorSessionId = normalizeAuditStringOrNull(operatorSessionId, 128);
    const updates = {};
    if (code !== undefined) {
      updates.code = normalizeRequiredStringField(code, errors.invalidPayload);
    }
    if (name !== undefined) {
      updates.name = normalizeRequiredStringField(name, errors.invalidPayload);
    }
    if (status !== undefined) {
      const normalizedStatus = normalizePlatformRoleCatalogStatus(status);
      if (!VALID_PLATFORM_ROLE_CATALOG_STATUS.has(normalizedStatus)) {
        throw errors.invalidPayload();
      }
      updates.status = normalizedStatus === 'enabled'
        ? 'active'
        : normalizedStatus;
    }
    let previousRole = null;
    if (typeof authStore.findPlatformRoleCatalogEntryByRoleId === 'function') {
      try {
        previousRole = await authStore.findPlatformRoleCatalogEntryByRoleId({
          roleId: normalizedRoleId,
          scope: normalizedScope,
          tenantId: normalizedTenantId
        });
      } catch (_error) {
      }
    }
    assertStoreMethod(authStore, 'updatePlatformRoleCatalogEntry', 'authStore');
    let updatedRole = null;
    try {
      updatedRole = await authStore.updatePlatformRoleCatalogEntry({
        roleId: normalizedRoleId,
        scope: normalizedScope,
        tenantId: normalizedTenantId,
        ...updates,
        operatorUserId: normalizedOperatorUserId,
        operatorSessionId: normalizedOperatorSessionId,
        auditContext: {
          requestId: normalizedRequestId,
          traceparent: normalizedTraceparent,
          actorUserId: normalizedOperatorUserId,
          actorSessionId: normalizedOperatorSessionId
        }
      });
    } catch (error) {
      if (String(error?.code || '').trim() === 'ERR_AUDIT_WRITE_FAILED') {
        throw errors.auditDependencyUnavailable({
          reason: 'audit-write-failed'
        });
      }
      throw error;
    }
    if (!updatedRole) {
      return updatedRole;
    }
    if (!isPlainObject(updatedRole)) {
      throw errors.auditDependencyUnavailable({
        reason: 'platform-role-update-result-invalid'
      });
    }
    const resolvedUpdatedRoleId = normalizeAuditStringOrNull(
      resolveRawCamelSnakeField(updatedRole, 'roleId', 'role_id'),
      64
    );
    if (!resolvedUpdatedRoleId) {
      throw errors.auditDependencyUnavailable({
        reason: 'platform-role-update-result-invalid'
      });
    }
    if (resolvedUpdatedRoleId !== normalizedRoleId) {
      throw errors.auditDependencyUnavailable({
        reason: 'platform-role-update-result-target-mismatch'
      });
    }
    let statusSyncResult = null;
    if (Object.prototype.hasOwnProperty.call(updates, 'status')) {
      const previousRoleStatusRaw = resolveRawCamelSnakeField(
        previousRole,
        'status',
        'status'
      );
      const hasKnownPreviousRoleStatus = normalizePlatformRoleCatalogStatus(
        previousRoleStatusRaw
      ).length > 0;
      const previousRoleStatus = normalizePlatformRoleCatalogStatus(previousRoleStatusRaw) || 'disabled';
      const currentRoleStatus = normalizePlatformRoleCatalogStatus(
        resolveRawCamelSnakeField(updatedRole, 'status', 'status')
      ) || 'disabled';
      if (!hasKnownPreviousRoleStatus || previousRoleStatus !== currentRoleStatus) {
        statusSyncResult = await resyncRoleStatusAffectedSnapshots({
          requestId: normalizedRequestId,
          traceparent: normalizedTraceparent,
          roleId: normalizedRoleId,
          scope: normalizedScope,
          tenantId: normalizedTenantId,
          previousStatus: previousRoleStatusRaw,
          currentStatus: resolveRawCamelSnakeField(updatedRole, 'status', 'status'),
          operatorUserId: normalizedOperatorUserId,
          operatorSessionId: normalizedOperatorSessionId
        });
      }
    }
    const storeAuditRecorded = (
      updatedRole?.auditRecorded === true
      || updatedRole?.audit_recorded === true
    );
    if (!storeAuditRecorded) {
      await recordPersistentAuditEvent({
        domain: normalizedScope === 'tenant' ? 'tenant' : 'platform',
        tenantId: normalizedScope === 'tenant' ? normalizedTenantId : null,
        requestId: normalizedRequestId,
        traceparent: normalizedTraceparent,
        eventType: 'auth.role.catalog.updated',
        actorUserId: normalizedOperatorUserId,
        actorSessionId: normalizedOperatorSessionId,
        targetType: 'role',
        targetId: normalizedRoleId,
        result: 'success',
        beforeState: previousRole
          ? {
            code: normalizeAuditStringOrNull(
              resolveRawCamelSnakeField(previousRole, 'code', 'code'),
              64
            ),
            name: normalizeAuditStringOrNull(
              resolveRawCamelSnakeField(previousRole, 'name', 'name'),
              128
            ),
            status: normalizePlatformRoleCatalogStatus(
              resolveRawCamelSnakeField(previousRole, 'status', 'status') || 'active'
            )
          }
          : null,
        afterState: {
          code: normalizeAuditStringOrNull(
            resolveRawCamelSnakeField(updatedRole, 'code', 'code'),
            64
          ),
          name: normalizeAuditStringOrNull(
            resolveRawCamelSnakeField(updatedRole, 'name', 'name'),
            128
          ),
          status: normalizePlatformRoleCatalogStatus(
            resolveRawCamelSnakeField(updatedRole, 'status', 'status') || 'active'
          )
        },
        metadata: {
          scope: normalizedScope,
          changed_fields: Object.keys(updates),
          affected_user_count: Number(statusSyncResult?.affectedUserCount || 0),
          affected_membership_count: Number(statusSyncResult?.affectedMembershipCount || 0)
        }
      });
    }
    const updatedRoleResponse = {
      ...(updatedRole || {})
    };
    if (statusSyncResult) {
      updatedRoleResponse.affected_user_count = Number(
        statusSyncResult.affectedUserCount || 0
      );
      updatedRoleResponse.affected_membership_count = Number(
        statusSyncResult.affectedMembershipCount || 0
      );
    }
    delete updatedRoleResponse.auditRecorded;
    delete updatedRoleResponse.audit_recorded;
    return updatedRoleResponse;
  };

  const deletePlatformRoleCatalogEntry = async ({
    requestId = 'request_id_unset',
    traceparent = null,
    roleId,
    scope = PLATFORM_ROLE_CATALOG_SCOPE,
    tenantId = null,
    operatorUserId = null,
    operatorSessionId = null
  }) => {
    const normalizedRoleId = normalizeRequiredStringField(
      roleId,
      errors.invalidPayload
    ).toLowerCase();
    const normalizedScope = normalizePlatformRoleCatalogScope(scope);
    if (!VALID_PLATFORM_ROLE_CATALOG_SCOPE.has(normalizedScope)) {
      throw errors.invalidPayload();
    }
    const normalizedTenantId = normalizePlatformRoleCatalogTenantIdForScope({
      scope: normalizedScope,
      tenantId
    });
    const normalizedRequestId =
      normalizeAuditStringOrNull(requestId, 128) || 'request_id_unset';
    const normalizedTraceparent = normalizeAuditStringOrNull(traceparent, 128);
    const normalizedOperatorUserId = normalizeAuditStringOrNull(operatorUserId, 64);
    const normalizedOperatorSessionId = normalizeAuditStringOrNull(operatorSessionId, 128);
    let previousRole = null;
    if (typeof authStore.findPlatformRoleCatalogEntryByRoleId === 'function') {
      try {
        previousRole = await authStore.findPlatformRoleCatalogEntryByRoleId({
          roleId: normalizedRoleId,
          scope: normalizedScope,
          tenantId: normalizedTenantId
        });
      } catch (_error) {
      }
    }
    assertStoreMethod(authStore, 'deletePlatformRoleCatalogEntry', 'authStore');
    let deletedRole = null;
    try {
      deletedRole = await authStore.deletePlatformRoleCatalogEntry({
        roleId: normalizedRoleId,
        scope: normalizedScope,
        tenantId: normalizedTenantId,
        operatorUserId: normalizedOperatorUserId,
        operatorSessionId: normalizedOperatorSessionId,
        auditContext: {
          requestId: normalizedRequestId,
          traceparent: normalizedTraceparent,
          actorUserId: normalizedOperatorUserId,
          actorSessionId: normalizedOperatorSessionId
        }
      });
    } catch (error) {
      if (String(error?.code || '').trim() === 'ERR_AUDIT_WRITE_FAILED') {
        throw errors.auditDependencyUnavailable({
          reason: 'audit-write-failed'
        });
      }
      throw error;
    }
    if (!deletedRole) {
      return deletedRole;
    }
    if (!isPlainObject(deletedRole)) {
      throw errors.auditDependencyUnavailable({
        reason: 'platform-role-delete-result-invalid'
      });
    }
    const resolvedDeletedRoleId = normalizeAuditStringOrNull(
      resolveRawCamelSnakeField(deletedRole, 'roleId', 'role_id'),
      64
    );
    if (!resolvedDeletedRoleId) {
      throw errors.auditDependencyUnavailable({
        reason: 'platform-role-delete-result-invalid'
      });
    }
    if (resolvedDeletedRoleId !== normalizedRoleId) {
      throw errors.auditDependencyUnavailable({
        reason: 'platform-role-delete-result-target-mismatch'
      });
    }
    const statusSyncResult = await resyncRoleStatusAffectedSnapshots({
      requestId: normalizedRequestId,
      traceparent: normalizedTraceparent,
      roleId: normalizedRoleId,
      scope: normalizedScope,
      tenantId: normalizedTenantId,
      previousStatus: resolveRawCamelSnakeField(previousRole, 'status', 'status'),
      currentStatus: resolveRawCamelSnakeField(deletedRole, 'status', 'status'),
      operatorUserId: normalizedOperatorUserId,
      operatorSessionId: normalizedOperatorSessionId
    });
    const storeAuditRecorded = (
      deletedRole?.auditRecorded === true
      || deletedRole?.audit_recorded === true
    );
    if (!storeAuditRecorded) {
      const deletedRoleBeforeAuditSource = (
        previousRole && typeof previousRole === 'object'
          ? previousRole
          : deletedRole
      );
      await recordPersistentAuditEvent({
        domain: normalizedScope === 'tenant' ? 'tenant' : 'platform',
        tenantId: normalizedScope === 'tenant' ? normalizedTenantId : null,
        requestId: normalizedRequestId,
        traceparent: normalizedTraceparent,
        eventType: 'auth.role.catalog.deleted',
        actorUserId: normalizedOperatorUserId,
        actorSessionId: normalizedOperatorSessionId,
        targetType: 'role',
        targetId: normalizedRoleId,
        result: 'success',
        beforeState: {
          code: normalizeAuditStringOrNull(
            resolveRawCamelSnakeField(deletedRoleBeforeAuditSource, 'code', 'code'),
            64
          ),
          name: normalizeAuditStringOrNull(
            resolveRawCamelSnakeField(deletedRoleBeforeAuditSource, 'name', 'name'),
            128
          ),
          status: normalizePlatformRoleCatalogStatus(
            resolveRawCamelSnakeField(deletedRoleBeforeAuditSource, 'status', 'status')
            || 'disabled'
          )
        },
        afterState: {
          status: 'disabled'
        },
        metadata: {
          scope: normalizedScope,
          affected_user_count: Number(statusSyncResult?.affectedUserCount || 0),
          affected_membership_count: Number(statusSyncResult?.affectedMembershipCount || 0)
        }
      });
    }
    const deletedRoleResponse = {
      ...(deletedRole || {})
    };
    deletedRoleResponse.affected_user_count = Number(
      statusSyncResult?.affectedUserCount || 0
    );
    deletedRoleResponse.affected_membership_count = Number(
      statusSyncResult?.affectedMembershipCount || 0
    );
    delete deletedRoleResponse.auditRecorded;
    delete deletedRoleResponse.audit_recorded;
    return deletedRoleResponse;
  };

  return {
    createPlatformRoleCatalogEntry,
    updatePlatformRoleCatalogEntry,
    deletePlatformRoleCatalogEntry
  };
};

module.exports = {
  createPlatformRoleCatalogGovernanceCapabilities
};
