'use strict';

const createTenantRolePermissionGrantCapabilities = ({
  authStore,
  errors,
  AuthProblemError,
  hasOwnProperty,
  normalizeStrictAddressableTenantRoleIdFromInput,
  loadValidatedTenantRoleCatalogEntries,
  loadTenantRolePermissionGrantsByRoleIds,
  normalizePlatformRoleIdKey,
  listTenantPermissionCatalogItems,
  normalizeTenantPermissionCode,
  toTenantPermissionCodeKey,
  isTenantPermissionCode,
  SUPPORTED_TENANT_PERMISSION_CODE_SET,
  CONTROL_CHAR_PATTERN,
  MAX_ROLE_PERMISSION_CODES_PER_REQUEST,
  MAX_ROLE_PERMISSION_ATOMIC_AFFECTED_USERS,
  normalizeTenantId,
  normalizeAuditStringOrNull,
  normalizeStrictRequiredStringField,
  resolveRawCamelSnakeField,
  normalizeStrictDistinctUserIdsFromDependency,
  normalizeStrictNonNegativeIntegerFromDependency,
  invalidateSessionCacheByUserId,
  addAuditEvent,
  recordPersistentAuditEvent
} = {}) => {
  const TENANT_CUSTOMER_SCOPE_OPERATE_TO_VIEW_PERMISSION_CODE_MAP = new Map([
    ['tenant.customer_scope_my.operate', 'tenant.customer_scope_my.view'],
    ['tenant.customer_scope_assist.operate', 'tenant.customer_scope_assist.view'],
    ['tenant.customer_scope_all.operate', 'tenant.customer_scope_all.view']
  ]);

  const listTenantPermissionCatalogEntries = () =>
    listTenantPermissionCatalogItems();
  const listAssignableTenantPermissionCodeSet = () =>
    new Set(
      listTenantPermissionCatalogEntries()
        .map((item) => toTenantPermissionCodeKey(item?.code))
        .filter((permissionCode) => permissionCode.length > 0)
    );

  const listTenantPermissionCatalog = () =>
    listTenantPermissionCatalogEntries()
      .map((item) => String(item?.code || '').trim().toLowerCase())
      .filter((code) => code.length > 0)
      .sort((left, right) => left.localeCompare(right));

  const listTenantRolePermissionGrants = async ({
    tenantId,
    roleId
  }) => {
    const normalizedRoleId =
      normalizeStrictAddressableTenantRoleIdFromInput(roleId);
    const {
      requestedRoleIds
    } = await loadValidatedTenantRoleCatalogEntries({
      tenantId,
      roleIds: [normalizedRoleId],
      allowDisabledRoles: true
    });
    const grantsByRoleIdKey = await loadTenantRolePermissionGrantsByRoleIds({
      roleIds: requestedRoleIds
    });
    const grants = grantsByRoleIdKey.get(normalizePlatformRoleIdKey(normalizedRoleId)) || [];
    return {
      role_id: normalizedRoleId,
      permission_codes: grants,
      available_permission_codes: listTenantPermissionCatalog(),
      available_permissions: listTenantPermissionCatalogEntries()
    };
  };

  const replaceTenantRolePermissionGrants = async ({
    requestId,
    traceparent = null,
    tenantId,
    roleId,
    permissionCodes = [],
    operatorUserId = null,
    operatorSessionId = null
  }) => {
    const normalizedRoleId =
      normalizeStrictAddressableTenantRoleIdFromInput(roleId);
    if (!Array.isArray(permissionCodes)) {
      throw errors.invalidPayload();
    }
    if (permissionCodes.length > MAX_ROLE_PERMISSION_CODES_PER_REQUEST) {
      throw errors.invalidPayload();
    }
    const assignablePermissionCodeSet = listAssignableTenantPermissionCodeSet();
    const dedupedPermissionCodes = new Map();
    for (const permissionCode of permissionCodes) {
      const normalizedPermissionCode = normalizeTenantPermissionCode(permissionCode);
      if (!normalizedPermissionCode) {
        throw errors.invalidPayload();
      }
      if (CONTROL_CHAR_PATTERN.test(normalizedPermissionCode)) {
        throw errors.invalidPayload();
      }
      const permissionCodeKey = toTenantPermissionCodeKey(normalizedPermissionCode);
      if (
        !isTenantPermissionCode(normalizedPermissionCode)
        || !SUPPORTED_TENANT_PERMISSION_CODE_SET.has(permissionCodeKey)
        || !assignablePermissionCodeSet.has(permissionCodeKey)
      ) {
        throw errors.invalidPayload();
      }
      dedupedPermissionCodes.set(permissionCodeKey, permissionCodeKey);
    }
    const normalizedPermissionCodes = [...dedupedPermissionCodes.values()];
    const normalizedPermissionCodeSet = new Set(normalizedPermissionCodes);
    for (const [operatePermissionCode, viewPermissionCode] of
      TENANT_CUSTOMER_SCOPE_OPERATE_TO_VIEW_PERMISSION_CODE_MAP.entries()) {
      if (
        normalizedPermissionCodeSet.has(operatePermissionCode)
        && !normalizedPermissionCodeSet.has(viewPermissionCode)
      ) {
        throw errors.invalidPayload();
      }
    }

    await loadValidatedTenantRoleCatalogEntries({
      tenantId,
      roleIds: [normalizedRoleId],
      allowDisabledRoles: true
    });
    const normalizedTenantId = normalizeTenantId(tenantId);
    let previousPermissionCodesForAudit = null;
    try {
      const previousGrantsByRoleIdKey = await loadTenantRolePermissionGrantsByRoleIds({
        roleIds: [normalizedRoleId]
      });
      previousPermissionCodesForAudit =
        previousGrantsByRoleIdKey.get(normalizePlatformRoleIdKey(normalizedRoleId)) || [];
    } catch (_error) {
      previousPermissionCodesForAudit = null;
    }

    if (typeof authStore.replaceTenantRolePermissionGrantsAndSyncSnapshots !== 'function') {
      throw errors.tenantUserDependencyUnavailable({
        reason: 'tenant-role-permission-grants-unsupported'
      });
    }

    let atomicWriteResult;
    try {
      atomicWriteResult = await authStore.replaceTenantRolePermissionGrantsAndSyncSnapshots({
        tenantId,
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
        maxAffectedMemberships: MAX_ROLE_PERMISSION_ATOMIC_AFFECTED_USERS
      });
    } catch (error) {
      if (error instanceof AuthProblemError) {
        throw error;
      }
      if (String(error?.code || '').trim()
        === 'ERR_TENANT_ROLE_PERMISSION_AFFECTED_MEMBERSHIPS_OVER_LIMIT') {
        throw errors.tenantUserDependencyUnavailable({
          reason: 'tenant-role-permission-affected-memberships-over-limit'
        });
      }
      if (String(error?.code || '').trim() === 'ERR_TENANT_ROLE_PERMISSION_SYNC_FAILED') {
        throw errors.tenantUserDependencyUnavailable({
          reason: String(error?.syncReason || 'tenant-role-permission-resync-failed')
        });
      }
      if (String(error?.code || '').trim() === 'ERR_AUDIT_WRITE_FAILED') {
        throw errors.tenantUserDependencyUnavailable({
          reason: 'audit-write-failed'
        });
      }
      const normalizedErrorMessage = String(error?.message || '')
        .trim()
        .toLowerCase();
      throw errors.tenantUserDependencyUnavailable({
        reason: normalizedErrorMessage.includes('deadlock')
          ? 'db-deadlock'
          : 'tenant-role-permission-atomic-write-failed'
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
    const resolvedRoleId = normalizeStrictRequiredStringField(rawResolvedRoleId)
      .toLowerCase();
    if (!resolvedRoleId || resolvedRoleId !== normalizedRoleId) {
      throw errors.tenantUserDependencyUnavailable({
        reason: 'tenant-role-permission-grants-update-role-mismatch'
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
      const normalizedPermissionCode =
        normalizeStrictRequiredStringField(permissionCode);
      const permissionCodeKey = toTenantPermissionCodeKey(normalizedPermissionCode);
      if (
        !normalizedPermissionCode
        || CONTROL_CHAR_PATTERN.test(normalizedPermissionCode)
        || seenSavedPermissionCodeKeys.has(permissionCodeKey)
        || !isTenantPermissionCode(normalizedPermissionCode)
        || !SUPPORTED_TENANT_PERMISSION_CODE_SET.has(permissionCodeKey)
        || !assignablePermissionCodeSet.has(permissionCodeKey)
      ) {
        throw errors.tenantUserDependencyUnavailable({
          reason: 'tenant-role-permission-grants-update-invalid'
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
      throw errors.tenantUserDependencyUnavailable({
        reason: 'tenant-role-permission-grants-update-mismatch'
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
      throw errors.tenantUserDependencyUnavailable({
        reason: 'tenant-role-permission-grants-update-affected-user-metadata-missing'
      });
    }
    const affectedUserIds = normalizeStrictDistinctUserIdsFromDependency({
      userIds: resolveRawCamelSnakeField(
        atomicWriteResult,
        'affectedUserIds',
        'affected_user_ids'
      )
    });
    const affectedUserCount = normalizeStrictNonNegativeIntegerFromDependency({
      value: resolveRawCamelSnakeField(
        atomicWriteResult,
        'affectedUserCount',
        'affected_user_count'
      ),
      dependencyReason: 'tenant-role-permission-grants-update-affected-user-count-invalid'
    });
    if (
      hasExplicitAffectedUserCount
      && affectedUserCount !== affectedUserIds.length
    ) {
      throw errors.tenantUserDependencyUnavailable({
        reason: 'tenant-role-permission-grants-update-affected-user-count-invalid'
      });
    }
    for (const affectedUserId of affectedUserIds) {
      invalidateSessionCacheByUserId(affectedUserId);
    }

    addAuditEvent({
      type: 'auth.tenant_role_permission_grants.updated',
      requestId,
      userId: operatorUserId || 'unknown',
      sessionId: operatorSessionId || 'unknown',
      detail: 'tenant role permission grants replaced and affected snapshots resynced',
      metadata: {
        tenant_id: normalizedTenantId,
        role_id: normalizedRoleId,
        permission_codes: normalizedSavedPermissionCodeKeys,
        affected_user_count: affectedUserCount
      }
    });
    const storeAuditRecorded = (
      atomicWriteResult?.auditRecorded === true
      || atomicWriteResult?.audit_recorded === true
    );
    if (!storeAuditRecorded) {
      await recordPersistentAuditEvent({
        domain: 'tenant',
        tenantId: normalizedTenantId,
        requestId: normalizeAuditStringOrNull(requestId, 128) || 'request_id_unset',
        traceparent: normalizeAuditStringOrNull(traceparent, 128),
        eventType: 'auth.tenant_role_permission_grants.updated',
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
          affected_user_count: affectedUserCount
        }
      });
    }

    return {
      role_id: normalizedRoleId,
      permission_codes: normalizedSavedPermissionCodeKeys,
      affected_user_count: affectedUserCount
    };
  };

  return {
    listTenantRolePermissionGrants,
    replaceTenantRolePermissionGrants
  };
};

module.exports = {
  createTenantRolePermissionGrantCapabilities
};
