'use strict';

const createTenantRoleBindingCapabilities = ({
  authStore,
  errors,
  AuthProblemError,
  hasOwnProperty,
  assertStoreMethod,
  normalizeRequiredStringField,
  normalizeStrictRequiredStringField,
  normalizeStrictTenantUsershipIdFromInput,
  normalizeTenantUsershipRecordFromStore,
  normalizeTenantUsershipStatus,
  normalizePlatformRoleCatalogTenantIdForScope,
  normalizeAuditStringOrNull,
  resolveRawCamelSnakeField,
  loadValidatedTenantRoleCatalogEntries,
  normalizeStrictDistinctUserIdsFromDependency,
  normalizeStrictNonNegativeIntegerFromDependency,
  invalidateSessionCacheByUserId,
  addAuditEvent,
  recordPersistentAuditEvent,
  MAX_TENANT_MEMBERSHIP_ROLE_BINDINGS,
  MAX_PLATFORM_ROLE_ID_LENGTH,
  CONTROL_CHAR_PATTERN,
  ROLE_ID_ADDRESSABLE_PATTERN
} = {}) => {
  const normalizeStrictTenantUsershipRoleIds = ({
    roleIds,
    minCount = 0,
    maxCount = MAX_TENANT_MEMBERSHIP_ROLE_BINDINGS,
    dependencyReason = 'tenant-membership-role-bindings-invalid'
  } = {}) => {
    if (!Array.isArray(roleIds)) {
      throw errors.tenantUserDependencyUnavailable({
        reason: dependencyReason
      });
    }
    if (roleIds.length < minCount || roleIds.length > maxCount) {
      throw errors.tenantUserDependencyUnavailable({
        reason: `${dependencyReason}-count-out-of-range`
      });
    }

    const normalizedRoleIds = [];
    const seenRoleIds = new Set();
    for (const roleId of roleIds) {
      const strictRoleId = normalizeStrictRequiredStringField(roleId);
      const normalizedRoleId = strictRoleId.toLowerCase();
      if (
        !strictRoleId
        || strictRoleId !== normalizedRoleId
        || !normalizedRoleId
        || normalizedRoleId.length > MAX_PLATFORM_ROLE_ID_LENGTH
        || CONTROL_CHAR_PATTERN.test(normalizedRoleId)
        || !ROLE_ID_ADDRESSABLE_PATTERN.test(normalizedRoleId)
        || seenRoleIds.has(normalizedRoleId)
      ) {
        throw errors.tenantUserDependencyUnavailable({
          reason: dependencyReason
        });
      }
      seenRoleIds.add(normalizedRoleId);
      normalizedRoleIds.push(normalizedRoleId);
    }
    return normalizedRoleIds.sort((left, right) => left.localeCompare(right));
  };

  const assertTenantUsershipRoleBindingsMatchTenantCatalog = async ({
    tenantId,
    roleIds,
    dependencyReason = 'tenant-membership-role-bindings-invalid'
  }) => {
    if (!Array.isArray(roleIds) || roleIds.length === 0) {
      return;
    }
    try {
      await loadValidatedTenantRoleCatalogEntries({
        tenantId,
        roleIds,
        allowDisabledRoles: true
      });
    } catch (error) {
      if (
        error instanceof AuthProblemError
        && error.errorCode === 'AUTH-404-ROLE-NOT-FOUND'
      ) {
        throw errors.tenantUserDependencyUnavailable({
          reason: dependencyReason
        });
      }
      throw error;
    }
  };

  const listTenantUserRoleBindings = async ({
    tenantId,
    membershipId
  }) => {
    const normalizedTenantId = normalizePlatformRoleCatalogTenantIdForScope({
      scope: 'tenant',
      tenantId,
      allowEmptyForPlatform: false
    });
    const normalizedMembershipId =
      normalizeStrictTenantUsershipIdFromInput(membershipId);
    assertStoreMethod(
      authStore,
      'findTenantUsershipByMembershipIdAndTenantId',
      'authStore'
    );
    assertStoreMethod(authStore, 'listTenantUsershipRoleBindings', 'authStore');

    const membership = await authStore.findTenantUsershipByMembershipIdAndTenantId({
      membershipId: normalizedMembershipId,
      tenantId: normalizedTenantId
    });
    if (!membership) {
      throw errors.tenantUsershipNotFound();
    }
    const normalizedMembership = normalizeTenantUsershipRecordFromStore({
      membership,
      expectedMembershipId: normalizedMembershipId,
      expectedTenantId: normalizedTenantId
    });
    if (!normalizedMembership) {
      throw errors.tenantUserDependencyUnavailable({
        reason: 'tenant-membership-record-invalid'
      });
    }

    let roleIds = await authStore.listTenantUsershipRoleBindings({
      membershipId: normalizedMembershipId,
      tenantId: normalizedTenantId
    });
    roleIds = normalizeStrictTenantUsershipRoleIds({
      roleIds,
      minCount: 0,
      maxCount: MAX_TENANT_MEMBERSHIP_ROLE_BINDINGS,
      dependencyReason: 'tenant-membership-role-bindings-invalid'
    });
    await assertTenantUsershipRoleBindingsMatchTenantCatalog({
      tenantId: normalizedTenantId,
      roleIds,
      dependencyReason: 'tenant-membership-role-bindings-invalid'
    });

    return {
      membership_id: normalizedMembershipId,
      role_ids: roleIds
    };
  };

  const replaceTenantUserRoleBindings = async ({
    requestId,
    traceparent = null,
    tenantId,
    membershipId,
    roleIds = [],
    operatorUserId = null,
    operatorSessionId = null
  }) => {
    const normalizedTenantId = normalizePlatformRoleCatalogTenantIdForScope({
      scope: 'tenant',
      tenantId,
      allowEmptyForPlatform: false
    });
    const normalizedMembershipId =
      normalizeStrictTenantUsershipIdFromInput(membershipId);
    if (!Array.isArray(roleIds)) {
      throw errors.invalidPayload();
    }
    if (
      roleIds.length < 1
      || roleIds.length > MAX_TENANT_MEMBERSHIP_ROLE_BINDINGS
    ) {
      throw errors.invalidPayload();
    }

    const dedupedRoleIds = new Map();
    for (const roleId of roleIds) {
      const normalizedRoleId = normalizeRequiredStringField(roleId, errors.invalidPayload)
        .toLowerCase();
      if (
        normalizedRoleId.length > MAX_PLATFORM_ROLE_ID_LENGTH
        || CONTROL_CHAR_PATTERN.test(normalizedRoleId)
        || !ROLE_ID_ADDRESSABLE_PATTERN.test(normalizedRoleId)
      ) {
        throw errors.invalidPayload();
      }
      if (dedupedRoleIds.has(normalizedRoleId)) {
        throw errors.invalidPayload();
      }
      dedupedRoleIds.set(normalizedRoleId, normalizedRoleId);
    }
    const normalizedRoleIds = [...dedupedRoleIds.values()];
    const normalizedTraceparent = normalizeAuditStringOrNull(traceparent, 128);
    let previousRoleIdsForAudit = null;

    assertStoreMethod(
      authStore,
      'findTenantUsershipByMembershipIdAndTenantId',
      'authStore'
    );
    const membership = await authStore.findTenantUsershipByMembershipIdAndTenantId({
      membershipId: normalizedMembershipId,
      tenantId: normalizedTenantId
    });
    if (!membership) {
      throw errors.tenantUsershipNotFound();
    }
    const normalizedMembership = normalizeTenantUsershipRecordFromStore({
      membership,
      expectedMembershipId: normalizedMembershipId,
      expectedTenantId: normalizedTenantId
    });
    if (!normalizedMembership) {
      throw errors.tenantUserDependencyUnavailable({
        reason: 'tenant-membership-record-invalid'
      });
    }
    const normalizedMembershipStatus = normalizeTenantUsershipStatus(
      normalizedMembership.status
    );
    if (normalizedMembershipStatus !== 'active') {
      throw errors.tenantUsershipNotFound();
    }

    await loadValidatedTenantRoleCatalogEntries({
      tenantId: normalizedTenantId,
      roleIds: normalizedRoleIds,
      allowDisabledRoles: false
    });

    if (typeof authStore.listTenantUsershipRoleBindings === 'function') {
      try {
        const existingRoleIds = await authStore.listTenantUsershipRoleBindings({
          membershipId: normalizedMembershipId,
          tenantId: normalizedTenantId
        });
        previousRoleIdsForAudit = normalizeStrictTenantUsershipRoleIds({
          roleIds: existingRoleIds,
          minCount: 0,
          maxCount: MAX_TENANT_MEMBERSHIP_ROLE_BINDINGS,
          dependencyReason: 'tenant-membership-role-bindings-audit-invalid'
        });
      } catch (_error) {
        previousRoleIdsForAudit = null;
      }
    }

    if (typeof authStore.replaceTenantUsershipRoleBindingsAndSyncSnapshot !== 'function') {
      throw errors.tenantUserDependencyUnavailable({
        reason: 'tenant-membership-role-bindings-unsupported'
      });
    }

    let writeResult;
    try {
      writeResult = await authStore.replaceTenantUsershipRoleBindingsAndSyncSnapshot({
        requestId,
        tenantId: normalizedTenantId,
        membershipId: normalizedMembershipId,
        roleIds: normalizedRoleIds,
        operatorUserId,
        operatorSessionId,
        auditContext: {
          requestId: normalizeAuditStringOrNull(requestId, 128) || 'request_id_unset',
          traceparent: normalizedTraceparent,
          actorUserId: normalizeAuditStringOrNull(operatorUserId, 64),
          actorSessionId: normalizeAuditStringOrNull(operatorSessionId, 128)
        }
      });
    } catch (error) {
      if (error instanceof AuthProblemError) {
        throw error;
      }
      const normalizedErrorCode = String(error?.code || '').trim();
      if (
        normalizedErrorCode
        === 'ERR_TENANT_MEMBERSHIP_ROLE_BINDINGS_MEMBERSHIP_NOT_ACTIVE'
      ) {
        throw errors.tenantUsershipNotFound();
      }
      if (
        normalizedErrorCode
        === 'ERR_TENANT_MEMBERSHIP_ROLE_BINDINGS_ROLE_INVALID'
      ) {
        throw errors.roleNotFound();
      }
      if (normalizedErrorCode === 'ERR_AUDIT_WRITE_FAILED') {
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
          : 'tenant-membership-role-bindings-update-failed'
      });
    }
    if (!writeResult) {
      throw errors.tenantUsershipNotFound();
    }

    const rawResolvedMembershipId = (
      resolveRawCamelSnakeField(
        writeResult,
        'membershipId',
        'membership_id'
      )
    );
    const resolvedMembershipId = normalizeStrictRequiredStringField(rawResolvedMembershipId);
    if (!resolvedMembershipId || resolvedMembershipId !== normalizedMembershipId) {
      throw errors.tenantUserDependencyUnavailable({
        reason: 'tenant-membership-role-bindings-update-membership-mismatch'
      });
    }

    const rawResolvedRoleIds = Array.isArray(writeResult?.roleIds)
      ? writeResult.roleIds
      : Array.isArray(writeResult?.role_ids)
        ? writeResult.role_ids
        : null;
    const resolvedRoleIds = normalizeStrictTenantUsershipRoleIds({
      roleIds: rawResolvedRoleIds,
      minCount: 1,
      maxCount: MAX_TENANT_MEMBERSHIP_ROLE_BINDINGS,
      dependencyReason: 'tenant-membership-role-bindings-update-invalid'
    });
    await assertTenantUsershipRoleBindingsMatchTenantCatalog({
      tenantId: normalizedTenantId,
      roleIds: resolvedRoleIds,
      dependencyReason: 'tenant-membership-role-bindings-update-invalid'
    });
    const expectedRoleIds = [...normalizedRoleIds]
      .sort((left, right) => left.localeCompare(right));
    const hasRoleBindingsMismatch = (
      expectedRoleIds.length !== resolvedRoleIds.length
      || expectedRoleIds.some(
        (roleId, index) => roleId !== resolvedRoleIds[index]
      )
    );
    if (hasRoleBindingsMismatch) {
      throw errors.tenantUserDependencyUnavailable({
        reason: 'tenant-membership-role-bindings-update-mismatch'
      });
    }
    const hasAffectedUserIds = (
      hasOwnProperty(writeResult, 'affectedUserIds')
      || hasOwnProperty(writeResult, 'affected_user_ids')
    );
    const hasExplicitAffectedUserCount = (
      hasOwnProperty(writeResult, 'affectedUserCount')
      || hasOwnProperty(writeResult, 'affected_user_count')
    );
    if (!hasAffectedUserIds || !hasExplicitAffectedUserCount) {
      throw errors.tenantUserDependencyUnavailable({
        reason: 'tenant-membership-role-bindings-update-affected-user-metadata-missing'
      });
    }
    const affectedUserIds = normalizeStrictDistinctUserIdsFromDependency({
      userIds: resolveRawCamelSnakeField(
        writeResult,
        'affectedUserIds',
        'affected_user_ids'
      ),
      dependencyReason: 'tenant-membership-role-bindings-update-affected-user-ids-invalid'
    });
    const affectedUserCount = normalizeStrictNonNegativeIntegerFromDependency({
      value: resolveRawCamelSnakeField(
        writeResult,
        'affectedUserCount',
        'affected_user_count'
      ),
      dependencyReason: 'tenant-membership-role-bindings-update-affected-user-count-invalid'
    });
    if (
      hasExplicitAffectedUserCount
      && affectedUserCount !== affectedUserIds.length
    ) {
      throw errors.tenantUserDependencyUnavailable({
        reason: 'tenant-membership-role-bindings-update-affected-user-count-invalid'
      });
    }
    for (const affectedUserId of affectedUserIds) {
      invalidateSessionCacheByUserId(affectedUserId);
    }

    addAuditEvent({
      type: 'auth.tenant_membership_roles.updated',
      requestId,
      userId: operatorUserId || 'unknown',
      sessionId: operatorSessionId || 'unknown',
      detail: 'tenant usership role bindings replaced and permission snapshot synced',
      metadata: {
        tenant_id: normalizedTenantId,
        membership_id: normalizedMembershipId,
        role_ids: resolvedRoleIds,
        affected_user_count: affectedUserCount
      }
    });
    const storeAuditRecorded = (
      writeResult?.auditRecorded === true
      || writeResult?.audit_recorded === true
    );
    if (!storeAuditRecorded) {
      await recordPersistentAuditEvent({
        domain: 'tenant',
        tenantId: normalizedTenantId,
        requestId: normalizeAuditStringOrNull(requestId, 128) || 'request_id_unset',
        traceparent: normalizedTraceparent,
        eventType: 'auth.tenant_membership_roles.updated',
        actorUserId: normalizeAuditStringOrNull(operatorUserId, 64),
        actorSessionId: normalizeAuditStringOrNull(operatorSessionId, 128),
        targetType: 'membership_role_bindings',
        targetId: normalizedMembershipId,
        result: 'success',
        beforeState: {
          role_ids: Array.isArray(previousRoleIdsForAudit)
            ? [...previousRoleIdsForAudit]
            : null
        },
        afterState: {
          role_ids: [...resolvedRoleIds]
        },
        metadata: {
          affected_user_count: affectedUserCount
        }
      });
    }

    return {
      membership_id: resolvedMembershipId,
      role_ids: resolvedRoleIds
    };
  };

  return {
    normalizeStrictTenantUsershipRoleIds,
    listTenantUserRoleBindings,
    replaceTenantUserRoleBindings
  };
};

module.exports = {
  createTenantRoleBindingCapabilities
};
