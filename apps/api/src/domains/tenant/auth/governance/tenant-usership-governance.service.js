'use strict';

const createTenantUsershipGovernanceCapabilities = ({
  authStore,
  errors,
  hasOwnProperty,
  assertStoreMethod,
  normalizeTenantId,
  normalizeStrictTenantUsershipIdFromInput,
  normalizeTenantUsershipRecordFromStore,
  normalizeMemberListInteger,
  resolveRawCamelSnakeField,
  normalizeStrictRequiredStringField,
  normalizeEntryDomain,
  normalizeTenantUsershipStatus,
  isValidTenantUsershipId,
  normalizeAuditStringOrNull,
  authorizeRoute,
  addAuditEvent,
  recordPersistentAuditEvent,
  invalidateSessionCacheByUserId,
  TENANT_USER_MANAGEMENT_OPERATE_PERMISSION_CODE,
  UNSET_EXPECTED_TENANT_USER_PROFILE_FIELD,
  MAX_TENANT_USER_DISPLAY_NAME_LENGTH,
  MAX_TENANT_USER_DEPARTMENT_NAME_LENGTH,
  MAX_OWNER_TRANSFER_REASON_LENGTH,
  CONTROL_CHAR_PATTERN
} = {}) => {
  const findTenantUsershipByUserAndTenantId = async ({
    userId,
    tenantId
  }) => {
    const normalizedUserId = String(userId || '').trim();
    const normalizedTenantId = normalizeTenantId(tenantId);
    if (!normalizedUserId || !normalizedTenantId) {
      return null;
    }

    assertStoreMethod(authStore, 'findTenantUsershipByUserAndTenantId', 'authStore');
    let membership = null;
    try {
      membership = await authStore.findTenantUsershipByUserAndTenantId({
        userId: normalizedUserId,
        tenantId: normalizedTenantId
      });
    } catch (error) {
      throw errors.tenantUserDependencyUnavailable({
        reason: String(error?.code || error?.message || 'query-failed')
      });
    }
    if (!membership) {
      return null;
    }
    const normalizedMembership = normalizeTenantUsershipRecordFromStore({
      membership,
      expectedUserId: normalizedUserId,
      expectedTenantId: normalizedTenantId
    });
    if (!normalizedMembership) {
      throw errors.tenantUserDependencyUnavailable({
        reason: 'tenant-membership-record-invalid'
      });
    }
    return normalizedMembership;
  };

  const listTenantUsers = async ({
    requestId,
    tenantId,
    page = 1,
    pageSize = 50
  }) => {
    const normalizedTenantId = normalizeTenantId(tenantId);
    if (!normalizedTenantId) {
      throw errors.noDomainAccess();
    }
    const normalizedPage = normalizeMemberListInteger({
      value: page,
      fallback: 1,
      min: 1,
      max: 100000
    });
    const normalizedPageSize = normalizeMemberListInteger({
      value: pageSize,
      fallback: 50,
      min: 1,
      max: 200
    });
    assertStoreMethod(authStore, 'listTenantUsersByTenantId', 'authStore');
    let members = [];
    try {
      members = await authStore.listTenantUsersByTenantId({
        tenantId: normalizedTenantId,
        page: normalizedPage,
        pageSize: normalizedPageSize
      });
    } catch (error) {
      throw errors.tenantUserDependencyUnavailable({
        reason: String(error?.code || error?.message || 'query-failed')
      });
    }
    if (!Array.isArray(members)) {
      throw errors.tenantUserDependencyUnavailable({
        reason: 'tenant-members-list-shape-invalid'
      });
    }
    const normalizedMembers = [];
    for (const member of members) {
      const normalizedMember = normalizeTenantUsershipRecordFromStore({
        membership: member,
        expectedTenantId: normalizedTenantId
      });
      if (!normalizedMember) {
        throw errors.tenantUserDependencyUnavailable({
          reason: 'tenant-membership-record-invalid'
        });
      }
      normalizedMembers.push(normalizedMember);
    }
    return normalizedMembers;
  };

  const findTenantUsershipByMembershipIdAndTenantId = async ({
    membershipId,
    tenantId
  }) => {
    const normalizedMembershipId =
      normalizeStrictTenantUsershipIdFromInput(membershipId);
    const normalizedTenantId = normalizeTenantId(tenantId);
    if (!normalizedMembershipId || !normalizedTenantId) {
      return null;
    }

    assertStoreMethod(
      authStore,
      'findTenantUsershipByMembershipIdAndTenantId',
      'authStore'
    );
    let membership = null;
    try {
      membership = await authStore.findTenantUsershipByMembershipIdAndTenantId({
        membershipId: normalizedMembershipId,
        tenantId: normalizedTenantId
      });
    } catch (error) {
      throw errors.tenantUserDependencyUnavailable({
        reason: String(error?.code || error?.message || 'query-failed')
      });
    }
    if (!membership) {
      return null;
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
    return normalizedMembership;
  };

  const updateTenantUserProfile = async (input = {}) => {
    const normalizedMembershipId =
      normalizeStrictTenantUsershipIdFromInput(
        resolveRawCamelSnakeField(input, 'membershipId', 'membership_id')
      );
    const requestedTenantId = normalizeTenantId(
      resolveRawCamelSnakeField(input, 'tenantId', 'tenant_id')
    );
    const rawDisplayName = resolveRawCamelSnakeField(
      input,
      'displayName',
      'display_name'
    );
    if (typeof rawDisplayName !== 'string') {
      throw errors.invalidPayload();
    }
    const normalizedDisplayName = normalizeStrictRequiredStringField(rawDisplayName);
    if (
      !normalizedDisplayName
      || normalizedDisplayName.length > MAX_TENANT_USER_DISPLAY_NAME_LENGTH
      || CONTROL_CHAR_PATTERN.test(normalizedDisplayName)
    ) {
      throw errors.invalidPayload();
    }
    const hasDepartmentNameProvidedFlag = (
      input?.departmentNameProvided === true
      || input?.department_name_provided === true
    );
    const hasDepartmentNameProvidedKey = (
      hasOwnProperty(input, 'departmentNameProvided')
      || hasOwnProperty(input, 'department_name_provided')
    );
    const hasDepartmentNameField = (
      hasOwnProperty(input, 'departmentName')
      || hasOwnProperty(input, 'department_name')
    );
    const hasDepartmentNameCandidate = (
      hasDepartmentNameProvidedFlag
      || (!hasDepartmentNameProvidedKey && hasDepartmentNameField)
    );
    const rawDepartmentName = hasOwnProperty(input, 'departmentName')
      ? input.departmentName
      : input.department_name;
    let normalizedDepartmentName = null;
    if (hasDepartmentNameCandidate) {
      if (rawDepartmentName === null) {
        normalizedDepartmentName = null;
      } else if (typeof rawDepartmentName === 'string') {
        normalizedDepartmentName = normalizeStrictRequiredStringField(rawDepartmentName);
        if (
          !normalizedDepartmentName
          || normalizedDepartmentName.length > MAX_TENANT_USER_DEPARTMENT_NAME_LENGTH
          || CONTROL_CHAR_PATTERN.test(normalizedDepartmentName)
        ) {
          throw errors.invalidPayload();
        }
      } else {
        throw errors.invalidPayload();
      }
    }

    const normalizedAuthorizedRoute =
      input?.authorizedRoute && typeof input.authorizedRoute === 'object'
        ? {
          user_id: String(
            input.authorizedRoute.user_id
            || input.authorizedRoute.userId
            || ''
          ).trim(),
          session_id: String(
            input.authorizedRoute.session_id
            || input.authorizedRoute.sessionId
            || ''
          ).trim(),
          entry_domain: normalizeEntryDomain(
            input.authorizedRoute.entry_domain
            || input.authorizedRoute.entryDomain
          ),
          active_tenant_id: normalizeTenantId(
            input.authorizedRoute.active_tenant_id
            || input.authorizedRoute.activeTenantId
          )
        }
        : null;
    let resolvedAuthorizedRoute = null;
    if (normalizedAuthorizedRoute) {
      if (
        !normalizedAuthorizedRoute.user_id
        || !normalizedAuthorizedRoute.session_id
        || normalizedAuthorizedRoute.entry_domain !== 'tenant'
      ) {
        throw errors.forbidden();
      }
      resolvedAuthorizedRoute = normalizedAuthorizedRoute;
    } else {
      resolvedAuthorizedRoute = await authorizeRoute({
        requestId: input.requestId,
        accessToken: input.accessToken,
        permissionCode: TENANT_USER_MANAGEMENT_OPERATE_PERMISSION_CODE,
        scope: 'tenant',
        authorizationContext: input.authorizationContext || null
      });
    }

    const operatorUserId = String(resolvedAuthorizedRoute?.user_id || '').trim();
    const operatorSessionId = String(resolvedAuthorizedRoute?.session_id || '').trim();
    const activeTenantId = normalizeTenantId(resolvedAuthorizedRoute?.active_tenant_id);
    if (!operatorUserId || !operatorSessionId || !activeTenantId) {
      throw errors.noDomainAccess();
    }
    if (requestedTenantId && requestedTenantId !== activeTenantId) {
      throw errors.invalidPayload();
    }

    assertStoreMethod(authStore, 'updateTenantUsershipProfile', 'authStore');
    let result = null;
    try {
      result = await authStore.updateTenantUsershipProfile({
        membershipId: normalizedMembershipId,
        tenantId: activeTenantId,
        displayName: normalizedDisplayName,
        departmentNameProvided: hasDepartmentNameCandidate,
        departmentName: normalizedDepartmentName,
        operatorUserId
      });
    } catch (error) {
      throw errors.tenantUserDependencyUnavailable({
        reason: String(error?.code || error?.message || 'write-failed')
      });
    }
    if (!result) {
      throw errors.tenantUsershipNotFound();
    }

    const normalizedMembership = normalizeTenantUsershipRecordFromStore({
      membership: result,
      expectedMembershipId: normalizedMembershipId,
      expectedTenantId: activeTenantId,
      expectedDisplayName: normalizedDisplayName,
      expectedDepartmentName: hasDepartmentNameCandidate
        ? normalizedDepartmentName
        : UNSET_EXPECTED_TENANT_USER_PROFILE_FIELD
    });
    if (!normalizedMembership) {
      throw errors.tenantUserDependencyUnavailable({
        reason: 'tenant-membership-record-invalid'
      });
    }

    addAuditEvent({
      type: 'auth.tenant.user.profile.updated',
      requestId: input.requestId,
      userId: operatorUserId || 'unknown',
      sessionId: operatorSessionId || 'unknown',
      detail: 'tenant user profile updated',
      metadata: {
        membership_id: normalizedMembershipId,
        tenant_id: activeTenantId,
        changed_fields: hasDepartmentNameCandidate
          ? ['display_name', 'department_name']
          : ['display_name']
      }
    });

    return normalizedMembership;
  };

  const updateTenantUserStatus = async ({
    requestId,
    traceparent = null,
    accessToken,
    membershipId,
    nextStatus,
    reason = null,
    authorizationContext = null,
    authorizedRoute = null
  }) => {
    const normalizedMembershipId =
      normalizeStrictTenantUsershipIdFromInput(membershipId);
    const normalizedNextStatus = normalizeTenantUsershipStatus(nextStatus);
    let normalizedReason = null;
    if (reason !== null && reason !== undefined) {
      if (typeof reason !== 'string') {
        throw errors.invalidPayload();
      }
      const normalizedReasonCandidate = String(reason).trim();
      if (
        !normalizedReasonCandidate
        || normalizedReasonCandidate.length > MAX_OWNER_TRANSFER_REASON_LENGTH
        || CONTROL_CHAR_PATTERN.test(normalizedReasonCandidate)
      ) {
        throw errors.invalidPayload();
      }
      normalizedReason = normalizedReasonCandidate;
    }
    if (
      !normalizedMembershipId
      || !normalizedNextStatus
      || !isValidTenantUsershipId(normalizedMembershipId)
    ) {
      throw errors.invalidPayload();
    }
    const normalizedRequestId = String(requestId || '').trim() || 'request_id_unset';
    const normalizedTraceparent = normalizeAuditStringOrNull(traceparent, 128);

    const normalizedAuthorizedRoute =
      authorizedRoute && typeof authorizedRoute === 'object'
        ? {
          user_id: String(
            authorizedRoute.user_id
            || authorizedRoute.userId
            || ''
          ).trim(),
          session_id: String(
            authorizedRoute.session_id
            || authorizedRoute.sessionId
            || ''
          ).trim(),
          entry_domain: normalizeEntryDomain(
            authorizedRoute.entry_domain
            || authorizedRoute.entryDomain
          ),
          active_tenant_id: normalizeTenantId(
            authorizedRoute.active_tenant_id
            || authorizedRoute.activeTenantId
          )
        }
        : null;
    let resolvedAuthorizedRoute = null;
    if (normalizedAuthorizedRoute) {
      if (
        !normalizedAuthorizedRoute.user_id
        || !normalizedAuthorizedRoute.session_id
        || normalizedAuthorizedRoute.entry_domain !== 'tenant'
      ) {
        throw errors.forbidden();
      }
      resolvedAuthorizedRoute = normalizedAuthorizedRoute;
    } else {
      resolvedAuthorizedRoute = await authorizeRoute({
        requestId: normalizedRequestId,
        accessToken,
        permissionCode: TENANT_USER_MANAGEMENT_OPERATE_PERMISSION_CODE,
        scope: 'tenant',
        authorizationContext
      });
    }

    const operatorUserId = String(resolvedAuthorizedRoute?.user_id || '').trim();
    const operatorSessionId = String(resolvedAuthorizedRoute?.session_id || '').trim();
    const activeTenantId = normalizeTenantId(resolvedAuthorizedRoute?.active_tenant_id);
    if (!operatorUserId || !operatorSessionId || !activeTenantId) {
      throw errors.noDomainAccess();
    }

    assertStoreMethod(authStore, 'updateTenantUsershipStatus', 'authStore');
    let result = null;
    try {
      result = await authStore.updateTenantUsershipStatus({
        membershipId: normalizedMembershipId,
        tenantId: activeTenantId,
        nextStatus: normalizedNextStatus,
        operatorUserId,
        reason: normalizedReason,
        auditContext: {
          requestId: normalizedRequestId,
          traceparent: normalizedTraceparent,
          actorUserId: operatorUserId,
          actorSessionId: operatorSessionId,
          reason: normalizedReason
        }
      });
    } catch (error) {
      if (String(error?.code || '').trim() === 'ERR_AUDIT_WRITE_FAILED') {
        throw errors.tenantUserDependencyUnavailable({
          reason: 'audit-write-failed'
        });
      }
      throw errors.tenantUserDependencyUnavailable({
        reason: String(error?.code || error?.message || 'write-failed')
      });
    }
    if (!result) {
      throw errors.tenantUsershipNotFound();
    }

    const previousStatus = normalizeTenantUsershipStatus(result.previous_status);
    const currentStatus = normalizeTenantUsershipStatus(result.current_status);
    if (!previousStatus || !currentStatus) {
      throw errors.tenantUserDependencyUnavailable({
        reason: 'tenant-membership-status-result-invalid'
      });
    }
    const rawResolvedMembershipId = hasOwnProperty(result, 'membership_id')
      ? result.membership_id
      : normalizedMembershipId;
    const resolvedMembershipId =
      normalizeStrictRequiredStringField(rawResolvedMembershipId).toLowerCase();
    const rawResolvedTenantId = hasOwnProperty(result, 'tenant_id')
      ? result.tenant_id
      : activeTenantId;
    const resolvedTenantId = normalizeStrictRequiredStringField(rawResolvedTenantId);
    const isRejoinTransition =
      previousStatus === 'left'
      && normalizedNextStatus === 'active'
      && currentStatus === 'active';
    const hasMembershipIdMismatch = resolvedMembershipId !== normalizedMembershipId;
    if (
      !isValidTenantUsershipId(resolvedMembershipId)
      || !resolvedTenantId
      || resolvedTenantId !== activeTenantId
      || (isRejoinTransition && !hasMembershipIdMismatch)
      || (!isRejoinTransition && hasMembershipIdMismatch)
    ) {
      throw errors.tenantUserDependencyUnavailable({
        reason: 'tenant-membership-result-shape-invalid'
      });
    }
    if (previousStatus !== currentStatus) {
      invalidateSessionCacheByUserId(String(result.user_id || '').trim());
    }
    addAuditEvent({
      type: 'auth.tenant.user.status.updated',
      requestId: normalizedRequestId,
      userId: operatorUserId || 'unknown',
      sessionId: operatorSessionId || 'unknown',
      detail: previousStatus === currentStatus
        ? 'tenant usership status update treated as no-op'
        : 'tenant usership status updated',
      metadata: {
        membership_id: resolvedMembershipId,
        target_user_id: String(result.user_id || '').trim() || null,
        tenant_id: resolvedTenantId,
        previous_status: previousStatus,
        current_status: currentStatus,
        reason: normalizedReason
      }
    });
    const storeAuditRecorded = (
      result?.auditRecorded === true
      || result?.audit_recorded === true
    );
    if (!storeAuditRecorded) {
      await recordPersistentAuditEvent({
        domain: 'tenant',
        tenantId: resolvedTenantId,
        requestId: normalizedRequestId,
        traceparent: normalizedTraceparent,
        eventType: 'auth.tenant.user.status.updated',
        actorUserId: normalizeAuditStringOrNull(operatorUserId, 64),
        actorSessionId: normalizeAuditStringOrNull(operatorSessionId, 128),
        targetType: 'membership',
        targetId: resolvedMembershipId,
        result: 'success',
        beforeState: {
          status: previousStatus
        },
        afterState: {
          status: currentStatus
        },
        metadata: {
          target_user_id: String(result.user_id || '').trim() || null,
          tenant_id: resolvedTenantId,
          membership_id: resolvedMembershipId,
          reason: normalizedReason
        }
      });
    }
    return {
      membership_id: resolvedMembershipId,
      user_id: String(result.user_id || '').trim(),
      tenant_id: resolvedTenantId,
      previous_status: previousStatus,
      current_status: currentStatus
    };
  };

  return {
    findTenantUsershipByUserAndTenantId,
    listTenantUsers,
    findTenantUsershipByMembershipIdAndTenantId,
    updateTenantUserProfile,
    updateTenantUserStatus
  };
};

module.exports = {
  createTenantUsershipGovernanceCapabilities
};
