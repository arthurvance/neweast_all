'use strict';

const {
  MAX_ORG_STATUS_CASCADE_COUNT
} = require('../../../../shared-kernel/auth/create-auth-service.helpers');

const createPlatformGovernanceCapabilities = ({
  authStore,
  errors,
  hasOwnProperty,
  assertStoreMethod,
  normalizeOrgStatus,
  normalizeAuditStringOrNull,
  normalizeStrictRequiredStringField,
  normalizeStrictNonNegativeIntegerFromPlatformDependency,
  resolveRawCamelSnakeField,
  invalidateAllAccessSessionCache,
  invalidateSessionCacheByUserId,
  addAuditEvent,
  recordPersistentAuditEvent,
  MAX_PLATFORM_USER_ID_LENGTH,
  VALID_ORG_STATUS,
  VALID_PLATFORM_USER_STATUS
} = {}) => {
  const normalizeOrgStatusCascadeCountFromDependency = ({
    value,
    dependencyReason = 'org-status-cascade-count-invalid'
  } = {}) => {
    if (value === undefined || value === null) {
      return 0;
    }
    if (
      typeof value !== 'number'
      || !Number.isInteger(value)
      || value < 0
    ) {
      throw errors.tenantUserDependencyUnavailable({
        reason: dependencyReason
      });
    }
    return Math.min(value, MAX_ORG_STATUS_CASCADE_COUNT);
  };

  const updateOrganizationStatus = async ({
    requestId,
    traceparent = null,
    orgId,
    nextStatus,
    operatorUserId,
    operatorSessionId,
    reason = null
  }) => {
    const normalizedRequestId = String(requestId || '').trim() || 'request_id_unset';
    const normalizedOrgId = String(orgId || '').trim();
    const normalizedOperatorUserId = String(operatorUserId || '').trim();
    const normalizedOperatorSessionId = String(operatorSessionId || '').trim();
    const normalizedNextStatus = normalizeOrgStatus(nextStatus);
    const normalizedReason = reason === null || reason === undefined
      ? null
      : String(reason).trim() || null;

    if (
      !normalizedOrgId
      || !normalizedOperatorUserId
      || !normalizedOperatorSessionId
      || !VALID_ORG_STATUS.has(normalizedNextStatus)
    ) {
      throw errors.invalidPayload();
    }

    assertStoreMethod(authStore, 'updateOrganizationStatus', 'authStore');
    let result = null;
    try {
      result = await authStore.updateOrganizationStatus({
        requestId: normalizedRequestId,
        orgId: normalizedOrgId,
        nextStatus: normalizedNextStatus,
        operatorUserId: normalizedOperatorUserId,
        reason: normalizedReason,
        auditContext: {
          requestId: normalizedRequestId,
          traceparent: normalizeAuditStringOrNull(traceparent, 128),
          actorUserId: normalizedOperatorUserId,
          actorSessionId: normalizedOperatorSessionId,
          reason: normalizedReason
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
    if (!result) {
      throw errors.orgNotFound();
    }

    const previousStatus = normalizeOrgStatus(result.previous_status);
    const currentStatus = normalizeOrgStatus(result.current_status);
    if (!previousStatus || !currentStatus) {
      throw errors.invalidPayload();
    }
    const affectedMembershipCount = normalizeOrgStatusCascadeCountFromDependency({
      value: resolveRawCamelSnakeField(
        result,
        'affectedMembershipCount',
        'affected_membership_count'
      ),
      dependencyReason: 'org-status-cascade-affected-membership-count-invalid'
    });
    const affectedRoleCount = normalizeOrgStatusCascadeCountFromDependency({
      value: resolveRawCamelSnakeField(
        result,
        'affectedRoleCount',
        'affected_role_count'
      ),
      dependencyReason: 'org-status-cascade-affected-role-count-invalid'
    });
    const affectedRoleBindingCount = normalizeOrgStatusCascadeCountFromDependency({
      value: resolveRawCamelSnakeField(
        result,
        'affectedRoleBindingCount',
        'affected_role_binding_count'
      ),
      dependencyReason: 'org-status-cascade-affected-role-binding-count-invalid'
    });
    const revokedSessionCount = normalizeOrgStatusCascadeCountFromDependency({
      value: resolveRawCamelSnakeField(
        result,
        'revokedSessionCount',
        'revoked_session_count'
      ),
      dependencyReason: 'org-status-cascade-revoked-session-count-invalid'
    });
    const revokedRefreshTokenCount = normalizeOrgStatusCascadeCountFromDependency({
      value: resolveRawCamelSnakeField(
        result,
        'revokedRefreshTokenCount',
        'revoked_refresh_token_count'
      ),
      dependencyReason: 'org-status-cascade-revoked-refresh-token-count-invalid'
    });
    if (previousStatus !== currentStatus) {
      invalidateAllAccessSessionCache();
    }
    addAuditEvent({
      type: 'auth.org.status.updated',
      requestId: normalizedRequestId,
      userId: normalizedOperatorUserId,
      sessionId: normalizedOperatorSessionId,
      detail: previousStatus === currentStatus
        ? 'organization status update treated as no-op'
        : 'organization status updated',
      metadata: {
        org_id: normalizedOrgId,
        previous_status: previousStatus,
        current_status: currentStatus,
        reason: normalizedReason,
        affected_membership_count: affectedMembershipCount,
        affected_role_count: affectedRoleCount,
        affected_role_binding_count: affectedRoleBindingCount,
        revoked_session_count: revokedSessionCount,
        revoked_refresh_token_count: revokedRefreshTokenCount
      }
    });
    const storeAuditRecorded = (
      result?.auditRecorded === true
      || result?.audit_recorded === true
    );
    if (!storeAuditRecorded) {
      await recordPersistentAuditEvent({
        domain: 'tenant',
        tenantId: normalizedOrgId,
        requestId: normalizedRequestId,
        traceparent: normalizeAuditStringOrNull(traceparent, 128),
        eventType: 'auth.org.status.updated',
        actorUserId: normalizedOperatorUserId,
        actorSessionId: normalizedOperatorSessionId,
        targetType: 'org',
        targetId: normalizedOrgId,
        result: 'success',
        beforeState: {
          status: previousStatus
        },
        afterState: {
          status: currentStatus
        },
        metadata: {
          reason: normalizedReason,
          affected_membership_count: affectedMembershipCount,
          affected_role_count: affectedRoleCount,
          affected_role_binding_count: affectedRoleBindingCount,
          revoked_session_count: revokedSessionCount,
          revoked_refresh_token_count: revokedRefreshTokenCount
        }
      });
    }

    return {
      org_id: normalizedOrgId,
      previous_status: previousStatus,
      current_status: currentStatus,
      affected_membership_count: affectedMembershipCount,
      affected_role_count: affectedRoleCount,
      affected_role_binding_count: affectedRoleBindingCount,
      revoked_session_count: revokedSessionCount,
      revoked_refresh_token_count: revokedRefreshTokenCount
    };
  };

  const updatePlatformUserStatus = async ({
    requestId,
    traceparent = null,
    userId,
    nextStatus,
    operatorUserId,
    operatorSessionId,
    reason = null
  }) => {
    const normalizedRequestId = String(requestId || '').trim() || 'request_id_unset';
    const normalizedUserId = String(userId || '').trim();
    const normalizedOperatorUserId = String(operatorUserId || '').trim();
    const normalizedOperatorSessionId = String(operatorSessionId || '').trim();
    const normalizedNextStatus = normalizeOrgStatus(nextStatus);
    const normalizedReason = reason === null || reason === undefined
      ? null
      : String(reason).trim() || null;
    const normalizedTraceparent = normalizeAuditStringOrNull(traceparent, 128);

    if (
      !normalizedUserId
      || normalizedUserId.length > MAX_PLATFORM_USER_ID_LENGTH
      || !normalizedOperatorUserId
      || !normalizedOperatorSessionId
      || !VALID_PLATFORM_USER_STATUS.has(normalizedNextStatus)
    ) {
      throw errors.invalidPayload();
    }

    assertStoreMethod(authStore, 'updatePlatformUserStatus', 'authStore');
    let result;
    try {
      result = await authStore.updatePlatformUserStatus({
        requestId: normalizedRequestId,
        userId: normalizedUserId,
        nextStatus: normalizedNextStatus,
        operatorUserId: normalizedOperatorUserId,
        reason: normalizedReason,
        auditContext: {
          requestId: normalizedRequestId,
          traceparent: normalizedTraceparent,
          actorUserId: normalizedOperatorUserId,
          actorSessionId: normalizedOperatorSessionId,
          reason: normalizedReason
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
    if (!result) {
      throw errors.userNotFound();
    }

    const previousStatus = normalizeOrgStatus(result.previous_status);
    const currentStatus = normalizeOrgStatus(result.current_status);
    if (
      !VALID_PLATFORM_USER_STATUS.has(previousStatus)
      || !VALID_PLATFORM_USER_STATUS.has(currentStatus)
    ) {
      throw errors.platformSnapshotDegraded({
        reason: 'platform-user-status-result-invalid'
      });
    }
    if (previousStatus !== currentStatus) {
      invalidateSessionCacheByUserId(normalizedUserId);
    }
    addAuditEvent({
      type: 'auth.platform.user.status.updated',
      requestId: normalizedRequestId,
      userId: normalizedOperatorUserId,
      sessionId: normalizedOperatorSessionId,
      detail: previousStatus === currentStatus
        ? 'platform user status update treated as no-op'
        : 'platform user status updated',
      metadata: {
        target_user_id: normalizedUserId,
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
        domain: 'platform',
        tenantId: null,
        requestId: normalizedRequestId,
        traceparent: normalizedTraceparent,
        eventType: 'auth.platform.user.status.updated',
        actorUserId: normalizedOperatorUserId,
        actorSessionId: normalizedOperatorSessionId,
        targetType: 'user',
        targetId: normalizedUserId,
        result: 'success',
        beforeState: {
          status: previousStatus
        },
        afterState: {
          status: currentStatus
        },
        metadata: {
          reason: normalizedReason
        }
      });
    }

    return {
      user_id: normalizedUserId,
      previous_status: previousStatus,
      current_status: currentStatus
    };
  };

  const softDeleteUser = async ({
    requestId,
    traceparent = null,
    userId,
    operatorUserId,
    operatorSessionId
  }) => {
    const normalizedRequestId = String(requestId || '').trim() || 'request_id_unset';
    const normalizedUserId = String(userId || '').trim();
    const normalizedOperatorUserId = String(operatorUserId || '').trim();
    const normalizedOperatorSessionId = String(operatorSessionId || '').trim();
    const normalizedTraceparent = normalizeAuditStringOrNull(traceparent, 128);

    if (
      !normalizedUserId
      || normalizedUserId.length > MAX_PLATFORM_USER_ID_LENGTH
      || !normalizedOperatorUserId
      || !normalizedOperatorSessionId
    ) {
      throw errors.invalidPayload();
    }

    assertStoreMethod(authStore, 'softDeleteUser', 'authStore');
    let result;
    try {
      result = await authStore.softDeleteUser({
        requestId: normalizedRequestId,
        userId: normalizedUserId,
        operatorUserId: normalizedOperatorUserId,
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
    if (!result) {
      throw errors.userNotFound();
    }

    const resolvedResultUserId = normalizeStrictRequiredStringField(
      resolveRawCamelSnakeField(result, 'userId', 'user_id')
    );
    if (!resolvedResultUserId || resolvedResultUserId !== normalizedUserId) {
      throw errors.platformSnapshotDegraded({
        reason: 'platform-user-soft-delete-target-mismatch'
      });
    }

    const previousStatus = normalizeOrgStatus(
      resolveRawCamelSnakeField(result, 'previousStatus', 'previous_status')
    );
    const currentStatus = normalizeOrgStatus(
      resolveRawCamelSnakeField(result, 'currentStatus', 'current_status')
    );
    if (
      !VALID_PLATFORM_USER_STATUS.has(previousStatus)
      || !VALID_PLATFORM_USER_STATUS.has(currentStatus)
      || currentStatus !== 'disabled'
    ) {
      throw errors.platformSnapshotDegraded({
        reason: 'platform-user-soft-delete-result-invalid'
      });
    }
    if (
      !hasOwnProperty(result, 'revokedSessionCount')
      && !hasOwnProperty(result, 'revoked_session_count')
    ) {
      throw errors.platformSnapshotDegraded({
        reason: 'platform-user-soft-delete-revoked-session-count-invalid'
      });
    }
    if (
      !hasOwnProperty(result, 'revokedRefreshTokenCount')
      && !hasOwnProperty(result, 'revoked_refresh_token_count')
    ) {
      throw errors.platformSnapshotDegraded({
        reason: 'platform-user-soft-delete-revoked-refresh-token-count-invalid'
      });
    }
    const revokedSessionCount = normalizeStrictNonNegativeIntegerFromPlatformDependency({
      value: resolveRawCamelSnakeField(
        result,
        'revokedSessionCount',
        'revoked_session_count'
      ),
      dependencyReason: 'platform-user-soft-delete-revoked-session-count-invalid'
    });
    const revokedRefreshTokenCount = normalizeStrictNonNegativeIntegerFromPlatformDependency({
      value: resolveRawCamelSnakeField(
        result,
        'revokedRefreshTokenCount',
        'revoked_refresh_token_count'
      ),
      dependencyReason: 'platform-user-soft-delete-revoked-refresh-token-count-invalid'
    });

    // Always clear cached access sessions for the target user to avoid stale cache allow-list
    // windows when soft-delete is replayed as a no-op.
    invalidateSessionCacheByUserId(normalizedUserId);
    addAuditEvent({
      type: 'auth.platform.user.soft_deleted',
      requestId: normalizedRequestId,
      userId: normalizedOperatorUserId,
      sessionId: normalizedOperatorSessionId,
      detail: previousStatus === currentStatus
        && revokedSessionCount === 0
        && revokedRefreshTokenCount === 0
        ? 'platform user soft-delete treated as no-op'
        : 'platform user soft-deleted and global sessions revoked',
      metadata: {
        target_user_id: normalizedUserId,
        previous_status: previousStatus,
        current_status: currentStatus,
        revoked_session_count: revokedSessionCount,
        revoked_refresh_token_count: revokedRefreshTokenCount
      }
    });
    const storeAuditRecorded = (
      result?.auditRecorded === true
      || result?.audit_recorded === true
    );
    if (!storeAuditRecorded) {
      await recordPersistentAuditEvent({
        domain: 'platform',
        tenantId: null,
        requestId: normalizedRequestId,
        traceparent: normalizedTraceparent,
        eventType: 'auth.platform.user.soft_deleted',
        actorUserId: normalizedOperatorUserId,
        actorSessionId: normalizedOperatorSessionId,
        targetType: 'user',
        targetId: normalizedUserId,
        result: 'success',
        beforeState: {
          status: previousStatus
        },
        afterState: {
          status: currentStatus
        },
        metadata: {
          revoked_session_count: revokedSessionCount,
          revoked_refresh_token_count: revokedRefreshTokenCount
        }
      });
    }

    return {
      user_id: normalizedUserId,
      previous_status: previousStatus,
      current_status: currentStatus,
      revoked_session_count: revokedSessionCount,
      revoked_refresh_token_count: revokedRefreshTokenCount
    };
  };

  return {
    updateOrganizationStatus,
    updatePlatformUserStatus,
    softDeleteUser
  };
};

module.exports = {
  createPlatformGovernanceCapabilities
};
