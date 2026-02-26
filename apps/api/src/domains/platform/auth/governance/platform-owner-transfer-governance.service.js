'use strict';

const createPlatformOwnerTransferGovernanceCapabilities = ({
  authStore,
  errors,
  AuthProblemError,
  now,
  ownerTransferLocksByOrgId,
  assertStoreMethod,
  normalizePhone,
  normalizeOrgStatus,
  isUserActive,
  maskPhone,
  toOwnerTransferTakeoverRoleId,
  normalizeAuditStringOrNull,
  invalidateSessionCacheByUserId,
  addAuditEvent,
  recordPersistentAuditEvent,
  MAX_OWNER_TRANSFER_ORG_ID_LENGTH,
  MAX_OWNER_TRANSFER_REASON_LENGTH,
  OWNER_TRANSFER_TAKEOVER_ROLE_CODE,
  OWNER_TRANSFER_TAKEOVER_ROLE_NAME,
  OWNER_TRANSFER_TAKEOVER_REQUIRED_PERMISSION_CODES,
  CONTROL_CHAR_PATTERN,
  WHITESPACE_PATTERN
} = {}) => {
  const acquireOwnerTransferLock = async ({
    orgId,
    requestId = 'request_id_unset',
    operatorUserId = 'unknown',
    timeoutSeconds = 0
  } = {}) => {
    const normalizedOrgId = String(orgId || '').trim();
    if (
      !normalizedOrgId
      || WHITESPACE_PATTERN.test(normalizedOrgId)
      || CONTROL_CHAR_PATTERN.test(normalizedOrgId)
      || normalizedOrgId.length > MAX_OWNER_TRANSFER_ORG_ID_LENGTH
    ) {
      return false;
    }
    const hasStoreAcquireOwnerTransferLock =
      authStore && typeof authStore.acquireOwnerTransferLock === 'function';
    const hasStoreReleaseOwnerTransferLock =
      authStore && typeof authStore.releaseOwnerTransferLock === 'function';
    if (!hasStoreAcquireOwnerTransferLock || !hasStoreReleaseOwnerTransferLock) {
      throw errors.ownerTransferLockUnavailable();
    }
    if (ownerTransferLocksByOrgId.has(normalizedOrgId)) {
      return false;
    }
    ownerTransferLocksByOrgId.set(normalizedOrgId, {
      request_id: String(requestId || '').trim() || 'request_id_unset',
      operator_user_id: String(operatorUserId || '').trim() || 'unknown',
      started_at: new Date(now()).toISOString()
    });
    try {
      const acquired = await authStore.acquireOwnerTransferLock({
        orgId: normalizedOrgId,
        requestId: String(requestId || '').trim() || 'request_id_unset',
        operatorUserId: String(operatorUserId || '').trim() || 'unknown',
        timeoutSeconds
      });
      if (acquired === true) {
        return true;
      }
      ownerTransferLocksByOrgId.delete(normalizedOrgId);
      return false;
    } catch (_error) {
      ownerTransferLocksByOrgId.delete(normalizedOrgId);
      throw errors.ownerTransferLockUnavailable();
    }
  };

  const releaseOwnerTransferLock = async ({
    orgId
  } = {}) => {
    const normalizedOrgId = String(orgId || '').trim();
    if (!normalizedOrgId) {
      return false;
    }
    ownerTransferLocksByOrgId.delete(normalizedOrgId);
    if (!authStore || typeof authStore.releaseOwnerTransferLock !== 'function') {
      return false;
    }
    try {
      const released = await authStore.releaseOwnerTransferLock({
        orgId: normalizedOrgId
      });
      return released === true;
    } catch (_error) {
      return false;
    }
  };

  const validateOwnerTransferRequest = async ({
    requestId,
    orgId,
    newOwnerPhone,
    operatorUserId,
    operatorSessionId,
    reason = null
  }) => {
    const normalizedRequestId = String(requestId || '').trim() || 'request_id_unset';

    if (typeof orgId !== 'string' || typeof newOwnerPhone !== 'string') {
      throw errors.invalidPayload();
    }
    const normalizedOrgId = orgId.trim();
    if (
      !normalizedOrgId
      || normalizedOrgId !== orgId
      || WHITESPACE_PATTERN.test(normalizedOrgId)
      || CONTROL_CHAR_PATTERN.test(normalizedOrgId)
      || normalizedOrgId.length > MAX_OWNER_TRANSFER_ORG_ID_LENGTH
    ) {
      throw errors.invalidPayload();
    }
    const normalizedNewOwnerPhone = normalizePhone(newOwnerPhone);
    if (!normalizedNewOwnerPhone || normalizedNewOwnerPhone !== newOwnerPhone) {
      throw errors.invalidPayload();
    }

    const normalizedOperatorUserId = String(operatorUserId || '').trim();
    const normalizedOperatorSessionId = String(operatorSessionId || '').trim();
    let normalizedReason = null;
    if (reason !== null && reason !== undefined) {
      if (typeof reason !== 'string') {
        throw errors.invalidPayload();
      }
      const trimmedReason = reason.trim();
      if (!trimmedReason || trimmedReason !== reason) {
        throw errors.invalidPayload();
      }
      if (CONTROL_CHAR_PATTERN.test(trimmedReason)) {
        throw errors.invalidPayload();
      }
      if (trimmedReason.length > MAX_OWNER_TRANSFER_REASON_LENGTH) {
        throw errors.invalidPayload();
      }
      normalizedReason = trimmedReason;
    }

    if (
      !normalizedOrgId
      || !normalizedNewOwnerPhone
      || !normalizedOperatorUserId
      || !normalizedOperatorSessionId
    ) {
      throw errors.invalidPayload();
    }

    assertStoreMethod(authStore, 'findOrganizationById', 'authStore');
    assertStoreMethod(authStore, 'findUserByPhone', 'authStore');

    const org = await authStore.findOrganizationById({
      orgId: normalizedOrgId
    });
    if (!org) {
      throw errors.orgNotFound();
    }

    const oldOwnerUserId = String(
      org.owner_user_id || org.ownerUserId || ''
    ).trim();
    if (!oldOwnerUserId) {
      throw errors.invalidPayload();
    }

    const normalizedOrgStatus = normalizeOrgStatus(org.status);
    if (normalizedOrgStatus !== 'active') {
      throw errors.ownerTransferOrgNotActive({
        orgId: normalizedOrgId,
        oldOwnerUserId
      });
    }

    const candidateOwner = await authStore.findUserByPhone(normalizedNewOwnerPhone);
    if (!candidateOwner) {
      throw errors.userNotFound({
        extensions: {
          org_id: normalizedOrgId,
          old_owner_user_id: oldOwnerUserId
        }
      });
    }

    const newOwnerUserId = String(
      candidateOwner.id || candidateOwner.user_id || ''
    ).trim();
    if (!newOwnerUserId) {
      throw errors.invalidPayload();
    }
    if (!isUserActive(candidateOwner)) {
      throw errors.ownerTransferTargetUserInactive({
        orgId: normalizedOrgId,
        oldOwnerUserId,
        newOwnerUserId
      });
    }
    if (newOwnerUserId === oldOwnerUserId) {
      throw errors.ownerTransferSameOwner({
        orgId: normalizedOrgId,
        oldOwnerUserId
      });
    }

    addAuditEvent({
      type: 'auth.org.owner_transfer.validated',
      requestId: normalizedRequestId,
      userId: normalizedOperatorUserId,
      sessionId: normalizedOperatorSessionId,
      detail: 'owner transfer request validated',
      metadata: {
        org_id: normalizedOrgId,
        old_owner_user_id: oldOwnerUserId,
        new_owner_user_id: newOwnerUserId,
        new_owner_phone_masked: maskPhone(normalizedNewOwnerPhone),
        reason: normalizedReason
      }
    });

    return {
      org_id: normalizedOrgId,
      old_owner_user_id: oldOwnerUserId,
      new_owner_user_id: newOwnerUserId
    };
  };

  const executeOwnerTransferTakeover = async ({
    requestId,
    traceparent = null,
    orgId,
    newOwnerPhone,
    operatorUserId,
    operatorSessionId,
    reason = null
  }) => {
    const normalizedRequestId = String(requestId || '').trim() || 'request_id_unset';
    const normalizedReason = reason === null || reason === undefined
      ? null
      : String(reason || '').trim() || null;

    const validationResult = await validateOwnerTransferRequest({
      requestId: normalizedRequestId,
      orgId,
      newOwnerPhone,
      operatorUserId,
      operatorSessionId,
      reason: normalizedReason
    });
    const validatedOrgId = String(validationResult?.org_id || '').trim();
    const validatedOldOwnerUserId = String(
      validationResult?.old_owner_user_id || ''
    ).trim();
    const validatedNewOwnerUserId = String(
      validationResult?.new_owner_user_id || ''
    ).trim();
    if (
      !validatedOrgId
      || !validatedOldOwnerUserId
      || !validatedNewOwnerUserId
    ) {
      throw errors.tenantUserDependencyUnavailable({
        reason: 'owner-transfer-validation-result-invalid'
      });
    }
    const takeoverRoleId = toOwnerTransferTakeoverRoleId({
      orgId: validatedOrgId
    });
    if (!takeoverRoleId) {
      throw errors.tenantUserDependencyUnavailable({
        reason: 'owner-transfer-takeover-role-id-invalid'
      });
    }

    assertStoreMethod(authStore, 'executeOwnerTransferTakeover', 'authStore');
    let takeoverResult = null;
    try {
      takeoverResult = await authStore.executeOwnerTransferTakeover({
        requestId: normalizedRequestId,
        orgId: validatedOrgId,
        oldOwnerUserId: validatedOldOwnerUserId,
        newOwnerUserId: validatedNewOwnerUserId,
        operatorUserId,
        operatorSessionId,
        reason: normalizedReason,
        takeoverRoleId,
        takeoverRoleCode: OWNER_TRANSFER_TAKEOVER_ROLE_CODE,
        takeoverRoleName: OWNER_TRANSFER_TAKEOVER_ROLE_NAME,
        requiredPermissionCodes: [...OWNER_TRANSFER_TAKEOVER_REQUIRED_PERMISSION_CODES],
        auditContext: {
          requestId: normalizedRequestId,
          traceparent: normalizeAuditStringOrNull(traceparent, 128),
          actorUserId: normalizeAuditStringOrNull(operatorUserId, 64),
          actorSessionId: normalizeAuditStringOrNull(operatorSessionId, 128),
          reason: normalizedReason
        }
      });
    } catch (error) {
      if (error instanceof AuthProblemError) {
        throw error;
      }
      const normalizedStoreErrorCode = String(error?.code || '').trim();
      if (normalizedStoreErrorCode === 'ERR_OWNER_TRANSFER_TAKEOVER_ORG_NOT_FOUND') {
        throw errors.orgNotFound();
      }
      if (normalizedStoreErrorCode === 'ERR_OWNER_TRANSFER_TAKEOVER_ORG_NOT_ACTIVE') {
        throw errors.ownerTransferOrgNotActive({
          orgId: validatedOrgId,
          oldOwnerUserId: validatedOldOwnerUserId
        });
      }
      if (normalizedStoreErrorCode === 'ERR_OWNER_TRANSFER_TAKEOVER_SAME_OWNER') {
        throw errors.ownerTransferSameOwner({
          orgId: validatedOrgId,
          oldOwnerUserId: validatedOldOwnerUserId
        });
      }
      if (normalizedStoreErrorCode === 'ERR_OWNER_TRANSFER_TAKEOVER_NEW_OWNER_NOT_FOUND') {
        throw errors.userNotFound({
          extensions: {
            org_id: validatedOrgId,
            old_owner_user_id: validatedOldOwnerUserId
          }
        });
      }
      if (normalizedStoreErrorCode === 'ERR_OWNER_TRANSFER_TAKEOVER_NEW_OWNER_INACTIVE') {
        throw errors.ownerTransferTargetUserInactive({
          orgId: validatedOrgId,
          oldOwnerUserId: validatedOldOwnerUserId,
          newOwnerUserId: validatedNewOwnerUserId
        });
      }
      if (normalizedStoreErrorCode === 'ERR_OWNER_TRANSFER_TAKEOVER_ROLE_INVALID') {
        throw errors.tenantUserDependencyUnavailable({
          reason: 'owner-transfer-takeover-role-invalid'
        });
      }
      if (normalizedStoreErrorCode === 'ERR_OWNER_TRANSFER_TAKEOVER_PRECONDITION_FAILED') {
        throw errors.ownerTransferConflict({
          orgId: validatedOrgId,
          oldOwnerUserId: validatedOldOwnerUserId,
          newOwnerUserId: validatedNewOwnerUserId
        });
      }
      if (normalizedStoreErrorCode === 'ERR_AUDIT_WRITE_FAILED') {
        throw errors.tenantUserDependencyUnavailable({
          reason: 'audit-write-failed'
        });
      }
      throw errors.tenantUserDependencyUnavailable({
        reason: normalizedStoreErrorCode
          || String(error?.message || 'owner-transfer-takeover-write-failed').trim()
          || 'owner-transfer-takeover-write-failed'
      });
    }

    const resolvedOrgId = String(takeoverResult?.org_id || '').trim();
    const resolvedOldOwnerUserId = String(
      takeoverResult?.old_owner_user_id || ''
    ).trim();
    const resolvedNewOwnerUserId = String(
      takeoverResult?.new_owner_user_id || ''
    ).trim();
    if (
      !resolvedOrgId
      || !resolvedOldOwnerUserId
      || !resolvedNewOwnerUserId
      || resolvedOrgId !== validatedOrgId
      || resolvedOldOwnerUserId !== validatedOldOwnerUserId
      || resolvedNewOwnerUserId !== validatedNewOwnerUserId
    ) {
      throw errors.tenantUserDependencyUnavailable({
        reason: 'owner-transfer-takeover-result-invalid'
      });
    }

    invalidateSessionCacheByUserId(resolvedNewOwnerUserId);
    addAuditEvent({
      type: 'auth.org.owner_transfer.executed',
      requestId: normalizedRequestId,
      userId: String(operatorUserId || '').trim() || 'unknown',
      sessionId: String(operatorSessionId || '').trim() || 'unknown',
      detail: 'owner transfer takeover committed',
      metadata: {
        org_id: resolvedOrgId,
        old_owner_user_id: resolvedOldOwnerUserId,
        new_owner_user_id: resolvedNewOwnerUserId
      }
    });
    const storeAuditRecorded = (
      takeoverResult?.auditRecorded === true
      || takeoverResult?.audit_recorded === true
    );
    if (!storeAuditRecorded) {
      await recordPersistentAuditEvent({
        domain: 'tenant',
        tenantId: resolvedOrgId,
        requestId: normalizedRequestId,
        traceparent: normalizeAuditStringOrNull(traceparent, 128),
        eventType: 'auth.org.owner_transfer.executed',
        actorUserId: normalizeAuditStringOrNull(operatorUserId, 64),
        actorSessionId: normalizeAuditStringOrNull(operatorSessionId, 128),
        targetType: 'org',
        targetId: resolvedOrgId,
        result: 'success',
        beforeState: {
          owner_user_id: resolvedOldOwnerUserId
        },
        afterState: {
          owner_user_id: resolvedNewOwnerUserId
        },
        metadata: {
          old_owner_user_id: resolvedOldOwnerUserId,
          new_owner_user_id: resolvedNewOwnerUserId,
          reason: normalizedReason
        }
      });
    }

    return {
      org_id: resolvedOrgId,
      old_owner_user_id: resolvedOldOwnerUserId,
      new_owner_user_id: resolvedNewOwnerUserId
    };
  };

  return {
    acquireOwnerTransferLock,
    releaseOwnerTransferLock,
    validateOwnerTransferRequest,
    executeOwnerTransferTakeover
  };
};

module.exports = {
  createPlatformOwnerTransferGovernanceCapabilities
};
