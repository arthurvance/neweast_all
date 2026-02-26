'use strict';

const createPlatformOrgOnboardingCapabilities = ({
  authStore,
  errors,
  randomUUID,
  assertStoreMethod,
  isPlainObject,
  resolveRawCamelSnakeField,
  normalizeAuditStringOrNull,
  recordPersistentAuditEvent,
  MAX_TENANT_USER_DISPLAY_NAME_LENGTH,
  CONTROL_CHAR_PATTERN
} = {}) => {
  const createOrganizationWithOwner = async ({
    requestId = 'request_id_unset',
    traceparent = null,
    orgId = randomUUID(),
    orgName,
    ownerDisplayName = null,
    ownerUserId,
    operatorUserId,
    operatorSessionId = null
  }) => {
    const normalizedRequestId =
      normalizeAuditStringOrNull(requestId, 128) || 'request_id_unset';
    const normalizedTraceparent = normalizeAuditStringOrNull(traceparent, 128);
    const normalizedOrgId = normalizeAuditStringOrNull(orgId, 64) || randomUUID();
    const normalizedOwnerUserId = normalizeAuditStringOrNull(ownerUserId, 64);
    const normalizedOperatorUserId = normalizeAuditStringOrNull(operatorUserId, 64);
    const normalizedOperatorSessionId = normalizeAuditStringOrNull(operatorSessionId, 128);
    const ownerDisplayNameCandidate = ownerDisplayName === null || ownerDisplayName === undefined
      ? null
      : String(ownerDisplayName || '').trim();
    const normalizedOwnerDisplayName = ownerDisplayNameCandidate
      && ownerDisplayNameCandidate.length <= MAX_TENANT_USER_DISPLAY_NAME_LENGTH
      && !CONTROL_CHAR_PATTERN.test(ownerDisplayNameCandidate)
      ? ownerDisplayNameCandidate
      : null;
    assertStoreMethod(authStore, 'createOrganizationWithOwner', 'authStore');
    let createdOrg = null;
    try {
      createdOrg = await authStore.createOrganizationWithOwner({
        orgId: normalizedOrgId,
        orgName,
        ownerDisplayName: normalizedOwnerDisplayName,
        ownerUserId,
        operatorUserId,
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
    if (!isPlainObject(createdOrg)) {
      throw errors.auditDependencyUnavailable({
        reason: 'org-create-result-invalid'
      });
    }
    const resolvedCreatedOrgId = normalizeAuditStringOrNull(
      resolveRawCamelSnakeField(createdOrg, 'orgId', 'org_id'),
      64
    );
    const resolvedCreatedOwnerUserId = normalizeAuditStringOrNull(
      resolveRawCamelSnakeField(createdOrg, 'ownerUserId', 'owner_user_id'),
      64
    );
    if (!resolvedCreatedOrgId || !resolvedCreatedOwnerUserId) {
      throw errors.auditDependencyUnavailable({
        reason: 'org-create-result-invalid'
      });
    }
    if (
      resolvedCreatedOrgId !== normalizedOrgId
      || resolvedCreatedOwnerUserId !== normalizedOwnerUserId
    ) {
      throw errors.auditDependencyUnavailable({
        reason: 'org-create-result-target-mismatch'
      });
    }
    const storeAuditRecorded = (
      createdOrg?.auditRecorded === true
      || createdOrg?.audit_recorded === true
    );
    if (!storeAuditRecorded) {
      await recordPersistentAuditEvent({
        domain: 'tenant',
        tenantId: normalizedOrgId,
        requestId: normalizedRequestId,
        traceparent: normalizedTraceparent,
        eventType: 'auth.org.create.succeeded',
        actorUserId: normalizedOperatorUserId,
        actorSessionId: normalizedOperatorSessionId,
        targetType: 'org',
        targetId: normalizedOrgId,
        result: 'success',
        beforeState: null,
        afterState: {
          org_id: resolvedCreatedOrgId,
          org_name: normalizeAuditStringOrNull(orgName, 128),
          owner_user_id: resolvedCreatedOwnerUserId
        },
        metadata: {
          operator_user_id: normalizedOperatorUserId
        }
      });
    }
    const createdOrgResponse = {
      ...(createdOrg || {})
    };
    delete createdOrgResponse.auditRecorded;
    delete createdOrgResponse.audit_recorded;
    return createdOrgResponse;
  };

  return {
    createOrganizationWithOwner
  };
};

module.exports = {
  createPlatformOrgOnboardingCapabilities
};
