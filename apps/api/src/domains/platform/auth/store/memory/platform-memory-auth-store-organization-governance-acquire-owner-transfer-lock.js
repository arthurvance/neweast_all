'use strict';

const createPlatformMemoryAuthStoreOrganizationGovernanceAcquireOwnerTransferLock = ({
  ownerTransferLocksByOrgId
} = {}) => ({
acquireOwnerTransferLock: async ({
      orgId,
      requestId,
      operatorUserId
    }) => {
      const normalizedOrgId = String(orgId || '').trim();
      if (!normalizedOrgId) {
        return false;
      }
      if (ownerTransferLocksByOrgId.has(normalizedOrgId)) {
        return false;
      }
      ownerTransferLocksByOrgId.set(normalizedOrgId, {
        request_id: String(requestId || '').trim() || 'request_id_unset',
        operator_user_id: String(operatorUserId || '').trim() || 'unknown',
        started_at: new Date().toISOString()
      });
      return true;
    }
});

module.exports = {
  createPlatformMemoryAuthStoreOrganizationGovernanceAcquireOwnerTransferLock
};
