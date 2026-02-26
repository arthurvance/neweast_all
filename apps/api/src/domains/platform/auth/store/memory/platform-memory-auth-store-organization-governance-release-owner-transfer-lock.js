'use strict';

const createPlatformMemoryAuthStoreOrganizationGovernanceReleaseOwnerTransferLock = ({
  ownerTransferLocksByOrgId
} = {}) => ({
releaseOwnerTransferLock: async ({ orgId }) => {
      const normalizedOrgId = String(orgId || '').trim();
      if (!normalizedOrgId) {
        return false;
      }
      return ownerTransferLocksByOrgId.delete(normalizedOrgId);
    }
});

module.exports = {
  createPlatformMemoryAuthStoreOrganizationGovernanceReleaseOwnerTransferLock
};
