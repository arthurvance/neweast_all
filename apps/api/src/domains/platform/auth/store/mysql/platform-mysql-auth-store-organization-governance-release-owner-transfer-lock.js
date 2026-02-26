'use strict';

const createPlatformMysqlAuthStoreOrganizationGovernanceReleaseOwnerTransferLock = ({
  dbClient,
  toOwnerTransferLockName
} = {}) => ({
releaseOwnerTransferLock: async ({ orgId }) => {
      const normalizedOrgId = String(orgId || '').trim();
      if (!normalizedOrgId) {
        return false;
      }
      const lockName = toOwnerTransferLockName(normalizedOrgId);
      if (!lockName) {
        return false;
      }
      const rows = await dbClient.query(
        `
          SELECT RELEASE_LOCK(?) AS lock_released
        `,
        [lockName]
      );
      return Number(rows?.[0]?.lock_released || 0) === 1;
    }
});

module.exports = {
  createPlatformMysqlAuthStoreOrganizationGovernanceReleaseOwnerTransferLock
};
