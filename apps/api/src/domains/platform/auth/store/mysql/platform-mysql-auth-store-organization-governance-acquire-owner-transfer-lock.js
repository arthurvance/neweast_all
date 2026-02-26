'use strict';

const createPlatformMysqlAuthStoreOrganizationGovernanceAcquireOwnerTransferLock = ({
  dbClient,
  normalizeOwnerTransferLockTimeoutSeconds,
  toOwnerTransferLockName
} = {}) => ({
acquireOwnerTransferLock: async ({
      orgId,
      timeoutSeconds = 0
    }) => {
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
          SELECT GET_LOCK(?, ?) AS lock_acquired
        `,
        [
          lockName,
          normalizeOwnerTransferLockTimeoutSeconds(timeoutSeconds)
        ]
      );
      return Number(rows?.[0]?.lock_acquired || 0) === 1;
    }
});

module.exports = {
  createPlatformMysqlAuthStoreOrganizationGovernanceAcquireOwnerTransferLock
};
