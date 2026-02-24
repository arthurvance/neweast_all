const { createOptionalDelegate } = require('./repository-helpers');

const createAuthPermissionRepository = ({ authStore } = {}) => {
  const repository = {};
  const optionalMethodNames = [
    'syncPlatformPermissionSnapshotByUserId',
    'findPlatformPermissionByUserId',
    'hasPlatformPermissionByUserId',
    'findTenantPermissionByUserAndTenantId'
  ];

  for (const methodName of optionalMethodNames) {
    const delegate = createOptionalDelegate(authStore, methodName);
    if (delegate) {
      repository[methodName] = delegate;
    }
  }

  return Object.freeze(repository);
};

module.exports = {
  createAuthPermissionRepository
};
