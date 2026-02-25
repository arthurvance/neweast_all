const { createOptionalDelegate } = require('./repository-helpers');

const createAuthTenantUsershipRepository = ({ authStore } = {}) => {
  const repository = {};
  const optionalMethodNames = [
    'listTenantOptionsByUserId'
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
  createAuthTenantUsershipRepository
};
