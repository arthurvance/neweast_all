const { createOptionalDelegate } = require('./repository-helpers');

const createAuthDomainAccessRepository = ({ authStore } = {}) => {
  const repository = {};
  const optionalMethodNames = [
    'findDomainAccessByUserId',
    'ensureDefaultDomainAccessForUser',
    'ensureTenantDomainAccessForUser',
    'hasAnyTenantRelationshipByUserId'
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
  createAuthDomainAccessRepository
};
