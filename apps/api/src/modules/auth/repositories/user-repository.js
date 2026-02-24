const {
  createRequiredDelegate,
  createOptionalDelegate
} = require('./repository-helpers');

const createAuthUserRepository = ({ authStore } = {}) => {
  const repositoryName = 'createAuthUserRepository';
  const repository = {
    findUserByPhone: createRequiredDelegate(
      authStore,
      'findUserByPhone',
      repositoryName
    ),
    findUserById: createRequiredDelegate(
      authStore,
      'findUserById',
      repositoryName
    )
  };

  const getPlatformUserById = createOptionalDelegate(authStore, 'getPlatformUserById');
  if (getPlatformUserById) {
    repository.getPlatformUserById = getPlatformUserById;
  }

  return Object.freeze(repository);
};

module.exports = {
  createAuthUserRepository
};
