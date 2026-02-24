const {
  createRequiredDelegate,
  createOptionalDelegate
} = require('./repository-helpers');

const createAuthSessionRepository = ({ authStore } = {}) => {
  const repositoryName = 'createAuthSessionRepository';
  const repository = {
    createSession: createRequiredDelegate(authStore, 'createSession', repositoryName),
    createRefreshToken: createRequiredDelegate(
      authStore,
      'createRefreshToken',
      repositoryName
    ),
    findSessionById: createRequiredDelegate(authStore, 'findSessionById', repositoryName)
  };

  const updateSessionContext = createOptionalDelegate(authStore, 'updateSessionContext');
  if (updateSessionContext) {
    repository.updateSessionContext = updateSessionContext;
  }

  return Object.freeze(repository);
};

module.exports = {
  createAuthSessionRepository
};
