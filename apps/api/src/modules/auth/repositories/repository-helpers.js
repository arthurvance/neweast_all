const assertAuthStoreMethod = (authStore, methodName, repositoryName) => {
  if (!authStore || typeof authStore[methodName] !== 'function') {
    throw new Error(
      `${repositoryName} requires authStore.${methodName} to be a function`
    );
  }
};

const createRequiredDelegate = (authStore, methodName, repositoryName) => {
  return (...args) => {
    assertAuthStoreMethod(authStore, methodName, repositoryName);
    return authStore[methodName](...args);
  };
};

const createOptionalDelegate = (authStore, methodName) => {
  if (!authStore || typeof authStore[methodName] !== 'function') {
    return null;
  }
  return (...args) => authStore[methodName](...args);
};

module.exports = {
  assertAuthStoreMethod,
  createRequiredDelegate,
  createOptionalDelegate
};
