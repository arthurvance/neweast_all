'use strict';

const createPlatformMemoryAuthStoreSystemConfigWrite = ({
  repositoryMethods
} = {}) => ({
  upsertSystemSensitiveConfig: repositoryMethods.upsertSystemSensitiveConfig
});

module.exports = {
  createPlatformMemoryAuthStoreSystemConfigWrite
};
