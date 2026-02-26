'use strict';

const createPlatformMemoryAuthStoreSystemConfigRead = ({
  repositoryMethods
} = {}) => ({
  getSystemSensitiveConfig: repositoryMethods.getSystemSensitiveConfig
});

module.exports = {
  createPlatformMemoryAuthStoreSystemConfigRead
};
