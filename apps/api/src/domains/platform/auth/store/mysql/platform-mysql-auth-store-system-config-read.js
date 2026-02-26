'use strict';

const createPlatformMysqlAuthStoreSystemConfigRead = ({
  repositoryMethods
} = {}) => ({
  getSystemSensitiveConfig: repositoryMethods.getSystemSensitiveConfig
});

module.exports = {
  createPlatformMysqlAuthStoreSystemConfigRead
};
