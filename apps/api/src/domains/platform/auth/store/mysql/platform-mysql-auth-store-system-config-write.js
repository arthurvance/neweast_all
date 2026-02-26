'use strict';

const createPlatformMysqlAuthStoreSystemConfigWrite = ({
  repositoryMethods
} = {}) => ({
  upsertSystemSensitiveConfig: repositoryMethods.upsertSystemSensitiveConfig
});

module.exports = {
  createPlatformMysqlAuthStoreSystemConfigWrite
};
