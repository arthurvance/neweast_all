'use strict';

const createPlatformMysqlAuthStoreRoleCatalogReadRepositoryProjection = ({
  repositoryMethods
} = {}) => ({
  countPlatformRoleCatalogEntries: repositoryMethods.countPlatformRoleCatalogEntries,
  listPlatformRoleCatalogEntries: repositoryMethods.listPlatformRoleCatalogEntries,
  findPlatformRoleCatalogEntryByRoleId: repositoryMethods.findPlatformRoleCatalogEntryByRoleId,
  findPlatformRoleCatalogEntriesByRoleIds: repositoryMethods.findPlatformRoleCatalogEntriesByRoleIds
});

module.exports = {
  createPlatformMysqlAuthStoreRoleCatalogReadRepositoryProjection
};
