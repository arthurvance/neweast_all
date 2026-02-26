'use strict';

const {
  createPlatformMysqlAuthStoreRoleCatalogReadRepositoryProjection
} = require('./platform-mysql-auth-store-role-catalog-read-repository-projection.js');
const {
  createPlatformMysqlAuthStoreRoleCatalogListUserIdsByPlatformRoleId
} = require('./platform-mysql-auth-store-role-catalog-list-user-ids-by-platform-role-id.js');
const {
  createPlatformMysqlAuthStoreRoleCatalogListPlatformRoleFactsByUserId
} = require('./platform-mysql-auth-store-role-catalog-list-platform-role-facts-by-user-id.js');
const {
  createPlatformMysqlAuthStoreRoleCatalogCreatePlatformRoleCatalogEntry
} = require('./platform-mysql-auth-store-role-catalog-create-platform-role-catalog-entry.js');
const {
  createPlatformMysqlAuthStoreRoleCatalogUpdatePlatformRoleCatalogEntry
} = require('./platform-mysql-auth-store-role-catalog-update-platform-role-catalog-entry.js');
const {
  createPlatformMysqlAuthStoreRoleCatalogDeletePlatformRoleCatalogEntry
} = require('./platform-mysql-auth-store-role-catalog-delete-platform-role-catalog-entry.js');

const createPlatformMysqlAuthStoreRoleCatalog = (dependencies = {}) => ({
  ...createPlatformMysqlAuthStoreRoleCatalogReadRepositoryProjection(dependencies),
  ...createPlatformMysqlAuthStoreRoleCatalogListUserIdsByPlatformRoleId(dependencies),
  ...createPlatformMysqlAuthStoreRoleCatalogListPlatformRoleFactsByUserId(dependencies),
  ...createPlatformMysqlAuthStoreRoleCatalogCreatePlatformRoleCatalogEntry(dependencies),
  ...createPlatformMysqlAuthStoreRoleCatalogUpdatePlatformRoleCatalogEntry(dependencies),
  ...createPlatformMysqlAuthStoreRoleCatalogDeletePlatformRoleCatalogEntry(dependencies),
});

module.exports = {
  createPlatformMysqlAuthStoreRoleCatalog
};
