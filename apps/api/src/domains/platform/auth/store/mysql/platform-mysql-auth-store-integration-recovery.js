'use strict';

const {
  createPlatformMysqlAuthStoreIntegrationRecoveryListPlatformIntegrationRecoveryQueueEntries
} = require('./platform-mysql-auth-store-integration-recovery-list-platform-integration-recovery-queue-entries.js');
const {
  createPlatformMysqlAuthStoreIntegrationRecoveryFindPlatformIntegrationRecoveryQueueEntryByRecoveryId
} = require('./platform-mysql-auth-store-integration-recovery-find-platform-integration-recovery-queue-entry-by-recovery-id.js');
const {
  createPlatformMysqlAuthStoreIntegrationRecoveryUpsertPlatformIntegrationRecoveryQueueEntry
} = require('./platform-mysql-auth-store-integration-recovery-upsert-platform-integration-recovery-queue-entry.js');
const {
  createPlatformMysqlAuthStoreIntegrationRecoveryClaimNextDuePlatformIntegrationRecoveryQueueEntry
} = require('./platform-mysql-auth-store-integration-recovery-claim-next-due-platform-integration-recovery-queue-entry.js');
const {
  createPlatformMysqlAuthStoreIntegrationRecoveryCompletePlatformIntegrationRecoveryQueueAttempt
} = require('./platform-mysql-auth-store-integration-recovery-complete-platform-integration-recovery-queue-attempt.js');
const {
  createPlatformMysqlAuthStoreIntegrationRecoveryReplayPlatformIntegrationRecoveryQueueEntry
} = require('./platform-mysql-auth-store-integration-recovery-replay-platform-integration-recovery-queue-entry.js');

const createPlatformMysqlAuthStoreIntegrationRecovery = (dependencies = {}) => ({
  ...createPlatformMysqlAuthStoreIntegrationRecoveryListPlatformIntegrationRecoveryQueueEntries(dependencies),
  ...createPlatformMysqlAuthStoreIntegrationRecoveryFindPlatformIntegrationRecoveryQueueEntryByRecoveryId(dependencies),
  ...createPlatformMysqlAuthStoreIntegrationRecoveryUpsertPlatformIntegrationRecoveryQueueEntry(dependencies),
  ...createPlatformMysqlAuthStoreIntegrationRecoveryClaimNextDuePlatformIntegrationRecoveryQueueEntry(dependencies),
  ...createPlatformMysqlAuthStoreIntegrationRecoveryCompletePlatformIntegrationRecoveryQueueAttempt(dependencies),
  ...createPlatformMysqlAuthStoreIntegrationRecoveryReplayPlatformIntegrationRecoveryQueueEntry(dependencies),
});

module.exports = {
  createPlatformMysqlAuthStoreIntegrationRecovery
};
