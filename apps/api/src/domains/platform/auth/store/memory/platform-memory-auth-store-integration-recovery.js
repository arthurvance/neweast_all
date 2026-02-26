'use strict';

const {
  createPlatformMemoryAuthStoreIntegrationRecoveryListPlatformIntegrationRecoveryQueueEntries
} = require('./platform-memory-auth-store-integration-recovery-list-platform-integration-recovery-queue-entries.js');
const {
  createPlatformMemoryAuthStoreIntegrationRecoveryFindPlatformIntegrationRecoveryQueueEntryByRecoveryId
} = require('./platform-memory-auth-store-integration-recovery-find-platform-integration-recovery-queue-entry-by-recovery-id.js');
const {
  createPlatformMemoryAuthStoreIntegrationRecoveryUpsertPlatformIntegrationRecoveryQueueEntry
} = require('./platform-memory-auth-store-integration-recovery-upsert-platform-integration-recovery-queue-entry.js');
const {
  createPlatformMemoryAuthStoreIntegrationRecoveryClaimNextDuePlatformIntegrationRecoveryQueueEntry
} = require('./platform-memory-auth-store-integration-recovery-claim-next-due-platform-integration-recovery-queue-entry.js');
const {
  createPlatformMemoryAuthStoreIntegrationRecoveryCompletePlatformIntegrationRecoveryQueueAttempt
} = require('./platform-memory-auth-store-integration-recovery-complete-platform-integration-recovery-queue-attempt.js');
const {
  createPlatformMemoryAuthStoreIntegrationRecoveryReplayPlatformIntegrationRecoveryQueueEntry
} = require('./platform-memory-auth-store-integration-recovery-replay-platform-integration-recovery-queue-entry.js');

const createPlatformMemoryAuthStoreIntegrationRecovery = (dependencies = {}) => ({
  ...createPlatformMemoryAuthStoreIntegrationRecoveryListPlatformIntegrationRecoveryQueueEntries(dependencies),
  ...createPlatformMemoryAuthStoreIntegrationRecoveryFindPlatformIntegrationRecoveryQueueEntryByRecoveryId(dependencies),
  ...createPlatformMemoryAuthStoreIntegrationRecoveryUpsertPlatformIntegrationRecoveryQueueEntry(dependencies),
  ...createPlatformMemoryAuthStoreIntegrationRecoveryClaimNextDuePlatformIntegrationRecoveryQueueEntry(dependencies),
  ...createPlatformMemoryAuthStoreIntegrationRecoveryCompletePlatformIntegrationRecoveryQueueAttempt(dependencies),
  ...createPlatformMemoryAuthStoreIntegrationRecoveryReplayPlatformIntegrationRecoveryQueueEntry(dependencies),
});

module.exports = {
  createPlatformMemoryAuthStoreIntegrationRecovery
};
