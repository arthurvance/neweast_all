const PLATFORM_INTEGRATION_RECOVERY_QUEUE_PATH =
  '/platform/integrations/:integration_id/recovery/queue';
const PLATFORM_INTEGRATION_RECOVERY_REPLAY_PATH =
  '/platform/integrations/:integration_id/recovery/queue/:recovery_id/replay';

const PLATFORM_INTEGRATION_RECOVERY_QUEUE_ROUTE_KEY =
  'GET /platform/integrations/:integration_id/recovery/queue';
const PLATFORM_INTEGRATION_RECOVERY_REPLAY_ROUTE_KEY =
  'POST /platform/integrations/:integration_id/recovery/queue/:recovery_id/replay';

const PLATFORM_INTEGRATION_RECOVERY_VIEW_PERMISSION_CODE =
  'platform.member_admin.view';
const PLATFORM_INTEGRATION_RECOVERY_OPERATE_PERMISSION_CODE =
  'platform.member_admin.operate';
const PLATFORM_INTEGRATION_RECOVERY_SCOPE = 'platform';

const PLATFORM_INTEGRATION_RECOVERY_STATUS_ENUM = Object.freeze([
  'pending',
  'retrying',
  'succeeded',
  'failed',
  'dlq',
  'replayed'
]);

module.exports = {
  PLATFORM_INTEGRATION_RECOVERY_QUEUE_PATH,
  PLATFORM_INTEGRATION_RECOVERY_REPLAY_PATH,
  PLATFORM_INTEGRATION_RECOVERY_QUEUE_ROUTE_KEY,
  PLATFORM_INTEGRATION_RECOVERY_REPLAY_ROUTE_KEY,
  PLATFORM_INTEGRATION_RECOVERY_VIEW_PERMISSION_CODE,
  PLATFORM_INTEGRATION_RECOVERY_OPERATE_PERMISSION_CODE,
  PLATFORM_INTEGRATION_RECOVERY_SCOPE,
  PLATFORM_INTEGRATION_RECOVERY_STATUS_ENUM
};
