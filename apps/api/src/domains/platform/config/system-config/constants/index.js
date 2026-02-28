const PLATFORM_SYSTEM_CONFIG_ITEM_PATH = '/platform/system-configs/:key';
const PLATFORM_SYSTEM_CONFIG_GET_ROUTE_KEY = 'GET /platform/system-configs/:key';
const PLATFORM_SYSTEM_CONFIG_PUT_ROUTE_KEY = 'PUT /platform/system-configs/:key';
const PLATFORM_SYSTEM_CONFIG_VIEW_PERMISSION_CODE = 'platform.role_management.view';
const PLATFORM_SYSTEM_CONFIG_OPERATE_PERMISSION_CODE = 'platform.role_management.operate';
const PLATFORM_SYSTEM_CONFIG_SCOPE = 'platform';
const PLATFORM_SYSTEM_CONFIG_ALLOWED_KEYS = Object.freeze([
  'auth.default_password',
  'auth.access_ttl_seconds',
  'auth.refresh_ttl_seconds',
  'auth.otp_ttl_seconds',
  'auth.rate_limit_window_seconds',
  'auth.rate_limit_max_attempts'
]);

module.exports = {
  PLATFORM_SYSTEM_CONFIG_ITEM_PATH,
  PLATFORM_SYSTEM_CONFIG_GET_ROUTE_KEY,
  PLATFORM_SYSTEM_CONFIG_PUT_ROUTE_KEY,
  PLATFORM_SYSTEM_CONFIG_VIEW_PERMISSION_CODE,
  PLATFORM_SYSTEM_CONFIG_OPERATE_PERMISSION_CODE,
  PLATFORM_SYSTEM_CONFIG_SCOPE,
  PLATFORM_SYSTEM_CONFIG_ALLOWED_KEYS
};
