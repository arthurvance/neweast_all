'use strict';

const { log } = require('../../../../../common/logger');
const { AuthProblemError } = require('../../../../../shared-kernel/auth/auth-problem-error');
const {
  resolveRoutePreauthorizedContext
} = require('../../../../../shared-kernel/auth/route-authz');
const {
  PLATFORM_SYSTEM_CONFIG_VIEW_PERMISSION_CODE,
  PLATFORM_SYSTEM_CONFIG_OPERATE_PERMISSION_CODE,
  PLATFORM_SYSTEM_CONFIG_SCOPE,
  PLATFORM_SYSTEM_CONFIG_ALLOWED_KEYS
} = require('../constants');

const CONTROL_CHAR_PATTERN = /[\u0000-\u001F\u007F]/;

const MAX_AUDIT_TRAIL_ENTRIES = 200;

const SYSTEM_CONFIG_ENVELOPE_VERSION = 'enc:v1';
const DEFAULT_PASSWORD_CONFIG_KEY = 'auth.default_password';
const ACCESS_TTL_SECONDS_CONFIG_KEY = 'auth.access_ttl_seconds';
const REFRESH_TTL_SECONDS_CONFIG_KEY = 'auth.refresh_ttl_seconds';
const OTP_TTL_SECONDS_CONFIG_KEY = 'auth.otp_ttl_seconds';
const RATE_LIMIT_WINDOW_SECONDS_CONFIG_KEY = 'auth.rate_limit_window_seconds';
const RATE_LIMIT_MAX_ATTEMPTS_CONFIG_KEY = 'auth.rate_limit_max_attempts';
const MAX_RUNTIME_AUTH_NUMERIC_CONFIG = 2147483647;

const BASE64URL_SEGMENT_PATTERN = /^[A-Za-z0-9_-]+$/;

const MYSQL_DUP_ENTRY_ERRNO = 1062;

const UPDATE_SYSTEM_CONFIG_ALLOWED_FIELDS = new Set([
  'value',
  'expected_version',
  'status',
  'remark'
]);

const VALID_SYSTEM_CONFIG_STATUS = new Set(['active', 'disabled']);

const ALLOWED_CONFIG_KEY_SET = new Set(
  PLATFORM_SYSTEM_CONFIG_ALLOWED_KEYS.map((configKey) =>
    String(configKey || '').trim().toLowerCase()
  )
);
const RUNTIME_AUTH_NUMERIC_CONFIG_KEY_SET = new Set([
  ACCESS_TTL_SECONDS_CONFIG_KEY,
  REFRESH_TTL_SECONDS_CONFIG_KEY,
  OTP_TTL_SECONDS_CONFIG_KEY,
  RATE_LIMIT_WINDOW_SECONDS_CONFIG_KEY,
  RATE_LIMIT_MAX_ATTEMPTS_CONFIG_KEY
]);

const isPlainObject = (candidate) =>
  candidate !== null
  && typeof candidate === 'object'
  && !Array.isArray(candidate);

const normalizeStrictRequiredString = (candidate) => {
  if (typeof candidate !== 'string') {
    return '';
  }
  const normalized = candidate.trim();
  if (!normalized || candidate !== normalized) {
    return '';
  }
  return normalized;
};

const normalizeConfigKey = (configKey) =>
  normalizeStrictRequiredString(configKey).toLowerCase();

const isWhitelistedConfigKey = (configKey) =>
  ALLOWED_CONFIG_KEY_SET.has(normalizeConfigKey(configKey));

const normalizeConfigStatus = (status) => {
  const normalizedStatus = String(status || 'active').trim().toLowerCase();
  if (normalizedStatus === 'enabled') {
    return 'active';
  }
  return VALID_SYSTEM_CONFIG_STATUS.has(normalizedStatus)
    ? normalizedStatus
    : '';
};

const isValidEncryptedEnvelope = (encryptedValue) => {
  const normalized = String(encryptedValue || '').trim();
  const sections = normalized.split(':');
  if (
    sections.length !== 5
    || `${sections[0]}:${sections[1]}` !== SYSTEM_CONFIG_ENVELOPE_VERSION
  ) {
    return false;
  }
  if (
    !BASE64URL_SEGMENT_PATTERN.test(sections[2] || '')
    || !BASE64URL_SEGMENT_PATTERN.test(sections[3] || '')
    || !BASE64URL_SEGMENT_PATTERN.test(sections[4] || '')
  ) {
    return false;
  }
  const iv = Buffer.from(sections[2], 'base64url');
  const authTag = Buffer.from(sections[3], 'base64url');
  const cipherText = Buffer.from(sections[4], 'base64url');
  return iv.length === 12 && authTag.length === 16 && cipherText.length > 0;
};

const parsePositiveIntegerConfigValue = (rawValue) => {
  const normalizedRawValue = String(rawValue || '').trim();
  if (!/^\d+$/.test(normalizedRawValue)) {
    return null;
  }
  const parsed = Number(normalizedRawValue);
  if (
    !Number.isInteger(parsed)
    || parsed <= 0
    || parsed > MAX_RUNTIME_AUTH_NUMERIC_CONFIG
  ) {
    return null;
  }
  return parsed;
};

const normalizeSystemConfigValueForKey = ({
  configKey,
  value
} = {}) => {
  const normalizedConfigKey = normalizeConfigKey(configKey);
  const normalizedValue = String(value || '').trim();
  if (normalizedConfigKey === DEFAULT_PASSWORD_CONFIG_KEY) {
    if (!isValidEncryptedEnvelope(normalizedValue)) {
      return {
        normalizedValue: '',
        detail: 'value 必须为有效 enc:v1 密文信封'
      };
    }
    return {
      normalizedValue,
      detail: ''
    };
  }
  if (RUNTIME_AUTH_NUMERIC_CONFIG_KEY_SET.has(normalizedConfigKey)) {
    const parsedNumericValue = parsePositiveIntegerConfigValue(normalizedValue);
    if (parsedNumericValue === null) {
      return {
        normalizedValue: '',
        detail: 'value 必须为大于 0 的整数'
      };
    }
    return {
      normalizedValue: String(parsedNumericValue),
      detail: ''
    };
  }
  return {
    normalizedValue: '',
    detail: 'key 非受控白名单项'
  };
};

const toIsoTimestamp = (value) => {
  if (value instanceof Date) {
    return value.toISOString();
  }
  const normalized = normalizeStrictRequiredString(value);
  if (normalized) {
    return normalized;
  }
  return new Date().toISOString();
};

const systemConfigProblem = ({
  status,
  title,
  detail,
  errorCode,
  extensions = {}
}) =>
  new AuthProblemError({
    status,
    title,
    detail,
    errorCode,
    extensions
  });

const systemConfigErrors = {
  invalidPayload: (detail = '请求参数不完整或格式错误') =>
    systemConfigProblem({
      status: 400,
      title: 'Bad Request',
      detail,
      errorCode: 'SYSCFG-400-INVALID-PAYLOAD'
    }),

  configNotFound: ({ configKey = null } = {}) =>
    systemConfigProblem({
      status: 404,
      title: 'Not Found',
      detail: '目标受控配置不存在',
      errorCode: 'SYSCFG-404-CONFIG-NOT-FOUND',
      extensions: {
        retryable: false,
        key: configKey ? String(configKey).trim() : null
      }
    }),

  versionConflict: ({
    configKey = null,
    expectedVersion = null,
    currentVersion = null
  } = {}) =>
    systemConfigProblem({
      status: 409,
      title: 'Conflict',
      detail: '配置版本冲突，请刷新后重试',
      errorCode: 'SYSCFG-409-VERSION-CONFLICT',
      extensions: {
        retryable: true,
        key: configKey ? String(configKey).trim() : null,
        expected_version:
          Number.isInteger(expectedVersion) && expectedVersion >= 0
            ? expectedVersion
            : null,
        current_version:
          Number.isInteger(currentVersion) && currentVersion >= 0
            ? currentVersion
            : null
      }
    }),

  forbidden: () =>
    systemConfigProblem({
      status: 403,
      title: 'Forbidden',
      detail: '当前操作无权限',
      errorCode: 'AUTH-403-FORBIDDEN'
    }),

  dependencyUnavailable: ({ reason = 'dependency-unavailable' } = {}) =>
    systemConfigProblem({
      status: 503,
      title: 'Service Unavailable',
      detail: '受控配置治理依赖暂不可用，请稍后重试',
      errorCode: 'SYSCFG-503-DEPENDENCY-UNAVAILABLE',
      extensions: {
        retryable: true,
        degradation_reason: String(reason || 'dependency-unavailable').trim()
      }
    })
};

const mapAuthorizationError = (error) => {
  if (error instanceof AuthProblemError) {
    return error;
  }
  return systemConfigErrors.dependencyUnavailable({
    reason: 'authorization-dependency-unavailable'
  });
};

const mapUpdateDependencyError = (error, configKey, expectedVersion) => {
  if (error instanceof AuthProblemError) {
    return error;
  }
  const normalizedErrorCode = String(error?.code || '').trim();
  if (
    normalizedErrorCode === 'ERR_SYSTEM_SENSITIVE_CONFIG_VERSION_CONFLICT'
    || normalizedErrorCode === 'ER_DUP_ENTRY'
    || Number(error?.errno || 0) === MYSQL_DUP_ENTRY_ERRNO
  ) {
    const currentVersion = Number(error?.currentVersion ?? error?.current_version);
    return systemConfigErrors.versionConflict({
      configKey,
      expectedVersion,
      currentVersion: Number.isInteger(currentVersion) ? currentVersion : null
    });
  }
  return systemConfigErrors.dependencyUnavailable({
    reason: normalizedErrorCode
      || String(error?.message || 'system-config-update-failed').trim().toLowerCase()
  });
};

const mapReadDependencyError = (error) => {
  if (error instanceof AuthProblemError) {
    return error;
  }
  return systemConfigErrors.dependencyUnavailable({
    reason: String(error?.code || error?.message || 'system-config-read-failed').trim().toLowerCase()
  });
};

const parseUpdatePayload = (
  payload,
  {
    configKey = ''
  } = {}
) => {
  if (!isPlainObject(payload)) {
    throw systemConfigErrors.invalidPayload();
  }

  const unknownPayloadKeys = Object.keys(payload).filter(
    (key) => !UPDATE_SYSTEM_CONFIG_ALLOWED_FIELDS.has(key)
  );
  if (unknownPayloadKeys.length > 0) {
    throw systemConfigErrors.invalidPayload();
  }

  if (!Object.prototype.hasOwnProperty.call(payload, 'value')) {
    throw systemConfigErrors.invalidPayload('value 必填');
  }
  if (!Object.prototype.hasOwnProperty.call(payload, 'expected_version')) {
    throw systemConfigErrors.invalidPayload('expected_version 必填');
  }

  if (typeof payload.value !== 'string') {
    throw systemConfigErrors.invalidPayload('value 必须为字符串');
  }
  const value = payload.value.trim();
  if (
    !value
    || value !== payload.value
    || CONTROL_CHAR_PATTERN.test(value)
  ) {
    throw systemConfigErrors.invalidPayload('value 格式错误');
  }
  const normalizedValueResolution = normalizeSystemConfigValueForKey({
    configKey,
    value
  });
  if (!normalizedValueResolution.detail && !normalizedValueResolution.normalizedValue) {
    throw systemConfigErrors.invalidPayload('value 格式错误');
  }
  if (normalizedValueResolution.detail) {
    throw systemConfigErrors.invalidPayload(normalizedValueResolution.detail);
  }

  if (
    typeof payload.expected_version !== 'number'
    || !Number.isInteger(payload.expected_version)
    || payload.expected_version < 0
  ) {
    throw systemConfigErrors.invalidPayload('expected_version 必须为大于等于 0 的整数');
  }

  let status = 'active';
  if (Object.prototype.hasOwnProperty.call(payload, 'status')) {
    if (typeof payload.status !== 'string') {
      throw systemConfigErrors.invalidPayload('status 必须为字符串');
    }
    status = normalizeConfigStatus(payload.status);
    if (!status) {
      throw systemConfigErrors.invalidPayload('status 必须为 active 或 disabled');
    }
  }

  let hasRemark = false;
  let remark = null;
  if (Object.prototype.hasOwnProperty.call(payload, 'remark')) {
    hasRemark = true;
    if (payload.remark === null || payload.remark === undefined) {
      remark = null;
    } else if (typeof payload.remark === 'string') {
      const normalizedRemark = payload.remark.trim();
      if (
        CONTROL_CHAR_PATTERN.test(normalizedRemark)
        || normalizedRemark.length > 255
      ) {
        throw systemConfigErrors.invalidPayload('remark 长度不能超过 255 且不能包含控制字符');
      }
      remark = normalizedRemark || null;
    } else {
      throw systemConfigErrors.invalidPayload('remark 必须为字符串或 null');
    }
  }

  return {
    value: normalizedValueResolution.normalizedValue,
    expectedVersion: payload.expected_version,
    status,
    remark,
    hasRemark
  };
};

const toReadResponse = ({
  configKey,
  remark,
  version,
  status,
  updatedByUserId,
  updatedAt,
  requestId
}) => ({
  data: {
    key: configKey,
    remark: remark ?? null,
    version,
    status,
    updated_by_user_id: updatedByUserId,
    updated_at: updatedAt
  },
  meta: {
    request_id: requestId
  }
});

const toWriteResponse = ({
  configKey,
  remark,
  version,
  previousVersion,
  status,
  updatedByUserId,
  updatedAt,
  requestId
}) => ({
  data: {
    key: configKey,
    remark: remark ?? null,
    previous_version: previousVersion,
    version,
    status,
    updated_by_user_id: updatedByUserId,
    updated_at: updatedAt
  },
  meta: {
    request_id: requestId
  }
});

const normalizeSystemSensitiveConfigRecord = (record = null) => {
  if (!record || typeof record !== 'object') {
    return null;
  }
  const configKey = normalizeConfigKey(
    record.key || record.configKey || record.config_key
  );
  if (!configKey || !isWhitelistedConfigKey(configKey)) {
    return null;
  }
  const normalizedVersion = Number(record.version);
  const normalizedPreviousVersion = Number(
    record.previousVersion
    ?? record.previous_version
    ?? 0
  );
  if (
    !Number.isInteger(normalizedVersion)
    || normalizedVersion < 0
    || !Number.isInteger(normalizedPreviousVersion)
    || normalizedPreviousVersion < 0
  ) {
    return null;
  }
  const status = normalizeConfigStatus(record.status || 'active');
  if (!status) {
    return null;
  }
  const updatedByUserId = normalizeStrictRequiredString(
    record.updatedByUserId || record.updated_by_user_id
  );
  if (!updatedByUserId) {
    return null;
  }
  let remark = null;
  if (Object.prototype.hasOwnProperty.call(record, 'remark')) {
    const normalizedRemark = String(record.remark || '').trim();
    if (
      CONTROL_CHAR_PATTERN.test(normalizedRemark)
      || normalizedRemark.length > 255
    ) {
      return null;
    }
    remark = normalizedRemark || null;
  }
  return {
    key: configKey,
    configKey,
    remark,
    version: normalizedVersion,
    previousVersion: normalizedPreviousVersion,
    status,
    updatedByUserId,
    updatedAt: toIsoTimestamp(record.updatedAt || record.updated_at)
  };
};

module.exports = {
  ALLOWED_CONFIG_KEY_SET,
  BASE64URL_SEGMENT_PATTERN,
  CONTROL_CHAR_PATTERN,
  MAX_AUDIT_TRAIL_ENTRIES,
  MYSQL_DUP_ENTRY_ERRNO,
  SYSTEM_CONFIG_ENVELOPE_VERSION,
  UPDATE_SYSTEM_CONFIG_ALLOWED_FIELDS,
  VALID_SYSTEM_CONFIG_STATUS,
  isPlainObject,
  isValidEncryptedEnvelope,
  isWhitelistedConfigKey,
  mapAuthorizationError,
  mapReadDependencyError,
  mapUpdateDependencyError,
  normalizeConfigKey,
  normalizeConfigStatus,
  normalizeStrictRequiredString,
  normalizeSystemSensitiveConfigRecord,
  parseUpdatePayload,
  systemConfigErrors,
  systemConfigProblem,
  toIsoTimestamp,
  toReadResponse,
  toWriteResponse
};
