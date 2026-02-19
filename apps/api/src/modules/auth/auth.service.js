const { createHash, createDecipheriv, generateKeyPairSync, pbkdf2Sync, randomBytes, randomUUID, randomInt, timingSafeEqual, createSign, createVerify } = require('node:crypto');
const { log } = require('../../common/logger');
const { createInMemoryAuthStore } = require('./auth.store.memory');

const ACCESS_TTL_SECONDS = 15 * 60;
const REFRESH_TTL_SECONDS = 7 * 24 * 60 * 60;
const OTP_TTL_SECONDS = 15 * 60;
const OTP_CODE_LENGTH = 6;
const RATE_LIMIT_WINDOW_SECONDS = 60;
const RATE_LIMIT_MAX_ATTEMPTS = 10;
const OTP_RESEND_COOLDOWN_SECONDS = 60;
const PASSWORD_MIN_LENGTH = 6;
const PBKDF2_ITERATIONS = 150000;
const PBKDF2_KEYLEN = 64;
const PBKDF2_DIGEST = 'sha512';
const ACCESS_SESSION_CACHE_TTL_MS = 800;
const VALID_PLATFORM_ROLE_FACT_STATUS = new Set(['active', 'enabled', 'disabled']);
const VALID_PLATFORM_ROLE_CATALOG_STATUS = new Set(['active', 'enabled', 'disabled']);
const VALID_PLATFORM_ROLE_CATALOG_SCOPE = new Set(['platform', 'tenant']);
const VALID_ORG_STATUS = new Set(['active', 'disabled']);
const VALID_PLATFORM_USER_STATUS = new Set(['active', 'disabled']);
const MAX_PLATFORM_ROLE_FACTS_PER_USER = 5;
const MAX_PLATFORM_ROLE_ID_LENGTH = 64;
const MAX_ROLE_PERMISSION_CODES_PER_REQUEST = 64;
const MAX_ROLE_PERMISSION_ATOMIC_AFFECTED_USERS = 100;
const MAX_TENANT_NAME_LENGTH = 128;
const MAX_OWNER_TRANSFER_ORG_ID_LENGTH = 64;
const MAX_OWNER_TRANSFER_REASON_LENGTH = 256;
const MAX_AUTH_AUDIT_TRAIL_ENTRIES = 2000;
const MAX_TENANT_MEMBERSHIP_ID_LENGTH = 64;
const MYSQL_DUP_ENTRY_ERRNO = 1062;
const MYSQL_DATA_TOO_LONG_ERRNO = 1406;
const CONTROL_CHAR_PATTERN = /[\u0000-\u001F\u007F]/;
const WHITESPACE_PATTERN = /\s/;
const TENANT_MEMBERSHIP_ID_PATTERN = /^[^\s\u0000-\u001F\u007F]{1,64}$/;
const DEFAULT_PASSWORD_CONFIG_KEY = 'auth.default_password';
const SENSITIVE_CONFIG_ENVELOPE_VERSION = 'enc:v1';
const SENSITIVE_CONFIG_KEY_DERIVATION_ITERATIONS = 210000;
const SENSITIVE_CONFIG_KEY_DERIVATION_SALT = DEFAULT_PASSWORD_CONFIG_KEY;
const PLATFORM_ROLE_FACTS_REPLACE_PERMISSION_CODE = 'platform.member_admin.operate';
const PLATFORM_ROLE_CATALOG_SCOPE = 'platform';
const PLATFORM_ROLE_PERMISSION_FIELD_KEYS = Object.freeze([
  'canViewMemberAdmin',
  'can_view_member_admin',
  'canOperateMemberAdmin',
  'can_operate_member_admin',
  'canViewBilling',
  'can_view_billing',
  'canOperateBilling',
  'can_operate_billing'
]);
const PLATFORM_ROLE_ASSIGNMENT_ALLOWED_FIELDS = new Set([
  'role_id',
  'roleId',
  'status'
]);

const DEFAULT_SEED_USERS = [];
const ROUTE_PERMISSION_EVALUATORS = Object.freeze({
  'tenant.context.read': () => true,
  'tenant.context.switch': () => true,
  'auth.session.logout': () => true,
  'auth.session.change_password': () => true,
  'platform.member_admin.view': ({ platformPermissionContext }) =>
    Boolean(platformPermissionContext?.can_view_member_admin),
  'platform.member_admin.operate': ({ platformPermissionContext }) =>
    Boolean(platformPermissionContext?.can_view_member_admin)
    && Boolean(platformPermissionContext?.can_operate_member_admin),
  'platform.billing.view': ({ platformPermissionContext }) =>
    Boolean(platformPermissionContext?.can_view_billing),
  'platform.billing.operate': ({ platformPermissionContext }) =>
    Boolean(platformPermissionContext?.can_view_billing)
    && Boolean(platformPermissionContext?.can_operate_billing),
  'tenant.member_admin.view': ({ tenantPermissionContext }) =>
    Boolean(tenantPermissionContext?.can_view_member_admin),
  'tenant.member_admin.operate': ({ tenantPermissionContext }) =>
    Boolean(tenantPermissionContext?.can_view_member_admin) && Boolean(tenantPermissionContext?.can_operate_member_admin),
  'tenant.billing.view': ({ tenantPermissionContext }) =>
    Boolean(tenantPermissionContext?.can_view_billing),
  'tenant.billing.operate': ({ tenantPermissionContext }) =>
    Boolean(tenantPermissionContext?.can_view_billing) && Boolean(tenantPermissionContext?.can_operate_billing)
});
const ROUTE_PERMISSION_SCOPE_RULES = Object.freeze({
  'tenant.context.read': Object.freeze(['tenant']),
  'tenant.context.switch': Object.freeze(['tenant']),
  'auth.session.logout': Object.freeze(['session']),
  'auth.session.change_password': Object.freeze(['session']),
  'platform.member_admin.view': Object.freeze(['platform']),
  'platform.member_admin.operate': Object.freeze(['platform']),
  'platform.billing.view': Object.freeze(['platform']),
  'platform.billing.operate': Object.freeze(['platform']),
  'tenant.member_admin.view': Object.freeze(['tenant']),
  'tenant.member_admin.operate': Object.freeze(['tenant']),
  'tenant.billing.view': Object.freeze(['tenant']),
  'tenant.billing.operate': Object.freeze(['tenant'])
});
const TENANT_SCOPE_ALLOWED_WITHOUT_ACTIVE_TENANT = new Set([
  'tenant.context.read',
  'tenant.context.switch'
]);
const hasOwnProperty = (target, key) =>
  target !== null
  && typeof target === 'object'
  && Object.prototype.hasOwnProperty.call(target, key);
const isPlainObject = (value) =>
  value !== null
  && typeof value === 'object'
  && !Array.isArray(value);
const normalizePlatformRoleIdKey = (roleId) =>
  String(roleId || '').trim().toLowerCase();
const normalizePlatformRoleCatalogStatus = (status) => {
  const normalizedStatus = String(status || '').trim().toLowerCase();
  if (normalizedStatus === 'enabled') {
    return 'active';
  }
  return normalizedStatus;
};
const normalizePlatformRoleCatalogScope = (scope) =>
  String(scope || '').trim().toLowerCase();
const normalizeRequiredStringField = (candidate, errorFactory) => {
  if (typeof candidate !== 'string') {
    throw errorFactory();
  }
  const normalized = candidate.trim();
  if (!normalized) {
    throw errorFactory();
  }
  return normalized;
};
const resolveRawRoleIdCandidate = (role) => {
  if (!role || typeof role !== 'object') {
    return undefined;
  }
  if (hasOwnProperty(role, 'roleId')) {
    return role.roleId;
  }
  if (hasOwnProperty(role, 'role_id')) {
    return role.role_id;
  }
  return undefined;
};
const isDuplicateRoleFactEntryError = (error) =>
  String(error?.code || '').trim().toUpperCase() === 'ER_DUP_ENTRY'
  || Number(error?.errno || 0) === MYSQL_DUP_ENTRY_ERRNO;
const isDataTooLongRoleFactError = (error) =>
  String(error?.code || '').trim().toUpperCase() === 'ER_DATA_TOO_LONG'
  || Number(error?.errno || 0) === MYSQL_DATA_TOO_LONG_ERRNO;
const isMissingTableError = (error) =>
  String(error?.code || '').trim().toUpperCase() === 'ER_NO_SUCH_TABLE'
  || Number(error?.errno || 0) === 1146;
const isMissingPlatformRoleCatalogTableError = (error) =>
  isMissingTableError(error)
  && /platform_role_catalog/i.test(String(error?.message || ''));
const assertOptionalBooleanRolePermission = (candidate, errorFactory) => {
  if (candidate === undefined) {
    return;
  }
  if (typeof candidate !== 'boolean') {
    throw errorFactory();
  }
};
const hasTopLevelPlatformRolePermissionField = (role) =>
  PLATFORM_ROLE_PERMISSION_FIELD_KEYS.some((field) =>
    hasOwnProperty(role, field)
  );
const normalizePlatformPermissionCode = (permissionCode) =>
  String(permissionCode || '').trim();
const toPlatformPermissionCodeKey = (permissionCode) =>
  normalizePlatformPermissionCode(permissionCode).toLowerCase();
const isPlatformPermissionCode = (permissionCode) =>
  String(permissionCode || '').trim().startsWith('platform.');
const listSupportedPlatformPermissionCodes = () =>
  Object.keys(ROUTE_PERMISSION_EVALUATORS)
    .filter((permissionCode) =>
      isPlatformPermissionCode(permissionCode)
      && (ROUTE_PERMISSION_SCOPE_RULES[permissionCode] || []).includes('platform')
    )
    .sort((left, right) => left.localeCompare(right));
const SUPPORTED_PLATFORM_PERMISSION_CODE_SET = new Set(
  listSupportedPlatformPermissionCodes().map((permissionCode) =>
    toPlatformPermissionCodeKey(permissionCode)
  )
);
const toPlatformPermissionSnapshotFromCodes = (permissionCodes = []) => {
  const snapshot = {
    canViewMemberAdmin: false,
    canOperateMemberAdmin: false,
    canViewBilling: false,
    canOperateBilling: false
  };
  for (const permissionCode of Array.isArray(permissionCodes) ? permissionCodes : []) {
    switch (toPlatformPermissionCodeKey(permissionCode)) {
      case 'platform.member_admin.view':
        snapshot.canViewMemberAdmin = true;
        break;
      case 'platform.member_admin.operate':
        snapshot.canViewMemberAdmin = true;
        snapshot.canOperateMemberAdmin = true;
        break;
      case 'platform.billing.view':
        snapshot.canViewBilling = true;
        break;
      case 'platform.billing.operate':
        snapshot.canViewBilling = true;
        snapshot.canOperateBilling = true;
        break;
      default:
        break;
    }
  }
  return snapshot;
};
const listSupportedRoutePermissionScopes = () =>
  Object.fromEntries(
    Object.entries(ROUTE_PERMISSION_SCOPE_RULES).map(([permissionCode, scopes]) => [
      permissionCode,
      [...scopes]
    ])
  );

class AuthProblemError extends Error {
  constructor({ status, title, detail, errorCode, extensions = {} }) {
    super(detail);
    this.name = 'AuthProblemError';
    this.status = status;
    this.title = title;
    this.detail = detail;
    this.errorCode = errorCode;
    this.extensions = extensions;
  }
}

const authError = ({ status, title, detail, errorCode, extensions = {} }) => new AuthProblemError({
  status,
  title,
  detail,
  errorCode,
  extensions
});

const errors = {
  invalidPayload: () =>
    authError({
      status: 400,
      title: 'Bad Request',
      detail: '请求参数不完整或格式错误',
      errorCode: 'AUTH-400-INVALID-PAYLOAD'
    }),

  loginFailed: () =>
    authError({
      status: 401,
      title: 'Unauthorized',
      detail: '手机号或密码错误',
      errorCode: 'AUTH-401-LOGIN-FAILED'
    }),

  invalidAccess: () =>
    authError({
      status: 401,
      title: 'Unauthorized',
      detail: '当前会话无效，请重新登录',
      errorCode: 'AUTH-401-INVALID-ACCESS'
    }),

  invalidRefresh: () =>
    authError({
      status: 401,
      title: 'Unauthorized',
      detail: '会话已失效，请重新登录',
      errorCode: 'AUTH-401-INVALID-REFRESH'
    }),

  otpFailed: () =>
    authError({
      status: 401,
      title: 'Unauthorized',
      detail: '验证码错误或已失效',
      errorCode: 'AUTH-401-OTP-FAILED'
    }),

  rateLimited: ({
    action,
    remainingSeconds,
    limit = RATE_LIMIT_MAX_ATTEMPTS,
    windowSeconds = RATE_LIMIT_WINDOW_SECONDS
  }) =>
    authError({
      status: 429,
      title: 'Too Many Requests',
      detail: '请求过于频繁，请稍后重试',
      errorCode: 'AUTH-429-RATE-LIMITED',
      extensions: {
        retryable: true,
        retry_after_seconds: remainingSeconds,
        rate_limit_action: action,
        rate_limit_limit: limit,
        rate_limit_window_seconds: windowSeconds
      }
    }),

  weakPassword: () =>
    authError({
      status: 400,
      title: 'Bad Request',
      detail: `新密码不满足策略，最小长度 ${PASSWORD_MIN_LENGTH}`,
      errorCode: 'AUTH-400-WEAK-PASSWORD'
    }),

  noDomainAccess: () =>
    authError({
      status: 403,
      title: 'Forbidden',
      detail: '当前入口无可用访问域权限',
      errorCode: 'AUTH-403-NO-DOMAIN'
    }),

  forbidden: () =>
    authError({
      status: 403,
      title: 'Forbidden',
      detail: '当前操作无权限',
      errorCode: 'AUTH-403-FORBIDDEN'
    }),

  orgNotFound: () =>
    authError({
      status: 404,
      title: 'Not Found',
      detail: '目标组织不存在',
      errorCode: 'AUTH-404-ORG-NOT-FOUND'
    }),

  userNotFound: ({ extensions = null } = {}) =>
    authError({
      status: 404,
      title: 'Not Found',
      detail: '目标用户不存在',
      errorCode: 'AUTH-404-USER-NOT-FOUND',
      extensions: isPlainObject(extensions) ? extensions : {}
    }),

  ownerTransferOrgNotActive: ({
    orgId = null,
    oldOwnerUserId = null
  } = {}) =>
    authError({
      status: 409,
      title: 'Conflict',
      detail: '目标组织当前不可发起负责人变更，请先启用后重试',
      errorCode: 'AUTH-409-ORG-NOT-ACTIVE',
      extensions: {
        org_id: orgId ? String(orgId).trim() : null,
        old_owner_user_id: oldOwnerUserId ? String(oldOwnerUserId).trim() : null
      }
    }),

  ownerTransferTargetUserInactive: ({
    orgId = null,
    oldOwnerUserId = null,
    newOwnerUserId = null
  } = {}) =>
    authError({
      status: 409,
      title: 'Conflict',
      detail: '候选新负责人状态不可用',
      errorCode: 'AUTH-409-OWNER-TRANSFER-TARGET-USER-INACTIVE',
      extensions: {
        org_id: orgId ? String(orgId).trim() : null,
        old_owner_user_id: oldOwnerUserId ? String(oldOwnerUserId).trim() : null,
        new_owner_user_id: newOwnerUserId ? String(newOwnerUserId).trim() : null
      }
    }),

  ownerTransferSameOwner: ({
    orgId = null,
    oldOwnerUserId = null
  } = {}) =>
    authError({
      status: 409,
      title: 'Conflict',
      detail: '新负责人不能与当前负责人相同',
      errorCode: 'AUTH-409-OWNER-TRANSFER-SAME-OWNER',
      extensions: {
        org_id: orgId ? String(orgId).trim() : null,
        old_owner_user_id: oldOwnerUserId ? String(oldOwnerUserId).trim() : null,
        new_owner_user_id: oldOwnerUserId ? String(oldOwnerUserId).trim() : null
      }
    }),

  roleNotFound: () =>
    authError({
      status: 404,
      title: 'Not Found',
      detail: '目标平台角色不存在',
      errorCode: 'AUTH-404-ROLE-NOT-FOUND'
    }),

  platformSnapshotDegraded: ({ reason = 'db-deadlock' } = {}) =>
    authError({
      status: 503,
      title: 'Service Unavailable',
      detail: '平台权限同步暂时不可用，请稍后重试',
      errorCode: 'AUTH-503-PLATFORM-SNAPSHOT-DEGRADED',
      extensions: {
        retryable: true,
        degradation_reason: String(reason || 'unknown')
      }
    }),

  provisioningConfigUnavailable: () =>
    authError({
      status: 503,
      title: 'Service Unavailable',
      detail: '默认密码配置不可用，请稍后重试',
      errorCode: 'AUTH-503-PROVISION-CONFIG-UNAVAILABLE',
      extensions: {
        retryable: true,
        degradation_reason: 'default-password-config-unavailable'
      }
    }),

  ownerTransferLockUnavailable: () =>
    authError({
      status: 503,
      title: 'Service Unavailable',
      detail: '负责人变更锁服务暂不可用，请稍后重试',
      errorCode: 'AUTH-503-OWNER-TRANSFER-LOCK-UNAVAILABLE',
      extensions: {
        retryable: true,
        degradation_reason: 'owner-transfer-lock-unavailable'
      }
    }),

  provisionConflict: () =>
    authError({
      status: 409,
      title: 'Conflict',
      detail: '用户关系已存在，请勿重复提交',
      errorCode: 'AUTH-409-PROVISION-CONFLICT'
    }),

  tenantMembershipNotFound: () =>
    authError({
      status: 404,
      title: 'Not Found',
      detail: '目标成员关系不存在',
      errorCode: 'AUTH-404-TENANT-MEMBERSHIP-NOT-FOUND',
      extensions: {
        retryable: false
      }
    }),

  tenantMemberDependencyUnavailable: ({ reason = 'dependency-unavailable' } = {}) =>
    authError({
      status: 503,
      title: 'Service Unavailable',
      detail: '组织成员治理依赖暂不可用，请稍后重试',
      errorCode: 'AUTH-503-TENANT-MEMBER-DEPENDENCY-UNAVAILABLE',
      extensions: {
        retryable: true,
        degradation_reason: String(reason || 'dependency-unavailable').trim()
      }
    })
};

const toBase64Url = (input) => {
  const raw = Buffer.isBuffer(input) ? input : Buffer.from(input, 'utf8');
  return raw.toString('base64url');
};

const fromBase64Url = (input) => Buffer.from(input, 'base64url');
const deriveLegacySensitiveConfigKey = (rawKey) => {
  const normalizedRawKey = typeof rawKey === 'string' ? rawKey.trim() : '';
  if (!normalizedRawKey) {
    return null;
  }
  if (/^[0-9a-f]{64}$/i.test(normalizedRawKey)) {
    return Buffer.from(normalizedRawKey, 'hex');
  }
  return createHash('sha256').update(normalizedRawKey).digest();
};
const derivePrimarySensitiveConfigKey = (rawKey) => {
  const normalizedRawKey = typeof rawKey === 'string' ? rawKey.trim() : '';
  if (!normalizedRawKey) {
    return null;
  }
  if (/^[0-9a-f]{64}$/i.test(normalizedRawKey)) {
    return Buffer.from(normalizedRawKey, 'hex');
  }
  return pbkdf2Sync(
    normalizedRawKey,
    SENSITIVE_CONFIG_KEY_DERIVATION_SALT,
    SENSITIVE_CONFIG_KEY_DERIVATION_ITERATIONS,
    32,
    'sha256'
  );
};
const deriveSensitiveConfigKeys = (rawKey) => {
  const derivedKeys = [];
  const primaryKey = derivePrimarySensitiveConfigKey(rawKey);
  const legacyKey = deriveLegacySensitiveConfigKey(rawKey);
  if (primaryKey) {
    derivedKeys.push(primaryKey);
  }
  if (
    legacyKey
    && !derivedKeys.some((candidate) => Buffer.compare(candidate, legacyKey) === 0)
  ) {
    derivedKeys.push(legacyKey);
  }
  return derivedKeys;
};
const decryptSensitiveConfigValue = ({
  encryptedValue,
  decryptionKey,
  decryptionKeys = null
}) => {
  const envelope = String(encryptedValue || '').trim();
  const keys = Array.isArray(decryptionKeys)
    ? decryptionKeys.filter((key) => Buffer.isBuffer(key))
    : deriveSensitiveConfigKeys(decryptionKey);
  if (!envelope || keys.length === 0) {
    throw new Error('sensitive-config-unavailable');
  }
  const envelopeSections = envelope.split(':');
  if (
    envelopeSections.length !== 5
    || `${envelopeSections[0]}:${envelopeSections[1]}` !== SENSITIVE_CONFIG_ENVELOPE_VERSION
  ) {
    throw new Error('sensitive-config-format-invalid');
  }
  const iv = Buffer.from(envelopeSections[2], 'base64url');
  const authTag = Buffer.from(envelopeSections[3], 'base64url');
  const ciphertext = Buffer.from(envelopeSections[4], 'base64url');
  if (iv.length !== 12 || authTag.length !== 16 || ciphertext.length === 0) {
    throw new Error('sensitive-config-envelope-invalid');
  }
  let decryptError = null;
  for (const key of keys) {
    try {
      const decipher = createDecipheriv('aes-256-gcm', key, iv);
      decipher.setAuthTag(authTag);
      const plainText = Buffer.concat([
        decipher.update(ciphertext),
        decipher.final()
      ]).toString('utf8');
      if (!plainText) {
        throw new Error('sensitive-config-plaintext-empty');
      }
      return plainText;
    } catch (error) {
      decryptError = error;
    }
  }
  if (decryptError?.message === 'sensitive-config-plaintext-empty') {
    throw decryptError;
  }
  throw new Error('sensitive-config-decrypt-failed');
};
const resolveProvisioningConfigFailureReason = (error) => {
  if (error instanceof AuthProblemError && error.errorCode === 'AUTH-400-WEAK-PASSWORD') {
    return 'decrypted-password-policy-violation';
  }
  const message = String(error?.message || '').trim();
  if (message === 'sensitive-config-unavailable') {
    return 'encrypted-config-missing-or-key-missing';
  }
  if (message === 'sensitive-config-format-invalid' || message === 'sensitive-config-envelope-invalid') {
    return 'encrypted-config-format-invalid';
  }
  if (message === 'sensitive-config-plaintext-empty') {
    return 'decrypted-password-empty';
  }
  return 'encrypted-config-decrypt-failed';
};

const signJwt = ({ payload, privateKeyPem, ttlSeconds }) => {
  const header = {
    alg: 'RS256',
    typ: 'JWT'
  };

  const nowSeconds = Math.floor(Date.now() / 1000);
  const normalizedPayload = {
    iat: nowSeconds,
    exp: nowSeconds + ttlSeconds,
    ...payload
  };

  const encodedHeader = toBase64Url(JSON.stringify(header));
  const encodedPayload = toBase64Url(JSON.stringify(normalizedPayload));
  const signingInput = `${encodedHeader}.${encodedPayload}`;

  const signer = createSign('RSA-SHA256');
  signer.update(signingInput);
  signer.end();

  const signature = signer.sign(privateKeyPem);
  const encodedSignature = signature.toString('base64url');
  return `${signingInput}.${encodedSignature}`;
};

const createJwtError = (message, code, extra = {}) => {
  const error = new Error(message);
  error.code = code;
  Object.assign(error, extra);
  return error;
};

const verifyJwt = ({ token, publicKeyPem, expectedTyp, allowExpired = false }) => {
  if (typeof token !== 'string' || token.trim().length === 0) {
    throw createJwtError('jwt missing', 'JWT_MISSING');
  }

  const sections = token.split('.');
  if (sections.length !== 3) {
    throw createJwtError('jwt malformed', 'JWT_MALFORMED');
  }

  const [encodedHeader, encodedPayload, encodedSignature] = sections;
  const signingInput = `${encodedHeader}.${encodedPayload}`;

  const verifier = createVerify('RSA-SHA256');
  verifier.update(signingInput);
  verifier.end();

  const signature = fromBase64Url(encodedSignature);
  const validSignature = verifier.verify(publicKeyPem, signature);
  if (!validSignature) {
    throw createJwtError('jwt signature mismatch', 'JWT_SIGNATURE_MISMATCH');
  }

  const header = JSON.parse(fromBase64Url(encodedHeader).toString('utf8'));
  const payload = JSON.parse(fromBase64Url(encodedPayload).toString('utf8'));

  if (header.alg !== 'RS256') {
    throw createJwtError('jwt alg mismatch', 'JWT_ALG_MISMATCH');
  }

  if (expectedTyp && payload.typ !== expectedTyp) {
    throw createJwtError('jwt typ mismatch', 'JWT_TYP_MISMATCH');
  }

  const nowSeconds = Math.floor(Date.now() / 1000);
  if (!allowExpired && (typeof payload.exp !== 'number' || payload.exp <= nowSeconds)) {
    throw createJwtError('jwt expired', 'JWT_EXPIRED', { payload });
  }

  return payload;
};

const hashPassword = (plainTextPassword) => {
  const salt = randomBytes(16).toString('hex');
  const derived = pbkdf2Sync(
    plainTextPassword,
    salt,
    PBKDF2_ITERATIONS,
    PBKDF2_KEYLEN,
    PBKDF2_DIGEST
  ).toString('hex');

  return `pbkdf2$${PBKDF2_DIGEST}$${PBKDF2_ITERATIONS}$${salt}$${derived}`;
};

const verifyPassword = (plainTextPassword, encodedHash) => {
  if (!encodedHash || typeof encodedHash !== 'string') {
    return false;
  }

  const sections = encodedHash.split('$');
  if (sections.length !== 5 || sections[0] !== 'pbkdf2') {
    return false;
  }

  const [, digest, iterationText, salt, expectedHex] = sections;
  const iterations = Number(iterationText);
  if (Number.isNaN(iterations) || iterations < 1) {
    return false;
  }

  let actualHex;
  try {
    actualHex = pbkdf2Sync(
      plainTextPassword,
      salt,
      iterations,
      Buffer.from(expectedHex, 'hex').length,
      digest
    ).toString('hex');
  } catch (_error) {
    return false;
  }

  const expected = Buffer.from(expectedHex, 'hex');
  const actual = Buffer.from(actualHex, 'hex');

  if (expected.length !== actual.length) {
    return false;
  }

  return timingSafeEqual(expected, actual);
};

const tokenHash = (rawToken) => createHash('sha256').update(rawToken).digest('hex');
const normalizePhone = (phone) => {
  if (typeof phone !== 'string') {
    return null;
  }
  const trimmed = phone.trim();
  if (!/^1\d{10}$/.test(trimmed)) {
    return null;
  }
  return trimmed;
};

const maskPhone = (phone) => {
  if (typeof phone !== 'string' || phone.trim().length === 0) {
    return 'unknown';
  }

  const cleaned = phone.trim().replace(/\s/g, '');

  if (/^1\d{10}$/.test(cleaned)) {
    return `${cleaned.slice(0, 3)}****${cleaned.slice(-4)}`;
  }

  if (cleaned.length <= 4) {
    return cleaned.replace(/./g, '*');
  }

  return `${cleaned.slice(0, 2)}${'*'.repeat(cleaned.length - 4)}${cleaned.slice(-2)}`;
};

const isUserActive = (user) => {
  if (!user || typeof user.status !== 'string') {
    return false;
  }

  const normalizedStatus = user.status.trim().toLowerCase();
  return normalizedStatus === 'active' || normalizedStatus === 'enabled';
};

const normalizeEntryDomain = (entryDomain) => {
  const normalized = String(entryDomain || 'platform').trim().toLowerCase();
  if (normalized !== 'platform' && normalized !== 'tenant') {
    return null;
  }
  return normalized;
};

const normalizeTenantId = (tenantId) => {
  if (tenantId === null || tenantId === undefined) {
    return null;
  }
  const normalized = String(tenantId).trim();
  return normalized.length > 0 ? normalized : null;
};
const normalizePlatformRoleCatalogTenantIdForScope = ({
  scope = PLATFORM_ROLE_CATALOG_SCOPE,
  tenantId,
  allowEmptyForPlatform = true
} = {}) => {
  const normalizedScope = normalizePlatformRoleCatalogScope(scope);
  const normalizedTenantId = normalizeTenantId(tenantId);
  if (normalizedScope === 'tenant') {
    if (!normalizedTenantId) {
      throw errors.invalidPayload();
    }
    return normalizedTenantId;
  }
  if (allowEmptyForPlatform) {
    return null;
  }
  return normalizedTenantId;
};
const normalizeOrgStatus = (status) => {
  const normalizedStatus = String(status || '').trim().toLowerCase();
  if (normalizedStatus === 'enabled') {
    return 'active';
  }
  if (normalizedStatus === 'active' || normalizedStatus === 'disabled') {
    return normalizedStatus;
  }
  return '';
};
const normalizeTenantMembershipStatus = (status) => {
  const normalizedStatus = String(status || '').trim().toLowerCase();
  if (normalizedStatus === 'enabled') {
    return 'active';
  }
  if (
    normalizedStatus === 'active'
    || normalizedStatus === 'disabled'
    || normalizedStatus === 'left'
  ) {
    return normalizedStatus;
  }
  return '';
};
const isValidTenantMembershipId = (membershipId) =>
  TENANT_MEMBERSHIP_ID_PATTERN.test(String(membershipId || ''))
  && String(membershipId || '').length <= MAX_TENANT_MEMBERSHIP_ID_LENGTH;
const normalizeMemberListInteger = ({
  value,
  fallback,
  min = 1,
  max = Number.MAX_SAFE_INTEGER
}) => {
  if (value === undefined || value === null || value === '') {
    return fallback;
  }
  const normalized = String(value).trim();
  if (!/^\d+$/.test(normalized)) {
    return fallback;
  }
  const parsed = Number.parseInt(normalized, 10);
  if (!Number.isFinite(parsed)) {
    return fallback;
  }
  if (parsed < min) {
    return min;
  }
  if (parsed > max) {
    return max;
  }
  return parsed;
};
const parseOptionalTenantName = (tenantName) => {
  if (tenantName === null || tenantName === undefined) {
    return { valid: true, value: null };
  }
  if (typeof tenantName !== 'string') {
    return { valid: false, value: null };
  }
  if (tenantName.length > MAX_TENANT_NAME_LENGTH) {
    return { valid: false, value: null };
  }
  const normalized = tenantName.trim();
  if (!normalized) {
    return { valid: false, value: null };
  }
  if (normalized.length > MAX_TENANT_NAME_LENGTH) {
    return { valid: false, value: null };
  }
  return { valid: true, value: normalized };
};

const buildPlatformPermissionContext = () => ({
  scope_label: '平台入口（无组织侧权限上下文）',
  can_view_member_admin: false,
  can_operate_member_admin: false,
  can_view_billing: false,
  can_operate_billing: false
});

const buildTenantUnselectedPermissionContext = () => ({
  scope_label: '组织未选择（无可操作权限）',
  can_view_member_admin: false,
  can_operate_member_admin: false,
  can_view_billing: false,
  can_operate_billing: false
});

const normalizeTenantPermissionContext = (permissionContext, fallbackScopeLabel) => {
  if (!permissionContext || typeof permissionContext !== 'object') {
    return null;
  }
  return {
    scope_label: permissionContext.scopeLabel
      || permissionContext.scope_label
      || fallbackScopeLabel
      || '组织权限快照（默认）',
    can_view_member_admin: Boolean(
      permissionContext.canViewMemberAdmin ?? permissionContext.can_view_member_admin
    ),
    can_operate_member_admin: Boolean(
      permissionContext.canOperateMemberAdmin ?? permissionContext.can_operate_member_admin
    ),
    can_view_billing: Boolean(permissionContext.canViewBilling ?? permissionContext.can_view_billing),
    can_operate_billing: Boolean(
      permissionContext.canOperateBilling ?? permissionContext.can_operate_billing
    )
  };
};

const normalizePlatformPermissionContext = (permissionContext, fallbackScopeLabel) => {
  if (!permissionContext || typeof permissionContext !== 'object') {
    return null;
  }
  return {
    scope_label: permissionContext.scopeLabel
      || permissionContext.scope_label
      || fallbackScopeLabel
      || '平台权限快照（默认）',
    can_view_member_admin: Boolean(
      permissionContext.canViewMemberAdmin ?? permissionContext.can_view_member_admin
    ),
    can_operate_member_admin: Boolean(
      permissionContext.canOperateMemberAdmin ?? permissionContext.can_operate_member_admin
    ),
    can_view_billing: Boolean(permissionContext.canViewBilling ?? permissionContext.can_view_billing),
    can_operate_billing: Boolean(
      permissionContext.canOperateBilling ?? permissionContext.can_operate_billing
    )
  };
};
const parseProvisionPayload = ({ payload, scope }) => {
  if (!isPlainObject(payload)) {
    return { valid: false, phone: undefined, tenantName: undefined, tenantNameProvided: false };
  }
  const normalizedScope = String(scope || '').trim().toLowerCase();
  const allowedKeys = normalizedScope === 'tenant'
    ? new Set(['phone', 'tenant_name'])
    : new Set(['phone']);
  for (const key of Object.keys(payload)) {
    if (!allowedKeys.has(key)) {
      return { valid: false, phone: undefined, tenantName: undefined, tenantNameProvided: false };
    }
  }
  const tenantNameProvided = hasOwnProperty(payload, 'tenant_name');
  return {
    valid: true,
    phone: payload.phone,
    tenantName: tenantNameProvided ? payload.tenant_name : undefined,
    tenantNameProvided
  };
};

const createInMemoryOtpStore = ({ nowProvider }) => {
  const otpByPhone = new Map();

  return {
    upsertOtp: async ({ phone, code, expiresAt }) => {
      const sentAtMs = nowProvider();
      otpByPhone.set(String(phone), {
        codeHash: tokenHash(String(code)),
        expiresAt: Number(expiresAt),
        consumed: false,
        sentAtMs
      });
      return { sent_at_ms: sentAtMs };
    },

    getSentAt: async ({ phone }) => {
      const record = otpByPhone.get(String(phone));
      return record ? record.sentAtMs : null;
    },

    verifyAndConsumeOtp: async ({ phone, code, nowMs }) => {
      const record = otpByPhone.get(String(phone));
      if (!record) {
        return { ok: false, reason: 'missing' };
      }
      if (record.consumed) {
        return { ok: false, reason: 'used' };
      }
      if (record.expiresAt <= Number(nowMs)) {
        return { ok: false, reason: 'expired' };
      }
      if (record.codeHash !== tokenHash(String(code))) {
        return { ok: false, reason: 'mismatch' };
      }

      record.consumed = true;
      record.consumedAt = nowProvider();
      otpByPhone.set(String(phone), record);
      return { ok: true, reason: 'ok' };
    }
  };
};

const createInMemoryRateLimitStore = () => {
  const eventsByKey = new Map();

  return {
    consume: async ({ phone, action, limit, windowSeconds, nowMs }) => {
      const key = `${String(phone)}:${String(action)}`;
      const windowMs = Number(windowSeconds) * 1000;
      const floor = Number(nowMs) - windowMs;
      const existing = eventsByKey.get(key) || [];
      const pruned = existing.filter((eventTs) => eventTs > floor);
      pruned.push(Number(nowMs));
      eventsByKey.set(key, pruned);

      const count = pruned.length;
      const oldest = pruned[0] || Number(nowMs);
      const remainingMs = Math.max(0, oldest + windowMs - Number(nowMs));
      return {
        allowed: count <= Number(limit),
        count,
        remainingSeconds: Math.max(1, Math.ceil(remainingMs / 1000))
      };
    }
  };
};

const assertStoreMethod = (store, methodName, storeName) => {
  if (!store || typeof store[methodName] !== 'function') {
    throw new Error(`${storeName}.${methodName} is required`);
  }
};

const assertOtpStoreContract = (store) => {
  assertStoreMethod(store, 'upsertOtp', 'otpStore');
  assertStoreMethod(store, 'getSentAt', 'otpStore');
  assertStoreMethod(store, 'verifyAndConsumeOtp', 'otpStore');
};

const createAuthService = (options = {}) => {
  const now = options.now || (() => Date.now());
  const seedUsers = options.seedUsers || DEFAULT_SEED_USERS;
  const authStore = options.authStore || createInMemoryAuthStore({ seedUsers, hashPassword });
  const hasExternalAuthStore = Boolean(options.authStore);

  const isSecureMode = options.requireSecureOtpStores === true;
  if (isSecureMode && (!options.otpStore || !options.rateLimitStore)) {
    throw new Error('OTP and rate-limit stores are REQUIRED in secure mode. Fallback to memory is forbidden.');
  }

  const allowInMemoryOtpStores = options.allowInMemoryOtpStores === true;
  if (
    hasExternalAuthStore &&
    !allowInMemoryOtpStores &&
    (!options.otpStore || !options.rateLimitStore)
  ) {
    throw new Error('OTP and rate-limit stores must be configured explicitly');
  }

  const otpStore = options.otpStore || createInMemoryOtpStore({ nowProvider: now });
  const rateLimitStore = options.rateLimitStore || createInMemoryRateLimitStore();
  assertOtpStoreContract(otpStore);

  const isMultiInstance = Boolean(options.multiInstance || options.enforceExternalJwtKeys);
  const configuredAccessSessionCacheTtlMs = Math.max(
    0,
    Number(options.accessSessionCacheTtlMs || ACCESS_SESSION_CACHE_TTL_MS)
  );
  const accessSessionCacheTtlMs = isMultiInstance ? 0 : configuredAccessSessionCacheTtlMs;
  const accessSessionCache = new Map();
  const sensitiveConfigProvider = options.sensitiveConfigProvider || null;
  const sensitiveConfigDecryptionKey = options.sensitiveConfigDecryptionKey || '';
  const sensitiveConfigDecryptionKeys = deriveSensitiveConfigKeys(sensitiveConfigDecryptionKey);

  const jwtKeyPair = (() => {
    if (options.jwtKeyPair?.privateKey && options.jwtKeyPair?.publicKey) {
      return options.jwtKeyPair;
    }

    if (options.enforceExternalJwtKeys) {
      throw new Error('External JWT key pair is required when enforceExternalJwtKeys is enabled');
    }

    return generateKeyPairSync('rsa', {
      modulusLength: 2048,
      publicKeyEncoding: { type: 'spki', format: 'pem' },
      privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
    });
  })();

  const auditTrail = [];
  const ownerTransferLocksByOrgId = new Map();

  const addAuditEvent = ({
    type,
    requestId,
    userId = 'unknown',
    sessionId = 'unknown',
    detail = '',
    metadata = {}
  }) => {
    const event = {
      type,
      at: new Date(now()).toISOString(),
      request_id: requestId || 'request_id_unset',
      user_id: userId,
      session_id: sessionId,
      detail,
      ...metadata
    };

    auditTrail.push(event);
    if (auditTrail.length > MAX_AUTH_AUDIT_TRAIL_ENTRIES) {
      auditTrail.splice(0, auditTrail.length - MAX_AUTH_AUDIT_TRAIL_ENTRIES);
    }
    log('info', 'Auth audit event', event);
  };

  const recordIdempotencyEvent = async ({
    requestId,
    outcome = 'hit',
    routeKey = '',
    idempotencyKey = '',
    authorizationContext = null,
    metadata = {}
  } = {}) => {
    const requestedOutcome = String(outcome || 'hit').trim().toLowerCase();
    const outcomeDescriptorByCode = {
      hit: {
        eventType: 'auth.idempotency.hit',
        detail: 'idempotency replay served from prior result'
      },
      conflict: {
        eventType: 'auth.idempotency.conflict',
        detail: 'idempotency key reused with different request payload'
      },
      store_unavailable: {
        eventType: 'auth.idempotency.degraded',
        detail: 'idempotency store unavailable for this request'
      },
      pending_timeout: {
        eventType: 'auth.idempotency.degraded',
        detail: 'idempotency pending wait timeout'
      },
      unknown: {
        eventType: 'auth.idempotency.unknown',
        detail: 'idempotency outcome is unrecognized'
      }
    };
    const normalizedOutcome = Object.prototype.hasOwnProperty.call(
      outcomeDescriptorByCode,
      requestedOutcome
    )
      ? requestedOutcome
      : 'unknown';
    const selectedOutcomeDescriptor = outcomeDescriptorByCode[normalizedOutcome];
    const resolvedUserId = String(
      authorizationContext?.user_id
      || authorizationContext?.user?.id
      || 'unknown'
    ).trim() || 'unknown';
    const resolvedSessionId = String(
      authorizationContext?.session_id
      || authorizationContext?.session?.sessionId
      || authorizationContext?.session?.session_id
      || 'unknown'
    ).trim() || 'unknown';
    const idempotencyKeyFingerprint = createHash('sha256')
      .update(String(idempotencyKey || '').trim())
      .digest('hex');

    addAuditEvent({
      type: selectedOutcomeDescriptor.eventType,
      requestId,
      userId: resolvedUserId,
      sessionId: resolvedSessionId,
      detail: selectedOutcomeDescriptor.detail,
      metadata: {
        route_key: String(routeKey || ''),
        idempotency_key_fingerprint: idempotencyKeyFingerprint,
        idempotency_outcome: normalizedOutcome,
        ...metadata
      }
    });
  };

  const addAccessInvalidAuditEvent = ({
    requestId,
    payload = null,
    userId = 'unknown',
    sessionId = 'unknown',
    dispositionReason = 'access-token-invalid'
  }) =>
    addAuditEvent({
      type: 'auth.access.invalid',
      requestId,
      userId,
      sessionId,
      detail: 'access token rejected',
      metadata: {
        session_id_hint: String(payload?.sid || sessionId || 'unknown'),
        disposition_reason: dispositionReason,
        disposition_action: 'reject-only'
      }
    });

  const validatePasswordPolicy = (candidatePassword) => {
    if (typeof candidatePassword !== 'string' || candidatePassword.length < PASSWORD_MIN_LENGTH) {
      throw errors.weakPassword();
    }
  };

  const invalidateSessionCacheBySessionId = (sessionId) => {
    for (const key of accessSessionCache.keys()) {
      if (key.startsWith(`${String(sessionId)}:`)) {
        accessSessionCache.delete(key);
      }
    }
  };

  const invalidateSessionCacheByUserId = (userId) => {
    for (const key of accessSessionCache.keys()) {
      const parts = key.split(':');
      if (parts[1] === String(userId)) {
        accessSessionCache.delete(key);
      }
    }
  };

  const invalidateAllAccessSessionCache = () => {
    accessSessionCache.clear();
  };

  const buildSessionContext = (session = {}) => ({
    entry_domain: normalizeEntryDomain(session.entryDomain || session.entry_domain || 'platform') || 'platform',
    active_tenant_id: normalizeTenantId(session.activeTenantId || session.active_tenant_id)
  });

  const getDomainAccessForUser = async (userId) => {
    if (typeof authStore.findDomainAccessByUserId === 'function') {
      const access = await authStore.findDomainAccessByUserId(String(userId));
      return {
        platform: Boolean(access?.platform),
        tenant: Boolean(access?.tenant)
      };
    }
    return { platform: false, tenant: false };
  };

  const ensureDefaultDomainAccessForUser = async ({ requestId, userId }) => {
    if (typeof authStore.ensureDefaultDomainAccessForUser !== 'function') {
      return { inserted: false };
    }
    const result = await authStore.ensureDefaultDomainAccessForUser(String(userId));
    if (result?.inserted === true) {
      addAuditEvent({
        type: 'auth.domain.default_granted',
        requestId,
        userId,
        detail: 'default platform domain access provisioned',
        metadata: {
          entry_domain: 'platform',
          tenant_id: null
        }
      });
    }
    return {
      inserted: result?.inserted === true
    };
  };

  const ensureTenantDomainAccessForUser = async ({ requestId, userId, entryDomain }) => {
    if (entryDomain !== 'tenant') {
      return;
    }
    if (typeof authStore.ensureTenantDomainAccessForUser !== 'function') {
      return;
    }
    const result = await authStore.ensureTenantDomainAccessForUser(String(userId));
    if (result?.inserted === true) {
      addAuditEvent({
        type: 'auth.domain.tenant_granted',
        requestId,
        userId,
        detail: 'tenant domain access provisioned from active tenant membership',
        metadata: {
          entry_domain: 'tenant',
          tenant_id: null
        }
      });
    }
  };

  const getTenantOptionsForUser = async (userId) => {
    if (typeof authStore.listTenantOptionsByUserId !== 'function') {
      return [];
    }
    const options = await authStore.listTenantOptionsByUserId(String(userId));
    if (!Array.isArray(options)) {
      return [];
    }
    return options
      .map((option) => ({
        tenant_id: normalizeTenantId(option.tenantId || option.tenant_id),
        tenant_name: option.tenantName || option.tenant_name || null
      }))
      .filter((option) => option.tenant_id);
  };

  const shouldProvisionDefaultPlatformDomainAccess = async ({ userId }) => {
    const access = await getDomainAccessForUser(userId);
    if (access.platform || access.tenant) {
      return false;
    }

    if (typeof authStore.hasAnyTenantRelationshipByUserId !== 'function') {
      return false;
    }

    const hasAnyTenantRelationship = await authStore.hasAnyTenantRelationshipByUserId(
      String(userId)
    );
    if (hasAnyTenantRelationship) {
      return false;
    }

    const tenantOptions = await getTenantOptionsForUser(userId);
    return tenantOptions.length === 0;
  };

  const rejectNoDomainAccess = ({
    requestId,
    userId,
    sessionId = 'unknown',
    entryDomain,
    tenantId,
    detail,
    permissionCode = null
  }) => {
    addAuditEvent({
      type: 'auth.domain.rejected',
      requestId,
      userId,
      sessionId,
      detail,
      metadata: {
        permission_code: permissionCode,
        entry_domain: entryDomain,
        tenant_id: normalizeTenantId(tenantId)
      }
    });
    throw errors.noDomainAccess();
  };

  const getTenantPermissionContext = async ({
    requestId,
    userId,
    sessionId,
    entryDomain,
    activeTenantId
  }) => {
    if (entryDomain !== 'tenant') {
      return buildPlatformPermissionContext();
    }

    const normalizedTenantId = normalizeTenantId(activeTenantId);
    if (!normalizedTenantId) {
      return buildTenantUnselectedPermissionContext();
    }

    if (typeof authStore.findTenantPermissionByUserAndTenantId !== 'function') {
      rejectNoDomainAccess({
        requestId,
        userId,
        sessionId,
        entryDomain,
        tenantId: normalizedTenantId,
        detail: `tenant permission lookup unavailable: ${normalizedTenantId}`
      });
    }

    const permissionContext = await authStore.findTenantPermissionByUserAndTenantId({
      userId: String(userId),
      tenantId: normalizedTenantId
    });
    const normalized = normalizeTenantPermissionContext(
      permissionContext,
      `组织权限（${normalizedTenantId}）`
    );
    if (!normalized) {
      rejectNoDomainAccess({
        requestId,
        userId,
        sessionId,
        entryDomain,
        tenantId: normalizedTenantId,
        detail: `tenant permission missing: ${normalizedTenantId}`
      });
    }
    return normalized;
  };

  const getPlatformPermissionContext = async ({
    requestId,
    userId,
    sessionId,
    entryDomain,
    permissionCode = null
  }) => {
    if (entryDomain !== 'platform') {
      return null;
    }

    const access = await getDomainAccessForUser(userId);
    if (!access.platform) {
      rejectNoDomainAccess({
        requestId,
        userId,
        sessionId,
        entryDomain,
        tenantId: null,
        detail: 'platform domain access denied',
        permissionCode
      });
    }

    if (typeof authStore.syncPlatformPermissionSnapshotByUserId === 'function') {
      let syncResult = await authStore.syncPlatformPermissionSnapshotByUserId({
        userId: String(userId),
        forceWhenNoRoleFacts: true
      });
      if (syncResult?.reason === 'concurrent-role-facts-update') {
        syncResult = await authStore.syncPlatformPermissionSnapshotByUserId({
          userId: String(userId),
          forceWhenNoRoleFacts: true
        });
      }
      if (syncResult?.reason === 'concurrent-role-facts-update') {
        addAuditEvent({
          type: 'auth.platform.snapshot.degraded',
          requestId,
          userId,
          sessionId,
          detail: 'platform snapshot sync degraded: concurrent-role-facts-update',
          metadata: {
            permission_code: permissionCode,
            entry_domain: entryDomain,
            tenant_id: null,
            degradation_reason: 'concurrent-role-facts-update'
          }
        });
        throw errors.platformSnapshotDegraded({
          reason: 'concurrent-role-facts-update'
        });
      }
      if (syncResult?.reason === 'db-deadlock') {
        addAuditEvent({
          type: 'auth.platform.snapshot.degraded',
          requestId,
          userId,
          sessionId,
          detail: 'platform snapshot sync degraded: db-deadlock',
          metadata: {
            permission_code: permissionCode,
            entry_domain: entryDomain,
            tenant_id: null,
            degradation_reason: 'db-deadlock'
          }
        });
        throw errors.platformSnapshotDegraded({
          reason: 'db-deadlock'
        });
      }
      if (syncResult?.reason === 'role-facts-table-missing') {
        rejectNoDomainAccess({
          requestId,
          userId,
          sessionId,
          entryDomain,
          tenantId: null,
          detail: 'platform role facts unavailable',
          permissionCode
        });
      }

      const normalizedSyncReason = String(syncResult?.reason || '').trim();
      const acceptedSyncReasons = new Set([
        'ok',
        'up-to-date',
        'already-empty'
      ]);
      if (!acceptedSyncReasons.has(normalizedSyncReason)) {
        addAuditEvent({
          type: 'auth.platform.snapshot.degraded',
          requestId,
          userId,
          sessionId,
          detail: `platform snapshot sync degraded: ${normalizedSyncReason || 'unknown'}`,
          metadata: {
            permission_code: permissionCode,
            entry_domain: entryDomain,
            tenant_id: null,
            degradation_reason: normalizedSyncReason || 'unknown'
          }
        });
        throw errors.platformSnapshotDegraded({
          reason: normalizedSyncReason || 'unknown'
        });
      }
    }

    if (typeof authStore.findPlatformPermissionByUserId !== 'function') {
      rejectNoDomainAccess({
        requestId,
        userId,
        sessionId,
        entryDomain,
        tenantId: null,
        detail: 'platform permission lookup unavailable',
        permissionCode
      });
    }

    const permissionContext = await authStore.findPlatformPermissionByUserId({
      userId: String(userId)
    });
    const normalized = normalizePlatformPermissionContext(permissionContext);
    if (!normalized) {
      addAuditEvent({
        type: 'auth.route.forbidden',
        requestId,
        userId,
        sessionId,
        detail: 'platform permission missing',
        metadata: {
          permission_code: permissionCode,
          entry_domain: entryDomain,
          tenant_id: null
        }
      });
      throw errors.forbidden();
    }
    return normalized;
  };

  const reconcileTenantSessionContext = async ({
    requestId,
    userId,
    sessionId,
    sessionContext,
    options
  }) => {
    if (sessionContext.entry_domain !== 'tenant') {
      return sessionContext;
    }

    if (!Array.isArray(options) || options.length === 0) {
      rejectNoDomainAccess({
        requestId,
        userId,
        sessionId,
        entryDomain: sessionContext.entry_domain,
        tenantId: null,
        detail: 'tenant entry without active tenant relationship'
      });
    }

    const optionTenantIds = new Set(options.map((option) => option.tenant_id));
    const currentActiveTenantId = normalizeTenantId(sessionContext.active_tenant_id);

    if (currentActiveTenantId && optionTenantIds.has(currentActiveTenantId)) {
      return sessionContext;
    }

    const nextActiveTenantId = options.length === 1 ? options[0].tenant_id : null;
    if (currentActiveTenantId && !optionTenantIds.has(currentActiveTenantId)) {
      addAuditEvent({
        type: 'auth.tenant.context.invalidated',
        requestId,
        userId,
        sessionId,
        detail: `active tenant no longer allowed: ${currentActiveTenantId}`,
        metadata: {
          entry_domain: sessionContext.entry_domain,
          tenant_id: currentActiveTenantId
        }
      });
    }

    if (currentActiveTenantId !== nextActiveTenantId) {
      if (typeof authStore.updateSessionContext !== 'function') {
        throw new Error('authStore.updateSessionContext is required');
      }
      await authStore.updateSessionContext({
        sessionId,
        entryDomain: 'tenant',
        activeTenantId: nextActiveTenantId
      });
      invalidateSessionCacheBySessionId(sessionId);
    }

    return {
      entry_domain: 'tenant',
      active_tenant_id: nextActiveTenantId
    };
  };

  const assertDomainAccess = async ({ requestId, userId, entryDomain }) => {
    const access = await getDomainAccessForUser(userId);
    const allowed = entryDomain === 'platform' ? access.platform : access.tenant;
    if (!allowed) {
      addAuditEvent({
        type: 'auth.domain.rejected',
        requestId,
        userId,
        detail: `domain access denied: ${entryDomain}`,
        metadata: {
          permission_code: null,
          entry_domain: entryDomain,
          tenant_id: null
        }
      });
      throw errors.noDomainAccess();
    }
    return access;
  };

  const assertRateLimit = async ({ requestId, phone, action }) => {
    const result = await rateLimitStore.consume({
      phone,
      action,
      limit: RATE_LIMIT_MAX_ATTEMPTS,
      windowSeconds: RATE_LIMIT_WINDOW_SECONDS,
      nowMs: now()
    });

    if (result.allowed) {
      return result;
    }

    addAuditEvent({
      type: 'auth.rate_limited',
      requestId,
      detail: `rate limit exceeded for ${action}`,
      metadata: {
        phone_masked: maskPhone(phone),
        rate_limit_action: action,
        retry_after_seconds: result.remainingSeconds
      }
    });

    throw errors.rateLimited({
      action,
      remainingSeconds: result.remainingSeconds,
      limit: RATE_LIMIT_MAX_ATTEMPTS,
      windowSeconds: RATE_LIMIT_WINDOW_SECONDS
    });
  };

  const issueAccessToken = ({ userId, sessionId, sessionVersion }) =>
    signJwt({
      privateKeyPem: jwtKeyPair.privateKey,
      ttlSeconds: ACCESS_TTL_SECONDS,
      payload: {
        sub: userId,
        sid: sessionId,
        sv: sessionVersion,
        jti: randomUUID(),
        typ: 'access'
      }
    });

  const issueRefreshToken = ({ userId, sessionId, sessionVersion, refreshTokenId }) =>
    signJwt({
      privateKeyPem: jwtKeyPair.privateKey,
      ttlSeconds: REFRESH_TTL_SECONDS,
      payload: {
        sub: userId,
        sid: sessionId,
        sv: sessionVersion,
        jti: refreshTokenId,
        typ: 'refresh'
      }
    });

  const issueLoginTokenPair = async ({
    userId,
    sessionId,
    sessionVersion
  }) => {
    const refreshTokenId = randomUUID();
    const refreshHash = tokenHash(refreshTokenId);
    const expiresAt = now() + REFRESH_TTL_SECONDS * 1000;

    await authStore.createRefreshToken({
      tokenHash: refreshHash,
      sessionId,
      userId,
      expiresAt
    });

    const accessToken = signJwt({
      privateKeyPem: jwtKeyPair.privateKey,
      ttlSeconds: ACCESS_TTL_SECONDS,
      payload: {
        sub: userId,
        sid: sessionId,
        sv: sessionVersion,
        jti: randomUUID(),
        typ: 'access'
      }
    });

    const refreshToken = issueRefreshToken({
      userId,
      sessionId,
      sessionVersion,
      refreshTokenId
    });

    return {
      accessToken,
      refreshToken,
      refreshHash
    };
  };

  const createSessionAndIssueLoginTokens = async ({
    userId,
    sessionVersion,
    entryDomain,
    activeTenantId
  }) => {
    const sessionId = randomUUID();
    await authStore.createSession({
      sessionId,
      userId,
      sessionVersion: Number(sessionVersion),
      entryDomain,
      activeTenantId
    });

    const { accessToken, refreshToken } = await issueLoginTokenPair({
      userId,
      sessionId,
      sessionVersion: Number(sessionVersion)
    });

    return {
      sessionId,
      accessToken,
      refreshToken,
      sessionContext: {
        entry_domain: entryDomain,
        active_tenant_id: normalizeTenantId(activeTenantId)
      }
    };
  };

  const assertValidAccessSession = async ({
    accessToken,
    requestId = 'request_id_unset'
  }) => {
    let payload;
    try {
      payload = verifyJwt({
        token: accessToken,
        publicKeyPem: jwtKeyPair.publicKey,
        expectedTyp: 'access'
      });
    } catch (_error) {
      addAccessInvalidAuditEvent({
        requestId,
        dispositionReason: 'access-token-malformed'
      });
      throw errors.invalidAccess();
    }

    const cacheKey = `${String(payload.sid)}:${String(payload.sub)}:${String(payload.sv)}`;
    if (accessSessionCacheTtlMs > 0) {
      const cached = accessSessionCache.get(cacheKey);
      if (cached && cached.expiresAt > now()) {
        return { payload, session: cached.session, user: cached.user };
      }
    }

    const [session, user] = await Promise.all([authStore.findSessionById(payload.sid), authStore.findUserById(payload.sub)]);

    const normalizedSessionStatus = String(session?.status || '').toLowerCase();
    const normalizedRevokedReason = String(
      session?.revokedReason || session?.revoked_reason || ''
    ).trim().toLowerCase();
    const revokedByCriticalStateChange = normalizedSessionStatus === 'revoked'
      && (
        normalizedRevokedReason === 'password-changed'
        || normalizedRevokedReason === 'platform-role-facts-changed'
        || normalizedRevokedReason === 'critical-state-changed'
      );
    if (!session || !user || normalizedSessionStatus !== 'active') {
      const dispositionReason = !session
        ? 'access-session-missing'
        : !user
          ? 'access-user-missing'
          : revokedByCriticalStateChange
            ? 'session-version-mismatch'
          : `access-session-${normalizedSessionStatus || 'invalid'}`;
      addAccessInvalidAuditEvent({
        requestId,
        payload,
        userId: payload?.sub || 'unknown',
        sessionId: payload?.sid || 'unknown',
        dispositionReason
      });
      throw errors.invalidAccess();
    }

    const boundUserMismatch = String(session.userId) !== String(payload.sub);
    const sessionVersionMismatch =
      Number(session.sessionVersion) !== Number(payload.sv)
      || Number(user.sessionVersion) !== Number(payload.sv);
    if (boundUserMismatch || sessionVersionMismatch) {
      const dispositionReason = boundUserMismatch
        ? 'access-token-binding-mismatch'
        : sessionVersionMismatch
          ? 'session-version-mismatch'
          : 'access-token-state-mismatch';
      addAccessInvalidAuditEvent({
        requestId,
        payload,
        userId: user.id || payload?.sub || 'unknown',
        sessionId: session.sessionId || session.session_id || payload?.sid || 'unknown',
        dispositionReason
      });
      throw errors.invalidAccess();
    }

    if (accessSessionCacheTtlMs > 0) {
      accessSessionCache.set(cacheKey, {
        session,
        user,
        expiresAt: now() + accessSessionCacheTtlMs
      });
    }
    return { payload, session, user };
  };

  const resolveAuthorizedSession = async ({
    requestId,
    accessToken,
    authorizationContext = null
  }) => {
    const authorizedSession = await assertValidAccessSession({
      accessToken,
      requestId
    });
    if (!authorizationContext || typeof authorizationContext !== 'object') {
      return authorizedSession;
    }

    const contextSession = authorizationContext.session;
    const contextUser = authorizationContext.user;
    if (!contextSession || !contextUser) {
      return authorizedSession;
    }

    const resolvedSessionId = String(
      authorizedSession.session?.sessionId || authorizedSession.session?.session_id || ''
    ).trim();
    const resolvedUserId = String(
      authorizedSession.user?.id || authorizedSession.user?.user_id || ''
    ).trim();
    const contextSessionId = String(
      contextSession?.sessionId || contextSession?.session_id || ''
    ).trim();
    const contextUserId = String(contextUser?.id || contextUser?.user_id || '').trim();

    if (
      resolvedSessionId.length === 0
      || resolvedUserId.length === 0
      || contextSessionId.length === 0
      || contextUserId.length === 0
      || resolvedSessionId !== contextSessionId
      || resolvedUserId !== contextUserId
    ) {
      const auditUserId = contextUserId || resolvedUserId || 'unknown';
      const auditSessionId = contextSessionId || resolvedSessionId || 'unknown';
      addAccessInvalidAuditEvent({
        requestId,
        userId: auditUserId,
        sessionId: auditSessionId,
        dispositionReason: 'access-authorization-context-mismatch'
      });
      throw errors.invalidAccess();
    }

    return authorizedSession;
  };

  const login = async ({ requestId, phone, password, entryDomain }) => {
    const normalizedPhone = normalizePhone(phone);
    const normalizedEntryDomain = normalizeEntryDomain(entryDomain);
    if (
      !normalizedPhone ||
      typeof password !== 'string' ||
      password.trim() === '' ||
      !normalizedEntryDomain
    ) {
      throw errors.invalidPayload();
    }

    const rateLimit = await assertRateLimit({
      requestId,
      phone: normalizedPhone,
      action: 'password_login'
    });

    const user = await authStore.findUserByPhone(normalizedPhone);
    const validCredentials = Boolean(
      user && isUserActive(user) && verifyPassword(password, user.passwordHash)
    );

    if (!validCredentials) {
      addAuditEvent({
        type: 'auth.login.failed',
        requestId,
        userId: user?.id,
        detail: 'invalid credentials or unavailable user',
        metadata: {
          phone_masked: maskPhone(normalizedPhone),
          session_id_hint: 'unknown'
        }
      });
      throw errors.loginFailed();
    }

    if (normalizedEntryDomain === 'platform') {
      const shouldProvisionDefaultPlatformDomain =
        await shouldProvisionDefaultPlatformDomainAccess({ userId: user.id });
      if (shouldProvisionDefaultPlatformDomain) {
        await ensureDefaultDomainAccessForUser({
          requestId,
          userId: user.id
        });
      }
    }
    if (normalizedEntryDomain === 'tenant') {
      await ensureTenantDomainAccessForUser({
        requestId,
        userId: user.id,
        entryDomain: normalizedEntryDomain
      });
    }

    await assertDomainAccess({
      requestId,
      userId: user.id,
      entryDomain: normalizedEntryDomain
    });
    const tenantOptions = normalizedEntryDomain === 'tenant'
      ? await getTenantOptionsForUser(user.id)
      : [];

    if (normalizedEntryDomain === 'tenant' && tenantOptions.length === 0) {
      addAuditEvent({
        type: 'auth.domain.rejected',
        requestId,
        userId: user.id,
        detail: 'tenant entry without active tenant relationship',
        metadata: {
          permission_code: null,
          entry_domain: normalizedEntryDomain,
          tenant_id: null
        }
      });
      throw errors.noDomainAccess();
    }

    const tenantSelectionRequired = normalizedEntryDomain === 'tenant' && tenantOptions.length > 1;
    const activeTenantId = normalizedEntryDomain === 'tenant' && tenantOptions.length === 1
      ? tenantOptions[0].tenant_id
      : null;

    const { sessionId, accessToken, refreshToken, sessionContext } = await createSessionAndIssueLoginTokens({
      userId: user.id,
      sessionVersion: Number(user.sessionVersion),
      entryDomain: normalizedEntryDomain,
      activeTenantId
    });

    addAuditEvent({
      type: 'auth.domain.bound',
      requestId,
      userId: user.id,
      sessionId,
      detail: `domain bound to session: ${normalizedEntryDomain}`,
      metadata: {
        entry_domain: normalizedEntryDomain,
        tenant_id: sessionContext.active_tenant_id
      }
    });

    addAuditEvent({
      type: 'auth.login.succeeded',
      requestId,
      userId: user.id,
      sessionId,
      metadata: {
        phone_masked: maskPhone(normalizedPhone),
        resend_after_seconds: rateLimit.remainingSeconds,
        entry_domain: normalizedEntryDomain,
        tenant_id: sessionContext.active_tenant_id
      }
    });

    const tenantPermissionContext = await getTenantPermissionContext({
      requestId,
      userId: user.id,
      sessionId,
      entryDomain: sessionContext.entry_domain,
      activeTenantId: sessionContext.active_tenant_id
    });

    return {
      token_type: 'Bearer',
      access_token: accessToken,
      refresh_token: refreshToken,
      expires_in: ACCESS_TTL_SECONDS,
      refresh_expires_in: REFRESH_TTL_SECONDS,
      session_id: sessionId,
      entry_domain: sessionContext.entry_domain,
      active_tenant_id: sessionContext.active_tenant_id,
      tenant_selection_required: tenantSelectionRequired,
      tenant_options: tenantOptions,
      tenant_permission_context: tenantPermissionContext,
      request_id: requestId || 'request_id_unset'
    };
  };

  const sendOtp = async ({ requestId, phone }) => {
    const normalizedPhone = normalizePhone(phone);
    if (!normalizedPhone) {
      throw errors.invalidPayload();
    }

    const currentTime = now();
    let lastSentAt = null;
    try {
      lastSentAt = await otpStore.getSentAt({ phone: normalizedPhone });
    } catch (error) {
      addAuditEvent({
        type: 'auth.otp.send.cooldown_check_failed',
        requestId,
        detail: `getSentAt failed: ${error.message}`,
        metadata: { phone_masked: maskPhone(normalizedPhone) }
      });
      throw errors.rateLimited({
        action: 'otp_send',
        remainingSeconds: OTP_RESEND_COOLDOWN_SECONDS,
        limit: 1,
        windowSeconds: OTP_RESEND_COOLDOWN_SECONDS
      });
    }

    if (lastSentAt !== null && lastSentAt !== undefined) {
      const lastSentAtMs = Number(lastSentAt);
      if (!Number.isFinite(lastSentAtMs) || lastSentAtMs <= 0) {
        addAuditEvent({
          type: 'auth.otp.send.cooldown_check_failed',
          requestId,
          detail: `getSentAt returned invalid value: ${String(lastSentAt)}`,
          metadata: { phone_masked: maskPhone(normalizedPhone) }
        });
        throw errors.rateLimited({
          action: 'otp_send',
          remainingSeconds: OTP_RESEND_COOLDOWN_SECONDS,
          limit: 1,
          windowSeconds: OTP_RESEND_COOLDOWN_SECONDS
        });
      }

      const cooldownEndsAt = lastSentAtMs + OTP_RESEND_COOLDOWN_SECONDS * 1000;
      if (cooldownEndsAt > currentTime) {
        const remainingSeconds = Math.ceil((cooldownEndsAt - currentTime) / 1000);
        addAuditEvent({
          type: 'auth.otp.send.cooldown',
          requestId,
          detail: 'otp resend within cooldown period',
          metadata: {
            phone_masked: maskPhone(normalizedPhone),
            resend_after_seconds: remainingSeconds
          }
        });
        throw errors.rateLimited({
          action: 'otp_send',
          remainingSeconds,
          limit: 1,
          windowSeconds: OTP_RESEND_COOLDOWN_SECONDS
        });
      }
    }

    await assertRateLimit({
      requestId,
      phone: normalizedPhone,
      action: 'otp_send'
    });

    const otpCode = String(randomInt(0, 10 ** OTP_CODE_LENGTH)).padStart(OTP_CODE_LENGTH, '0');
    const expiresAt = currentTime + OTP_TTL_SECONDS * 1000;

    try {
      await otpStore.upsertOtp({
        phone: normalizedPhone,
        code: otpCode,
        expiresAt
      });
    } catch (error) {
      addAuditEvent({
        type: 'auth.otp.send.failed',
        requestId,
        detail: `otp store failure: ${error.message}`,
        metadata: { phone_masked: maskPhone(normalizedPhone) }
      });
      throw error;
    }

    addAuditEvent({
      type: 'auth.otp.send.succeeded',
      requestId,
      detail: 'otp code issued',
      metadata: {
        phone_masked: maskPhone(normalizedPhone),
        resend_after_seconds: OTP_RESEND_COOLDOWN_SECONDS
      }
    });

    return {
      sent: true,
      resend_after_seconds: OTP_RESEND_COOLDOWN_SECONDS,
      request_id: requestId || 'request_id_unset'
    };
  };

  const loginWithOtp = async ({ requestId, phone, otpCode, entryDomain }) => {
    const normalizedPhone = normalizePhone(phone);
    const normalizedEntryDomain = normalizeEntryDomain(entryDomain);
    if (
      !normalizedPhone ||
      typeof otpCode !== 'string' ||
      !/^\d{6}$/.test(otpCode.trim()) ||
      !normalizedEntryDomain
    ) {
      throw errors.invalidPayload();
    }

    await assertRateLimit({
      requestId,
      phone: normalizedPhone,
      action: 'otp_login'
    });

    let verifyResult;
    try {
      verifyResult = await otpStore.verifyAndConsumeOtp({
        phone: normalizedPhone,
        code: otpCode.trim(),
        nowMs: now()
      });
    } catch (error) {
      addAuditEvent({
        type: 'auth.otp.login.failed',
        requestId,
        detail: `otp store failure: ${error.message}`,
        metadata: { phone_masked: maskPhone(normalizedPhone) }
      });
      throw error;
    }

    if (!verifyResult || verifyResult.ok !== true) {
      addAuditEvent({
        type: 'auth.otp.login.failed',
        requestId,
        detail: `otp rejected: ${verifyResult?.reason || 'unknown'}`,
        metadata: {
          phone_masked: maskPhone(normalizedPhone),
          session_id_hint: 'unknown'
        }
      });
      throw errors.otpFailed();
    }

    const user = await authStore.findUserByPhone(normalizedPhone);
    if (!user || !isUserActive(user)) {
      addAuditEvent({
        type: 'auth.otp.login.failed',
        requestId,
        userId: user?.id,
        detail: 'otp accepted but user unavailable',
        metadata: {
          phone_masked: maskPhone(normalizedPhone),
          session_id_hint: 'unknown'
        }
      });
      throw errors.otpFailed();
    }

    if (normalizedEntryDomain === 'platform') {
      const shouldProvisionDefaultPlatformDomain =
        await shouldProvisionDefaultPlatformDomainAccess({ userId: user.id });
      if (shouldProvisionDefaultPlatformDomain) {
        await ensureDefaultDomainAccessForUser({
          requestId,
          userId: user.id
        });
      }
    }
    if (normalizedEntryDomain === 'tenant') {
      await ensureTenantDomainAccessForUser({
        requestId,
        userId: user.id,
        entryDomain: normalizedEntryDomain
      });
    }

    await assertDomainAccess({
      requestId,
      userId: user.id,
      entryDomain: normalizedEntryDomain
    });
    const tenantOptions = normalizedEntryDomain === 'tenant'
      ? await getTenantOptionsForUser(user.id)
      : [];

    if (normalizedEntryDomain === 'tenant' && tenantOptions.length === 0) {
      addAuditEvent({
        type: 'auth.domain.rejected',
        requestId,
        userId: user.id,
        detail: 'tenant entry without active tenant relationship',
        metadata: {
          permission_code: null,
          entry_domain: normalizedEntryDomain,
          tenant_id: null
        }
      });
      throw errors.noDomainAccess();
    }

    const tenantSelectionRequired = normalizedEntryDomain === 'tenant' && tenantOptions.length > 1;
    const activeTenantId = normalizedEntryDomain === 'tenant' && tenantOptions.length === 1
      ? tenantOptions[0].tenant_id
      : null;

    const { sessionId, accessToken, refreshToken, sessionContext } = await createSessionAndIssueLoginTokens({
      userId: user.id,
      sessionVersion: Number(user.sessionVersion),
      entryDomain: normalizedEntryDomain,
      activeTenantId
    });

    addAuditEvent({
      type: 'auth.domain.bound',
      requestId,
      userId: user.id,
      sessionId,
      detail: `domain bound to session: ${normalizedEntryDomain}`,
      metadata: {
        entry_domain: normalizedEntryDomain,
        tenant_id: sessionContext.active_tenant_id
      }
    });

    addAuditEvent({
      type: 'auth.otp.login.succeeded',
      requestId,
      userId: user.id,
      sessionId,
      metadata: {
        phone_masked: maskPhone(normalizedPhone),
        entry_domain: normalizedEntryDomain,
        tenant_id: sessionContext.active_tenant_id
      }
    });

    const tenantPermissionContext = await getTenantPermissionContext({
      requestId,
      userId: user.id,
      sessionId,
      entryDomain: sessionContext.entry_domain,
      activeTenantId: sessionContext.active_tenant_id
    });

    return {
      token_type: 'Bearer',
      access_token: accessToken,
      refresh_token: refreshToken,
      expires_in: ACCESS_TTL_SECONDS,
      refresh_expires_in: REFRESH_TTL_SECONDS,
      session_id: sessionId,
      entry_domain: sessionContext.entry_domain,
      active_tenant_id: sessionContext.active_tenant_id,
      tenant_selection_required: tenantSelectionRequired,
      tenant_options: tenantOptions,
      tenant_permission_context: tenantPermissionContext,
      request_id: requestId || 'request_id_unset'
    };
  };

  const refresh = async ({ requestId, refreshToken }) => {
    if (typeof refreshToken !== 'string' || refreshToken.trim() === '') {
      addAuditEvent({
        type: 'auth.refresh.replay_or_invalid',
        requestId,
        detail: 'refresh payload missing',
        metadata: {
          session_id_hint: 'unknown',
          disposition_reason: 'refresh-payload-missing',
          disposition_action: 'reject-only'
        }
      });
      throw errors.invalidPayload();
    }

    let payload;
    try {
      payload = verifyJwt({
        token: refreshToken,
        publicKeyPem: jwtKeyPair.publicKey,
        expectedTyp: 'refresh'
      });
    } catch (error) {
      const isExpiredRefreshToken = String(error?.code || '').trim().toUpperCase() === 'JWT_EXPIRED';
      const expiredPayload = isExpiredRefreshToken && error?.payload && typeof error.payload === 'object'
        ? error.payload
        : null;
      const expiredUserId = expiredPayload?.sub ? String(expiredPayload.sub) : 'unknown';
      const expiredSessionId = expiredPayload?.sid ? String(expiredPayload.sid) : 'unknown';
      addAuditEvent({
        type: 'auth.refresh.replay_or_invalid',
        requestId,
        userId: isExpiredRefreshToken ? expiredUserId : 'unknown',
        sessionId: isExpiredRefreshToken ? expiredSessionId : 'unknown',
        detail: isExpiredRefreshToken ? 'refresh token expired' : 'refresh token malformed',
        metadata: {
          session_id_hint: isExpiredRefreshToken ? expiredSessionId : 'unknown',
          disposition_reason: isExpiredRefreshToken
            ? 'refresh-token-expired'
            : 'refresh-token-malformed',
          disposition_action: 'reject-only'
        }
      });
      throw errors.invalidRefresh();
    }

    const refreshHash = tokenHash(String(payload.jti || ''));
    const [refreshRecord, session, user] = await Promise.all([
      authStore.findRefreshTokenByHash(refreshHash),
      authStore.findSessionById(payload.sid),
      authStore.findUserById(payload.sub)
    ]);

    const refreshStatus = refreshRecord ? String(refreshRecord.status).toLowerCase() : 'missing';
    const refreshExpired = Boolean(refreshRecord) && refreshRecord.expiresAt <= now();
    const refreshBelongsToClaim = Boolean(
      refreshRecord
      && String(refreshRecord.sessionId || '') === String(payload.sid || '')
      && String(refreshRecord.userId || '') === String(payload.sub || '')
    );

    const sessionVersionMismatch = Boolean(session && user)
      && (
        Number(session.sessionVersion) !== Number(payload.sv)
        || Number(user.sessionVersion) !== Number(payload.sv)
      );
    const invalidState = (
      !refreshRecord ||
      !refreshBelongsToClaim ||
      refreshStatus !== 'active' ||
      refreshExpired ||
      !session ||
      String(session.status).toLowerCase() !== 'active' ||
      !user ||
      String(session.userId) !== String(user.id) ||
      sessionVersionMismatch
    );

    if (invalidState) {
      const replayDetected = refreshBelongsToClaim
        && (refreshStatus === 'rotated' || refreshStatus === 'revoked');
      const dispositionReason = !refreshRecord
          ? 'refresh-token-missing'
          : !refreshBelongsToClaim
            ? 'refresh-token-binding-mismatch'
          : refreshExpired
            ? 'refresh-token-expired'
            : sessionVersionMismatch
              ? 'session-version-mismatch'
            : replayDetected
              ? 'refresh-replay-detected'
            : refreshStatus === 'active'
              ? 'refresh-token-state-mismatch'
              : `refresh-token-${refreshStatus}`;

      if (refreshRecord && refreshStatus === 'active' && refreshBelongsToClaim) {
        await authStore.markRefreshTokenStatus({
          tokenHash: refreshHash,
          status: 'revoked'
        });
      }

      if (replayDetected) {
        await authStore.revokeSession({
          sessionId: refreshRecord.sessionId || payload.sid,
          reason: 'refresh-replay-detected'
        });
        invalidateSessionCacheBySessionId(refreshRecord.sessionId || payload.sid);
      }

      addAuditEvent({
        type: 'auth.refresh.replay_or_invalid',
        requestId,
        userId: payload.sub,
        sessionId: payload.sid,
        detail: 'refresh token rejected',
        metadata: {
          session_id_hint: String(payload.sid || 'unknown'),
          refresh_status: refreshStatus,
          disposition_reason: dispositionReason,
          disposition_action: replayDetected
            ? 'revoke-session-chain'
            : refreshStatus === 'active' && refreshBelongsToClaim
              ? 'revoke-current-token'
              : 'reject-only'
        }
      });
      throw errors.invalidRefresh();
    }

    const sessionId = session.sessionId || session.session_id || payload.sid;
    const nextRefreshTokenId = randomUUID();
    const nextRefreshHash = tokenHash(nextRefreshTokenId);
    const nextRefreshExpiresAt = now() + REFRESH_TTL_SECONDS * 1000;

    if (typeof authStore.rotateRefreshToken === 'function') {
      const rotated = await authStore.rotateRefreshToken({
        previousTokenHash: refreshHash,
        nextTokenHash: nextRefreshHash,
        sessionId,
        userId: user.id,
        expiresAt: nextRefreshExpiresAt
      });

      if (!rotated || rotated.ok !== true) {
        await authStore.revokeSession({
          sessionId,
          reason: 'refresh-rotation-conflict'
        });
        invalidateSessionCacheBySessionId(sessionId);
        addAuditEvent({
          type: 'auth.refresh.replay_or_invalid',
          requestId,
          userId: user.id,
          sessionId,
          detail: 'refresh token rejected by rotation conflict',
          metadata: {
            session_id_hint: String(sessionId || 'unknown'),
            disposition_reason: 'refresh-rotation-conflict',
            disposition_action: 'revoke-session-chain'
          }
        });
        throw errors.invalidRefresh();
      }
    } else {
      await authStore.markRefreshTokenStatus({
        tokenHash: refreshHash,
        status: 'rotated'
      });

      await authStore.createRefreshToken({
        tokenHash: nextRefreshHash,
        sessionId,
        userId: user.id,
        expiresAt: nextRefreshExpiresAt
      });

      await authStore.linkRefreshRotation({
        previousTokenHash: refreshHash,
        nextTokenHash: nextRefreshHash
      });
    }

    const accessToken = issueAccessToken({
      userId: user.id,
      sessionId,
      sessionVersion: Number(user.sessionVersion)
    });
    const nextRefreshToken = issueRefreshToken({
      userId: user.id,
      sessionId,
      sessionVersion: Number(user.sessionVersion),
      refreshTokenId: nextRefreshTokenId
    });
    let sessionContext = buildSessionContext(session);
    const refreshedTenantOptions = sessionContext.entry_domain === 'tenant'
      ? await getTenantOptionsForUser(user.id)
      : [];
    sessionContext = await reconcileTenantSessionContext({
      requestId,
      userId: user.id,
      sessionId,
      sessionContext,
      options: refreshedTenantOptions
    });
    const tenantSelectionRequired = sessionContext.entry_domain === 'tenant'
      && refreshedTenantOptions.length > 1
      && !sessionContext.active_tenant_id;
    const tenantPermissionContext = await getTenantPermissionContext({
      requestId,
      userId: user.id,
      sessionId,
      entryDomain: sessionContext.entry_domain,
      activeTenantId: sessionContext.active_tenant_id
    });

    addAuditEvent({
      type: 'auth.refresh.succeeded',
      requestId,
      userId: user.id,
      sessionId
    });

    return {
      token_type: 'Bearer',
      access_token: accessToken,
      refresh_token: nextRefreshToken,
      expires_in: ACCESS_TTL_SECONDS,
      refresh_expires_in: REFRESH_TTL_SECONDS,
      session_id: sessionId,
      entry_domain: sessionContext.entry_domain,
      active_tenant_id: sessionContext.active_tenant_id,
      tenant_selection_required: tenantSelectionRequired,
      tenant_options: refreshedTenantOptions,
      tenant_permission_context: tenantPermissionContext,
      request_id: requestId || 'request_id_unset'
    };
  };

  const logout = async ({ requestId, accessToken, authorizationContext = null }) => {
    const { session, user } = await resolveAuthorizedSession({
      requestId,
      accessToken,
      authorizationContext
    });
    const sessionId = session.sessionId || session.session_id;
    await authStore.revokeSession({
      sessionId,
      reason: 'logout-current-session'
    });
    invalidateSessionCacheBySessionId(sessionId);

    addAuditEvent({
      type: 'auth.logout.current_session',
      requestId,
      userId: user.id,
      sessionId
    });

    return {
      ok: true,
      session_id: sessionId,
      request_id: requestId || 'request_id_unset'
    };
  };

  const changePassword = async ({
    requestId,
    accessToken,
    currentPassword,
    newPassword,
    authorizationContext = null
  }) => {
    if (typeof currentPassword !== 'string' || typeof newPassword !== 'string') {
      addAuditEvent({
        type: 'auth.password_change.rejected',
        requestId,
        detail: 'password payload invalid',
        metadata: {
          session_id_hint: 'unknown'
        }
      });
      throw errors.invalidPayload();
    }

    try {
      validatePasswordPolicy(newPassword);
    } catch (error) {
      addAuditEvent({
        type: 'auth.password_change.rejected',
        requestId,
        detail: 'new password policy violation',
        metadata: {
          session_id_hint: 'unknown'
        }
      });
      throw error;
    }

    const { session, user } = await resolveAuthorizedSession({
      requestId,
      accessToken,
      authorizationContext
    });
    const currentPasswordValid = verifyPassword(currentPassword, user.passwordHash);

    if (!currentPasswordValid) {
      addAuditEvent({
        type: 'auth.password_change.rejected',
        requestId,
        userId: user.id,
        sessionId: session.sessionId || session.session_id,
        detail: 'current password mismatch',
        metadata: {
          phone_masked: maskPhone(user.phone)
        }
      });
      throw errors.loginFailed();
    }

    const updatedUser = typeof authStore.updateUserPasswordAndRevokeSessions === 'function'
      ? await authStore.updateUserPasswordAndRevokeSessions({
        userId: user.id,
        passwordHash: hashPassword(newPassword),
        reason: 'password-changed'
      })
      : await authStore.updateUserPasswordAndBumpSessionVersion({
        userId: user.id,
        passwordHash: hashPassword(newPassword)
      });
    if (!updatedUser) {
      throw errors.invalidAccess();
    }
    if (typeof authStore.updateUserPasswordAndRevokeSessions !== 'function') {
      await authStore.revokeAllUserSessions({
        userId: user.id,
        reason: 'password-changed'
      });
    }
    invalidateSessionCacheByUserId(user.id);

    addAuditEvent({
      type: 'auth.password_change.succeeded',
      requestId,
      userId: user.id,
      sessionId: session.sessionId || session.session_id
    });

    return {
      password_changed: true,
      relogin_required: true,
      request_id: requestId || 'request_id_unset'
    };
  };

  const mapPlatformRoleCatalogLookupErrorToProblem = (error) => {
    if (isMissingPlatformRoleCatalogTableError(error)) {
      return errors.platformSnapshotDegraded({
        reason: 'platform-role-catalog-unavailable'
      });
    }
    return errors.platformSnapshotDegraded({
      reason: 'platform-role-catalog-query-failed'
    });
  };

  const assertPlatformRoleCatalogLookupCapability = () => {
    if (typeof authStore.findPlatformRoleCatalogEntriesByRoleIds !== 'function') {
      throw errors.platformSnapshotDegraded({
        reason: 'platform-role-catalog-lookup-unsupported'
      });
    }
  };

  const assertPlatformRoleCatalogDependencyAvailable = async () => {
    assertPlatformRoleCatalogLookupCapability();
    if (typeof authStore.countPlatformRoleCatalogEntries === 'function') {
      try {
        await authStore.countPlatformRoleCatalogEntries();
        return;
      } catch (error) {
        throw mapPlatformRoleCatalogLookupErrorToProblem(error);
      }
    }
    try {
      await authStore.findPlatformRoleCatalogEntriesByRoleIds({
        roleIds: ['__platform_role_catalog_health_probe__']
      });
    } catch (error) {
      throw mapPlatformRoleCatalogLookupErrorToProblem(error);
    }
  };

  const loadValidatedPlatformRoleCatalogEntriesForRoleFacts = async ({
    roles = [],
    allowDisabledRoles = false
  }) => {
    if (!Array.isArray(roles) || roles.length === 0) {
      await assertPlatformRoleCatalogDependencyAvailable();
      return {
        requestedRoleIds: [],
        catalogEntriesByRoleIdKey: new Map()
      };
    }
    assertPlatformRoleCatalogLookupCapability();

    const requestedRoleIds = [];
    const requestedRoleIdKeys = new Set();
    for (const role of roles) {
      const roleId = normalizeRequiredStringField(
        resolveRawRoleIdCandidate(role),
        errors.invalidPayload
      );
      const roleIdKey = normalizePlatformRoleIdKey(roleId);
      if (requestedRoleIdKeys.has(roleIdKey)) {
        continue;
      }
      requestedRoleIds.push(roleId);
      requestedRoleIdKeys.add(roleIdKey);
    }

    let catalogEntries = [];
    try {
      catalogEntries = await authStore.findPlatformRoleCatalogEntriesByRoleIds({
        roleIds: requestedRoleIds
      });
    } catch (error) {
      throw mapPlatformRoleCatalogLookupErrorToProblem(error);
    }
    const catalogEntriesByRoleIdKey = new Map();
    for (const catalogEntry of Array.isArray(catalogEntries) ? catalogEntries : []) {
      const roleId = String(
        catalogEntry?.roleId
        || catalogEntry?.role_id
        || ''
      ).trim();
      if (!roleId) {
        continue;
      }
      catalogEntriesByRoleIdKey.set(
        normalizePlatformRoleIdKey(roleId),
        catalogEntry
      );
    }

    for (const roleId of requestedRoleIds) {
      const roleIdKey = normalizePlatformRoleIdKey(roleId);
      const catalogEntry = catalogEntriesByRoleIdKey.get(roleIdKey);
      if (!catalogEntry) {
        throw errors.invalidPayload();
      }

      const normalizedStatus = normalizePlatformRoleCatalogStatus(
        catalogEntry?.status
      );
      const normalizedScope = normalizePlatformRoleCatalogScope(
        catalogEntry?.scope
      );
      if (
        !VALID_PLATFORM_ROLE_CATALOG_STATUS.has(normalizedStatus)
        || (!allowDisabledRoles && normalizedStatus === 'disabled')
        || normalizedScope !== PLATFORM_ROLE_CATALOG_SCOPE
      ) {
        throw errors.invalidPayload();
      }
    }

    return {
      requestedRoleIds,
      catalogEntriesByRoleIdKey
    };
  };

  const loadPlatformRolePermissionGrantsByRoleIds = async ({
    roleIds = []
  }) => {
    const normalizedRoleIds = [...new Set(
      (Array.isArray(roleIds) ? roleIds : [])
        .map((roleId) => normalizeRequiredStringField(roleId, errors.invalidPayload))
    )];
    if (normalizedRoleIds.length === 0) {
      return new Map();
    }

    if (typeof authStore.listPlatformRolePermissionGrantsByRoleIds !== 'function') {
      throw errors.platformSnapshotDegraded({
        reason: 'platform-role-permission-grants-unsupported'
      });
    }

    let grantEntries = [];
    try {
      grantEntries = await authStore.listPlatformRolePermissionGrantsByRoleIds({
        roleIds: normalizedRoleIds
      });
    } catch (_error) {
      throw errors.platformSnapshotDegraded({
        reason: 'platform-role-permission-grants-query-failed'
      });
    }

    const grantsByRoleIdKey = new Map();
    for (const roleId of normalizedRoleIds) {
      grantsByRoleIdKey.set(normalizePlatformRoleIdKey(roleId), []);
    }

    for (const grantEntry of Array.isArray(grantEntries) ? grantEntries : []) {
      const roleId = String(
        (grantEntry?.roleId ?? grantEntry?.role_id) || ''
      ).trim();
      if (!roleId) {
        throw errors.platformSnapshotDegraded({
          reason: 'platform-role-permission-grants-invalid'
        });
      }
      const roleIdKey = normalizePlatformRoleIdKey(roleId);
      if (!grantsByRoleIdKey.has(roleIdKey)) {
        continue;
      }
      const hasPermissionCodes = (
        Array.isArray(grantEntry?.permissionCodes)
        || Array.isArray(grantEntry?.permission_codes)
      );
      if (!hasPermissionCodes) {
        throw errors.platformSnapshotDegraded({
          reason: 'platform-role-permission-grants-invalid'
        });
      }
      const permissionCodes = Array.isArray(grantEntry?.permissionCodes)
        ? grantEntry.permissionCodes
        : grantEntry.permission_codes;
      const dedupedCodes = new Map();
      for (const permissionCode of permissionCodes) {
        const normalizedPermissionCode = normalizePlatformPermissionCode(permissionCode);
        if (!normalizedPermissionCode) {
          continue;
        }
        const permissionCodeKey = toPlatformPermissionCodeKey(normalizedPermissionCode);
        if (
          !isPlatformPermissionCode(normalizedPermissionCode)
          || !SUPPORTED_PLATFORM_PERMISSION_CODE_SET.has(permissionCodeKey)
        ) {
          throw errors.platformSnapshotDegraded({
            reason: 'platform-role-permission-grants-invalid'
          });
        }
        dedupedCodes.set(permissionCodeKey, permissionCodeKey);
      }
      grantsByRoleIdKey.set(roleIdKey, [...dedupedCodes.values()]);
    }

    return grantsByRoleIdKey;
  };

  const normalizePlatformRoleFactsForReplace = async ({
    roles = [],
    enforceRoleCatalogValidation = false
  }) => {
    const normalizedRoleFacts = [];
    const distinctRoleIds = new Set();

    for (const role of roles) {
      if (!isPlainObject(role)) {
        throw errors.invalidPayload();
      }

      const unknownRoleKeys = Object.keys(role).filter(
        (key) => !PLATFORM_ROLE_ASSIGNMENT_ALLOWED_FIELDS.has(key) && key !== 'permission'
      );
      if (enforceRoleCatalogValidation && unknownRoleKeys.length > 0) {
        throw errors.invalidPayload();
      }

      const hasPermissionField = hasOwnProperty(role, 'permission');
      if (
        enforceRoleCatalogValidation
        && (hasPermissionField || hasTopLevelPlatformRolePermissionField(role))
      ) {
        throw errors.invalidPayload();
      }
      if (!enforceRoleCatalogValidation && hasPermissionField && !isPlainObject(role.permission)) {
        throw errors.invalidPayload();
      }
      if (!enforceRoleCatalogValidation && hasTopLevelPlatformRolePermissionField(role)) {
        throw errors.invalidPayload();
      }

      const rawRoleId = resolveRawRoleIdCandidate(role);
      const normalizedRoleId = normalizeRequiredStringField(
        rawRoleId,
        errors.invalidPayload
      );
      const normalizedRoleIdKey = normalizePlatformRoleIdKey(normalizedRoleId);
      if (normalizedRoleIdKey.length > MAX_PLATFORM_ROLE_ID_LENGTH) {
        throw errors.invalidPayload();
      }
      if (distinctRoleIds.has(normalizedRoleIdKey)) {
        throw errors.invalidPayload();
      }
      distinctRoleIds.add(normalizedRoleIdKey);

      let normalizedRoleStatus = 'active';
      if (hasOwnProperty(role, 'status')) {
        if (typeof role.status !== 'string') {
          throw errors.invalidPayload();
        }
        normalizedRoleStatus = role.status.trim().toLowerCase();
        if (!normalizedRoleStatus) {
          throw errors.invalidPayload();
        }
      }
      if (!VALID_PLATFORM_ROLE_FACT_STATUS.has(normalizedRoleStatus)) {
        throw errors.invalidPayload();
      }
      const resolvedRoleStatus = normalizedRoleStatus === 'enabled'
        ? 'active'
        : normalizedRoleStatus;
      if (enforceRoleCatalogValidation && resolvedRoleStatus !== 'active') {
        throw errors.invalidPayload();
      }

      if (!enforceRoleCatalogValidation) {
        const rolePermissionSource = hasPermissionField ? role.permission : {};
        assertOptionalBooleanRolePermission(
          rolePermissionSource?.canViewMemberAdmin ?? rolePermissionSource?.can_view_member_admin,
          errors.invalidPayload
        );
        assertOptionalBooleanRolePermission(
          rolePermissionSource?.canOperateMemberAdmin ?? rolePermissionSource?.can_operate_member_admin,
          errors.invalidPayload
        );
        assertOptionalBooleanRolePermission(
          rolePermissionSource?.canViewBilling ?? rolePermissionSource?.can_view_billing,
          errors.invalidPayload
        );
        assertOptionalBooleanRolePermission(
          rolePermissionSource?.canOperateBilling ?? rolePermissionSource?.can_operate_billing,
          errors.invalidPayload
        );
        normalizedRoleFacts.push({
          roleId: normalizedRoleIdKey,
          status: resolvedRoleStatus,
          permission: {
            canViewMemberAdmin: Boolean(
              rolePermissionSource?.canViewMemberAdmin
              ?? rolePermissionSource?.can_view_member_admin
            ),
            canOperateMemberAdmin: Boolean(
              rolePermissionSource?.canOperateMemberAdmin
              ?? rolePermissionSource?.can_operate_member_admin
            ),
            canViewBilling: Boolean(
              rolePermissionSource?.canViewBilling
              ?? rolePermissionSource?.can_view_billing
            ),
            canOperateBilling: Boolean(
              rolePermissionSource?.canOperateBilling
              ?? rolePermissionSource?.can_operate_billing
            )
          }
        });
        continue;
      }

      normalizedRoleFacts.push({
        roleId: normalizedRoleIdKey,
        status: resolvedRoleStatus
      });
    }

    if (!enforceRoleCatalogValidation) {
      return normalizedRoleFacts;
    }

    const { requestedRoleIds } =
      await loadValidatedPlatformRoleCatalogEntriesForRoleFacts({
        roles: normalizedRoleFacts
      });
    const grantsByRoleIdKey = await loadPlatformRolePermissionGrantsByRoleIds({
      roleIds: requestedRoleIds
    });

    return normalizedRoleFacts.map((roleFact) => {
      const roleIdKey = normalizePlatformRoleIdKey(roleFact.roleId);
      const permissionCodes = grantsByRoleIdKey.get(roleIdKey) || [];
      return {
        roleId: roleFact.roleId,
        status: 'active',
        permission: toPlatformPermissionSnapshotFromCodes(permissionCodes)
      };
    });
  };

  const replacePlatformRolesAndSyncSnapshot = async ({
    requestId,
    accessToken = null,
    userId,
    roles,
    authorizationContext = null,
    enforceRoleCatalogValidation = false
  }) => {
    if (typeof authStore.replacePlatformRolesAndSyncSnapshot !== 'function') {
      throw new Error('authStore.replacePlatformRolesAndSyncSnapshot is required');
    }

    const normalizedAccessToken = typeof accessToken === 'string'
      ? accessToken.trim()
      : '';
    if (normalizedAccessToken.length === 0) {
      throw errors.invalidAccess();
    }
    const authorizedRoute = await authorizeRoute({
      requestId,
      accessToken: normalizedAccessToken,
      permissionCode: PLATFORM_ROLE_FACTS_REPLACE_PERMISSION_CODE,
      scope: 'platform',
      authorizationContext
    });
    const operatorUserId = String(
      authorizedRoute?.user_id || authorizedRoute?.user?.id || ''
    ).trim() || null;
    const operatorSessionId = String(
      authorizedRoute?.session_id || authorizedRoute?.session?.sessionId || ''
    ).trim() || null;

    const normalizedUserId = normalizeRequiredStringField(
      userId,
      errors.invalidPayload
    );
    if (!Array.isArray(roles)) {
      throw errors.invalidPayload();
    }
    if (enforceRoleCatalogValidation && roles.length === 0) {
      throw errors.invalidPayload();
    }
    if (roles.length > MAX_PLATFORM_ROLE_FACTS_PER_USER) {
      throw errors.invalidPayload();
    }
    const rolesForPersistence = await normalizePlatformRoleFactsForReplace({
      roles,
      enforceRoleCatalogValidation
    });

    const hasUserLookup = typeof authStore.findUserById === 'function';
    const previousUser = hasUserLookup
      ? await authStore.findUserById(normalizedUserId)
      : null;
    if (hasUserLookup && !previousUser) {
      throw errors.invalidPayload();
    }
    let result;
    try {
      result = await authStore.replacePlatformRolesAndSyncSnapshot({
        userId: normalizedUserId,
        roles: rolesForPersistence
      });
    } catch (error) {
      if (
        error instanceof Error
        && String(error.message || '').includes('invalid platform role status')
      ) {
        throw errors.invalidPayload();
      }
      if (isDuplicateRoleFactEntryError(error)) {
        throw errors.invalidPayload();
      }
      if (isDataTooLongRoleFactError(error)) {
        throw errors.invalidPayload();
      }
      throw error;
    }
    const syncReason = String(result?.reason || 'unknown').trim().toLowerCase();
    if (syncReason === 'invalid-user-id') {
      throw errors.invalidPayload();
    }
    if (syncReason === 'db-deadlock' || syncReason === 'concurrent-role-facts-update') {
      throw errors.platformSnapshotDegraded({
        reason: syncReason
      });
    }
    if (syncReason !== 'ok') {
      throw errors.platformSnapshotDegraded({
        reason: syncReason || 'unknown'
      });
    }

    const nextUser = hasUserLookup
      ? await authStore.findUserById(normalizedUserId)
      : null;
    const sessionVersionChanged = Boolean(
      previousUser
      && nextUser
      && Number(nextUser.sessionVersion) !== Number(previousUser.sessionVersion)
    );

    if (sessionVersionChanged || !hasUserLookup) {
      invalidateSessionCacheByUserId(normalizedUserId);
    }

    addAuditEvent({
      type: 'auth.platform_role_facts.updated',
      requestId,
      userId: normalizedUserId,
      sessionId: operatorSessionId || 'unknown',
      detail: 'platform role facts replaced and snapshot synced',
      metadata: {
        actor_user_id: operatorUserId,
        actor_session_id: operatorSessionId,
        target_user_id: normalizedUserId,
        session_version_changed: sessionVersionChanged,
        sync_reason: syncReason || 'unknown'
      }
    });

    return result;
  };

  const tenantOptions = async ({
    requestId,
    accessToken,
    authorizationContext = null
  }) => {
    const { session, user } = await resolveAuthorizedSession({
      requestId,
      accessToken,
      authorizationContext
    });
    const sessionId = session.sessionId || session.session_id;
    let sessionContext = buildSessionContext(session);
    if (sessionContext.entry_domain !== 'tenant') {
      rejectNoDomainAccess({
        requestId,
        userId: user.id,
        sessionId,
        entryDomain: sessionContext.entry_domain,
        tenantId: null,
        detail: `tenant options rejected for entry domain ${sessionContext.entry_domain}`
      });
    }
    const options = await getTenantOptionsForUser(user.id);
    sessionContext = await reconcileTenantSessionContext({
      requestId,
      userId: user.id,
      sessionId,
      sessionContext,
      options
    });
    const selectionRequired = sessionContext.entry_domain === 'tenant'
      && options.length > 1
      && !sessionContext.active_tenant_id;

    const tenantPermissionContext = await getTenantPermissionContext({
      requestId,
      userId: user.id,
      sessionId,
      entryDomain: sessionContext.entry_domain,
      activeTenantId: sessionContext.active_tenant_id
    });

    return {
      session_id: sessionId,
      entry_domain: sessionContext.entry_domain,
      active_tenant_id: sessionContext.active_tenant_id,
      tenant_selection_required: selectionRequired,
      tenant_options: options,
      tenant_permission_context: tenantPermissionContext,
      request_id: requestId || 'request_id_unset'
    };
  };

  const authorizeRoute = async ({
    requestId,
    accessToken,
    permissionCode,
    scope = 'session',
    authorizationContext = null,
    authorizedSession = null
  }) => {
    const normalizedPermissionCode = String(permissionCode || '').trim();
    if (normalizedPermissionCode.length === 0) {
      throw errors.forbidden();
    }

    const resolvedSession = authorizedSession && typeof authorizedSession === 'object'
      ? authorizedSession
      : await resolveAuthorizedSession({
        requestId,
        accessToken,
        authorizationContext
      });
    const { session, user } = resolvedSession;
    const sessionId = session.sessionId || session.session_id;
    const sessionContext = buildSessionContext(session);
    const normalizedScope = String(scope || 'session').trim().toLowerCase();
    const normalizedActiveTenantId = normalizeTenantId(sessionContext.active_tenant_id);

    if (normalizedScope === 'tenant' && sessionContext.entry_domain !== 'tenant') {
      addAuditEvent({
        type: 'auth.route.forbidden',
        requestId,
        userId: user.id,
        sessionId,
        detail: `tenant scoped route blocked in ${sessionContext.entry_domain} entry`,
        metadata: {
          permission_code: normalizedPermissionCode,
          entry_domain: sessionContext.entry_domain,
          tenant_id: sessionContext.active_tenant_id
        }
      });
      throw errors.noDomainAccess();
    }
    if (normalizedScope === 'platform' && sessionContext.entry_domain !== 'platform') {
      addAuditEvent({
        type: 'auth.route.forbidden',
        requestId,
        userId: user.id,
        sessionId,
        detail: `platform scoped route blocked in ${sessionContext.entry_domain} entry`,
        metadata: {
          permission_code: normalizedPermissionCode,
          entry_domain: sessionContext.entry_domain,
          tenant_id: sessionContext.active_tenant_id
        }
      });
      throw errors.noDomainAccess();
    }
    if (
      normalizedScope === 'tenant'
      && sessionContext.entry_domain === 'tenant'
      && !normalizedActiveTenantId
      && !TENANT_SCOPE_ALLOWED_WITHOUT_ACTIVE_TENANT.has(normalizedPermissionCode)
    ) {
      addAuditEvent({
        type: 'auth.route.forbidden',
        requestId,
        userId: user.id,
        sessionId,
        detail: 'tenant scoped route blocked without active tenant context',
        metadata: {
          permission_code: normalizedPermissionCode,
          entry_domain: sessionContext.entry_domain,
          tenant_id: null
        }
      });
      throw errors.noDomainAccess();
    }

    const shouldResolveTenantPermissionContext =
      normalizedScope === 'tenant'
      && !TENANT_SCOPE_ALLOWED_WITHOUT_ACTIVE_TENANT.has(normalizedPermissionCode);
    const shouldResolvePlatformPermissionContext = normalizedScope === 'platform';

    const tenantPermissionContext = shouldResolveTenantPermissionContext
      ? await getTenantPermissionContext({
        requestId,
        userId: user.id,
        sessionId,
        entryDomain: sessionContext.entry_domain,
        activeTenantId: normalizedActiveTenantId
      })
      : null;
    const platformPermissionContext = shouldResolvePlatformPermissionContext
      ? await getPlatformPermissionContext({
        requestId,
        userId: user.id,
        sessionId,
        entryDomain: sessionContext.entry_domain,
        permissionCode: normalizedPermissionCode
      })
      : null;

    const evaluator = ROUTE_PERMISSION_EVALUATORS[normalizedPermissionCode];
    if (typeof evaluator !== 'function') {
      addAuditEvent({
        type: 'auth.route.forbidden',
        requestId,
        userId: user.id,
        sessionId,
        detail: `unknown permission code declaration: ${normalizedPermissionCode}`,
        metadata: {
          permission_code: normalizedPermissionCode,
          entry_domain: sessionContext.entry_domain,
          tenant_id: normalizedActiveTenantId
        }
      });
      throw errors.forbidden();
    }

    const allowed = evaluator({
      platformPermissionContext,
      tenantPermissionContext,
      entryDomain: sessionContext.entry_domain,
      activeTenantId: normalizedActiveTenantId
    });
    if (!allowed) {
      addAuditEvent({
        type: 'auth.route.forbidden',
        requestId,
        userId: user.id,
        sessionId,
        detail: `permission denied: ${normalizedPermissionCode}`,
        metadata: {
          permission_code: normalizedPermissionCode,
          entry_domain: sessionContext.entry_domain,
          tenant_id: normalizedActiveTenantId
        }
      });
      throw errors.forbidden();
    }

    return {
      session_id: sessionId,
      user_id: user.id,
      entry_domain: sessionContext.entry_domain,
      active_tenant_id: normalizedActiveTenantId || null,
      platform_permission_context: platformPermissionContext,
      tenant_permission_context: tenantPermissionContext,
      session,
      user
    };
  };

  const resolveDefaultProvisioningPassword = async ({
    requestId,
    operatorUserId,
    operatorSessionId
  }) => {
    if (
      !sensitiveConfigProvider
      || typeof sensitiveConfigProvider.getEncryptedConfig !== 'function'
    ) {
      addAuditEvent({
        type: 'auth.user.provision.config_failed',
        requestId,
        userId: operatorUserId || 'unknown',
        sessionId: operatorSessionId || 'unknown',
        detail: 'default password config provider unavailable',
        metadata: {
          config_key: DEFAULT_PASSWORD_CONFIG_KEY,
          failure_reason: 'config-provider-unavailable'
        }
      });
      throw errors.provisioningConfigUnavailable();
    }

    let encryptedDefaultPassword;
    try {
      encryptedDefaultPassword = await sensitiveConfigProvider.getEncryptedConfig(
        DEFAULT_PASSWORD_CONFIG_KEY
      );
      const plainTextDefaultPassword = decryptSensitiveConfigValue({
        encryptedValue: encryptedDefaultPassword,
        decryptionKeys: sensitiveConfigDecryptionKeys,
        decryptionKey: sensitiveConfigDecryptionKey
      });
      validatePasswordPolicy(plainTextDefaultPassword);
      return plainTextDefaultPassword;
    } catch (error) {
      const failureReason = resolveProvisioningConfigFailureReason(error);
      addAuditEvent({
        type: 'auth.user.provision.config_failed',
        requestId,
        userId: operatorUserId || 'unknown',
        sessionId: operatorSessionId || 'unknown',
        detail: 'default password resolution failed',
        metadata: {
          config_key: DEFAULT_PASSWORD_CONFIG_KEY,
          failure_reason: failureReason
        }
      });
      throw errors.provisioningConfigUnavailable();
    }
  };

  const getOrCreateProvisionUserByPhone = async ({
    requestId,
    phone,
    operatorUserId,
    operatorSessionId
  }) => {
    const existingUser = await authStore.findUserByPhone(phone);
    if (existingUser) {
      return {
        user: existingUser,
        createdUser: false
      };
    }

    assertStoreMethod(authStore, 'createUserByPhone', 'authStore');
    const defaultPassword = await resolveDefaultProvisioningPassword({
      requestId,
      operatorUserId,
      operatorSessionId
    });
    let createdUser = null;
    try {
      createdUser = await authStore.createUserByPhone({
        phone,
        passwordHash: hashPassword(defaultPassword),
        status: 'active'
      });
    } catch (error) {
      if (isDataTooLongRoleFactError(error)) {
        throw errors.invalidPayload();
      }
      throw error;
    }
    if (createdUser) {
      return {
        user: createdUser,
        createdUser: true
      };
    }

    const reusedUser = await authStore.findUserByPhone(phone);
    if (reusedUser) {
      return {
        user: reusedUser,
        createdUser: false
      };
    }

    throw errors.provisionConflict();
  };

  const getOrCreateUserIdentityByPhone = async ({
    requestId,
    phone,
    operatorUserId = 'unknown',
    operatorSessionId = 'unknown'
  }) => {
    const normalizedPhone = normalizePhone(phone);
    if (!normalizedPhone) {
      throw errors.invalidPayload();
    }

    const resolvedUser = await getOrCreateProvisionUserByPhone({
      requestId,
      phone: normalizedPhone,
      operatorUserId,
      operatorSessionId
    });

    addAuditEvent({
      type: resolvedUser.createdUser
        ? 'auth.user.bootstrap.created'
        : 'auth.user.bootstrap.reused',
      requestId,
      userId: resolvedUser.user.id,
      sessionId: operatorSessionId,
      detail: resolvedUser.createdUser
        ? 'owner user created with default password policy'
        : 'owner user identity reused without credential mutation',
      metadata: {
        operator_user_id: operatorUserId,
        phone_masked: maskPhone(normalizedPhone),
        credential_initialized: resolvedUser.createdUser,
        first_login_force_password_change: false
      }
    });

    return {
      user_id: resolvedUser.user.id,
      phone: resolvedUser.user.phone,
      created_user: resolvedUser.createdUser,
      reused_existing_user: !resolvedUser.createdUser,
      credential_initialized: resolvedUser.createdUser,
      first_login_force_password_change: false
    };
  };

  const createOrganizationWithOwner = async ({
    orgId = randomUUID(),
    orgName,
    ownerUserId,
    operatorUserId
  }) => {
    assertStoreMethod(authStore, 'createOrganizationWithOwner', 'authStore');
    return authStore.createOrganizationWithOwner({
      orgId,
      orgName,
      ownerUserId,
      operatorUserId
    });
  };

  const acquireOwnerTransferLock = async ({
    orgId,
    requestId = 'request_id_unset',
    operatorUserId = 'unknown',
    timeoutSeconds = 0
  } = {}) => {
    const normalizedOrgId = String(orgId || '').trim();
    if (
      !normalizedOrgId
      || WHITESPACE_PATTERN.test(normalizedOrgId)
      || CONTROL_CHAR_PATTERN.test(normalizedOrgId)
      || normalizedOrgId.length > MAX_OWNER_TRANSFER_ORG_ID_LENGTH
    ) {
      return false;
    }
    assertStoreMethod(authStore, 'acquireOwnerTransferLock', 'authStore');
    if (ownerTransferLocksByOrgId.has(normalizedOrgId)) {
      return false;
    }
    ownerTransferLocksByOrgId.set(normalizedOrgId, {
      request_id: String(requestId || '').trim() || 'request_id_unset',
      operator_user_id: String(operatorUserId || '').trim() || 'unknown',
      started_at: new Date(now()).toISOString()
    });
    try {
      const acquired = await authStore.acquireOwnerTransferLock({
        orgId: normalizedOrgId,
        requestId: String(requestId || '').trim() || 'request_id_unset',
        operatorUserId: String(operatorUserId || '').trim() || 'unknown',
        timeoutSeconds
      });
      if (acquired === true) {
        return true;
      }
      ownerTransferLocksByOrgId.delete(normalizedOrgId);
      return false;
    } catch (_error) {
      ownerTransferLocksByOrgId.delete(normalizedOrgId);
      throw errors.ownerTransferLockUnavailable();
    }
  };

  const releaseOwnerTransferLock = async ({
    orgId
  } = {}) => {
    const normalizedOrgId = String(orgId || '').trim();
    if (!normalizedOrgId) {
      return false;
    }
    ownerTransferLocksByOrgId.delete(normalizedOrgId);
    assertStoreMethod(authStore, 'releaseOwnerTransferLock', 'authStore');
    try {
      const released = await authStore.releaseOwnerTransferLock({
        orgId: normalizedOrgId
      });
      return released === true;
    } catch (_error) {
      return false;
    }
  };

  const validateOwnerTransferRequest = async ({
    requestId,
    orgId,
    newOwnerPhone,
    operatorUserId,
    operatorSessionId,
    reason = null
  }) => {
    const normalizedRequestId = String(requestId || '').trim() || 'request_id_unset';

    if (typeof orgId !== 'string' || typeof newOwnerPhone !== 'string') {
      throw errors.invalidPayload();
    }
    const normalizedOrgId = orgId.trim();
    if (
      !normalizedOrgId
      || normalizedOrgId !== orgId
      || WHITESPACE_PATTERN.test(normalizedOrgId)
      || CONTROL_CHAR_PATTERN.test(normalizedOrgId)
      || normalizedOrgId.length > MAX_OWNER_TRANSFER_ORG_ID_LENGTH
    ) {
      throw errors.invalidPayload();
    }
    const normalizedNewOwnerPhone = normalizePhone(newOwnerPhone);
    if (!normalizedNewOwnerPhone || normalizedNewOwnerPhone !== newOwnerPhone) {
      throw errors.invalidPayload();
    }

    const normalizedOperatorUserId = String(operatorUserId || '').trim();
    const normalizedOperatorSessionId = String(operatorSessionId || '').trim();
    let normalizedReason = null;
    if (reason !== null && reason !== undefined) {
      if (typeof reason !== 'string') {
        throw errors.invalidPayload();
      }
      const trimmedReason = reason.trim();
      if (!trimmedReason || trimmedReason !== reason) {
        throw errors.invalidPayload();
      }
      if (CONTROL_CHAR_PATTERN.test(trimmedReason)) {
        throw errors.invalidPayload();
      }
      if (trimmedReason.length > MAX_OWNER_TRANSFER_REASON_LENGTH) {
        throw errors.invalidPayload();
      }
      normalizedReason = trimmedReason;
    }

    if (
      !normalizedOrgId
      || !normalizedNewOwnerPhone
      || !normalizedOperatorUserId
      || !normalizedOperatorSessionId
    ) {
      throw errors.invalidPayload();
    }

    assertStoreMethod(authStore, 'findOrganizationById', 'authStore');
    assertStoreMethod(authStore, 'findUserByPhone', 'authStore');

    const org = await authStore.findOrganizationById({
      orgId: normalizedOrgId
    });
    if (!org) {
      throw errors.orgNotFound();
    }

    const oldOwnerUserId = String(
      org.owner_user_id || org.ownerUserId || ''
    ).trim();
    if (!oldOwnerUserId) {
      throw errors.invalidPayload();
    }

    const normalizedOrgStatus = normalizeOrgStatus(org.status);
    if (normalizedOrgStatus !== 'active') {
      throw errors.ownerTransferOrgNotActive({
        orgId: normalizedOrgId,
        oldOwnerUserId
      });
    }

    const candidateOwner = await authStore.findUserByPhone(normalizedNewOwnerPhone);
    if (!candidateOwner) {
      throw errors.userNotFound({
        extensions: {
          org_id: normalizedOrgId,
          old_owner_user_id: oldOwnerUserId
        }
      });
    }

    const newOwnerUserId = String(
      candidateOwner.id || candidateOwner.user_id || ''
    ).trim();
    if (!newOwnerUserId) {
      throw errors.invalidPayload();
    }
    if (!isUserActive(candidateOwner)) {
      throw errors.ownerTransferTargetUserInactive({
        orgId: normalizedOrgId,
        oldOwnerUserId,
        newOwnerUserId
      });
    }
    if (newOwnerUserId === oldOwnerUserId) {
      throw errors.ownerTransferSameOwner({
        orgId: normalizedOrgId,
        oldOwnerUserId
      });
    }

    addAuditEvent({
      type: 'auth.org.owner_transfer.validated',
      requestId: normalizedRequestId,
      userId: normalizedOperatorUserId,
      sessionId: normalizedOperatorSessionId,
      detail: 'owner transfer request validated',
      metadata: {
        org_id: normalizedOrgId,
        old_owner_user_id: oldOwnerUserId,
        new_owner_user_id: newOwnerUserId,
        new_owner_phone_masked: maskPhone(normalizedNewOwnerPhone),
        reason: normalizedReason
      }
    });

    return {
      org_id: normalizedOrgId,
      old_owner_user_id: oldOwnerUserId,
      new_owner_user_id: newOwnerUserId
    };
  };

  const createPlatformRoleCatalogEntry = async ({
    roleId,
    code,
    name,
    status = 'active',
    scope = PLATFORM_ROLE_CATALOG_SCOPE,
    tenantId = null,
    isSystem = false,
    operatorUserId = null,
    operatorSessionId = null
  }) => {
    const normalizedRoleId = normalizeRequiredStringField(
      roleId,
      errors.invalidPayload
    ).toLowerCase();
    const normalizedCode = normalizeRequiredStringField(
      code,
      errors.invalidPayload
    );
    const normalizedName = normalizeRequiredStringField(
      name,
      errors.invalidPayload
    );
    const normalizedStatus = normalizePlatformRoleCatalogStatus(status);
    const normalizedScope = normalizePlatformRoleCatalogScope(scope);
    if (
      !VALID_PLATFORM_ROLE_CATALOG_STATUS.has(normalizedStatus)
      || !VALID_PLATFORM_ROLE_CATALOG_SCOPE.has(normalizedScope)
    ) {
      throw errors.invalidPayload();
    }
    const normalizedTenantId = normalizePlatformRoleCatalogTenantIdForScope({
      scope: normalizedScope,
      tenantId
    });

    assertStoreMethod(authStore, 'createPlatformRoleCatalogEntry', 'authStore');
    return authStore.createPlatformRoleCatalogEntry({
      roleId: normalizedRoleId,
      code: normalizedCode,
      name: normalizedName,
      status: normalizedStatus === 'enabled' ? 'active' : normalizedStatus,
      scope: normalizedScope,
      tenantId: normalizedTenantId,
      isSystem: Boolean(isSystem),
      operatorUserId,
      operatorSessionId
    });
  };

  const updatePlatformRoleCatalogEntry = async ({
    roleId,
    scope = PLATFORM_ROLE_CATALOG_SCOPE,
    tenantId = null,
    code = undefined,
    name = undefined,
    status = undefined,
    operatorUserId = null,
    operatorSessionId = null
  }) => {
    const normalizedRoleId = normalizeRequiredStringField(
      roleId,
      errors.invalidPayload
    ).toLowerCase();
    const normalizedScope = normalizePlatformRoleCatalogScope(scope);
    if (!VALID_PLATFORM_ROLE_CATALOG_SCOPE.has(normalizedScope)) {
      throw errors.invalidPayload();
    }
    const normalizedTenantId = normalizePlatformRoleCatalogTenantIdForScope({
      scope: normalizedScope,
      tenantId
    });
    const updates = {};
    if (code !== undefined) {
      updates.code = normalizeRequiredStringField(code, errors.invalidPayload);
    }
    if (name !== undefined) {
      updates.name = normalizeRequiredStringField(name, errors.invalidPayload);
    }
    if (status !== undefined) {
      const normalizedStatus = normalizePlatformRoleCatalogStatus(status);
      if (!VALID_PLATFORM_ROLE_CATALOG_STATUS.has(normalizedStatus)) {
        throw errors.invalidPayload();
      }
      updates.status = normalizedStatus === 'enabled'
        ? 'active'
        : normalizedStatus;
    }

    assertStoreMethod(authStore, 'updatePlatformRoleCatalogEntry', 'authStore');
    return authStore.updatePlatformRoleCatalogEntry({
      roleId: normalizedRoleId,
      scope: normalizedScope,
      tenantId: normalizedTenantId,
      ...updates,
      operatorUserId,
      operatorSessionId
    });
  };

  const deletePlatformRoleCatalogEntry = async ({
    roleId,
    scope = PLATFORM_ROLE_CATALOG_SCOPE,
    tenantId = null,
    operatorUserId = null,
    operatorSessionId = null
  }) => {
    const normalizedRoleId = normalizeRequiredStringField(
      roleId,
      errors.invalidPayload
    ).toLowerCase();
    const normalizedScope = normalizePlatformRoleCatalogScope(scope);
    if (!VALID_PLATFORM_ROLE_CATALOG_SCOPE.has(normalizedScope)) {
      throw errors.invalidPayload();
    }
    const normalizedTenantId = normalizePlatformRoleCatalogTenantIdForScope({
      scope: normalizedScope,
      tenantId
    });
    assertStoreMethod(authStore, 'deletePlatformRoleCatalogEntry', 'authStore');
    return authStore.deletePlatformRoleCatalogEntry({
      roleId: normalizedRoleId,
      scope: normalizedScope,
      tenantId: normalizedTenantId,
      operatorUserId,
      operatorSessionId
    });
  };

  const listPlatformRoleCatalogEntries = async ({
    scope = PLATFORM_ROLE_CATALOG_SCOPE,
    tenantId = null
  } = {}) => {
    const normalizedScope = normalizePlatformRoleCatalogScope(scope);
    if (!VALID_PLATFORM_ROLE_CATALOG_SCOPE.has(normalizedScope)) {
      throw errors.invalidPayload();
    }
    const normalizedTenantId = normalizePlatformRoleCatalogTenantIdForScope({
      scope: normalizedScope,
      tenantId
    });
    assertStoreMethod(authStore, 'listPlatformRoleCatalogEntries', 'authStore');
    return authStore.listPlatformRoleCatalogEntries({
      scope: normalizedScope,
      tenantId: normalizedTenantId
    });
  };

  const findPlatformRoleCatalogEntryByRoleId = async ({
    roleId,
    scope = PLATFORM_ROLE_CATALOG_SCOPE,
    tenantId = null
  } = {}) => {
    const normalizedRoleId = normalizeRequiredStringField(
      roleId,
      errors.invalidPayload
    ).toLowerCase();
    const normalizedScope = normalizePlatformRoleCatalogScope(scope);
    if (!VALID_PLATFORM_ROLE_CATALOG_SCOPE.has(normalizedScope)) {
      throw errors.invalidPayload();
    }
    const normalizedTenantId = normalizePlatformRoleCatalogTenantIdForScope({
      scope: normalizedScope,
      tenantId
    });
    assertStoreMethod(authStore, 'findPlatformRoleCatalogEntryByRoleId', 'authStore');
    return authStore.findPlatformRoleCatalogEntryByRoleId({
      roleId: normalizedRoleId,
      scope: normalizedScope,
      tenantId: normalizedTenantId
    });
  };

  const listPlatformPermissionCatalog = () =>
    listSupportedPlatformPermissionCodes();

  const listPlatformRolePermissionGrants = async ({ roleId }) => {
    const normalizedRoleId = normalizeRequiredStringField(
      roleId,
      errors.invalidPayload
    ).toLowerCase();
    const {
      requestedRoleIds
    } = await loadValidatedPlatformRoleCatalogEntriesForRoleFacts({
      roles: [{ roleId: normalizedRoleId }],
      allowDisabledRoles: true
    });
    const grantsByRoleIdKey = await loadPlatformRolePermissionGrantsByRoleIds({
      roleIds: requestedRoleIds
    });
    const grants = grantsByRoleIdKey.get(normalizePlatformRoleIdKey(normalizedRoleId)) || [];
    return {
      role_id: normalizedRoleId,
      permission_codes: grants,
      available_permission_codes: listPlatformPermissionCatalog()
    };
  };

  const toDistinctNormalizedUserIds = (userIds = []) =>
    [...new Set(
      (Array.isArray(userIds) ? userIds : [])
        .map((userId) => String(userId || '').trim())
        .filter((userId) => userId.length > 0)
    )];

  const normalizeStoredRoleFactsForPermissionResync = (roleFacts = []) => {
    const normalizedStoredRoleFacts = [];
    for (const roleFact of Array.isArray(roleFacts) ? roleFacts : []) {
      let normalizedRoleFactRoleId;
      try {
        normalizedRoleFactRoleId = normalizeRequiredStringField(
          resolveRawRoleIdCandidate(roleFact),
          errors.invalidPayload
        );
      } catch (_error) {
        throw errors.platformSnapshotDegraded({
          reason: 'platform-role-permission-role-facts-invalid'
        });
      }
      const normalizedRoleFactRoleIdKey =
        normalizePlatformRoleIdKey(normalizedRoleFactRoleId);
      const normalizedRoleFactStatusInput = String(
        roleFact?.status || 'active'
      ).trim().toLowerCase();
      if (!VALID_PLATFORM_ROLE_FACT_STATUS.has(normalizedRoleFactStatusInput)) {
        throw errors.platformSnapshotDegraded({
          reason: 'platform-role-permission-role-facts-invalid'
        });
      }
      const normalizedRoleFactStatus = normalizedRoleFactStatusInput === 'enabled'
        ? 'active'
        : normalizedRoleFactStatusInput;
      normalizedStoredRoleFacts.push({
        roleIdKey: normalizedRoleFactRoleIdKey,
        status: normalizedRoleFactStatus
      });
    }
    return normalizedStoredRoleFacts;
  };

  const cloneRoleFactsSnapshotForRollback = (roleFacts = []) =>
    (Array.isArray(roleFacts) ? roleFacts : []).map((roleFact) => ({
      roleId: String(roleFact?.roleId || roleFact?.role_id || '').trim(),
      role_id: String(roleFact?.roleId || roleFact?.role_id || '').trim(),
      status: String(roleFact?.status || 'active').trim().toLowerCase() || 'active',
      permission:
        roleFact?.permission
        && typeof roleFact.permission === 'object'
        && !Array.isArray(roleFact.permission)
          ? {
            canViewMemberAdmin: Boolean(
              roleFact.permission.canViewMemberAdmin
              ?? roleFact.permission.can_view_member_admin
            ),
            canOperateMemberAdmin: Boolean(
              roleFact.permission.canOperateMemberAdmin
              ?? roleFact.permission.can_operate_member_admin
            ),
            canViewBilling: Boolean(
              roleFact.permission.canViewBilling
              ?? roleFact.permission.can_view_billing
            ),
            canOperateBilling: Boolean(
              roleFact.permission.canOperateBilling
              ?? roleFact.permission.can_operate_billing
            )
          }
          : null
    }));

  const replacePlatformRolePermissionGrants = async ({
    requestId,
    roleId,
    permissionCodes = [],
    operatorUserId = null,
    operatorSessionId = null
  }) => {
    const normalizedRoleId = normalizeRequiredStringField(
      roleId,
      errors.invalidPayload
    ).toLowerCase();
    const normalizedTargetRoleIdKey = normalizePlatformRoleIdKey(normalizedRoleId);
    if (!Array.isArray(permissionCodes)) {
      throw errors.invalidPayload();
    }
    if (permissionCodes.length > MAX_ROLE_PERMISSION_CODES_PER_REQUEST) {
      throw errors.invalidPayload();
    }
    const dedupedPermissionCodes = new Map();
    for (const permissionCode of permissionCodes) {
      const normalizedPermissionCode = normalizePlatformPermissionCode(permissionCode);
      if (!normalizedPermissionCode) {
        throw errors.invalidPayload();
      }
      const permissionCodeKey = toPlatformPermissionCodeKey(normalizedPermissionCode);
      if (
        !isPlatformPermissionCode(normalizedPermissionCode)
        || !SUPPORTED_PLATFORM_PERMISSION_CODE_SET.has(permissionCodeKey)
      ) {
        throw errors.invalidPayload();
      }
      dedupedPermissionCodes.set(permissionCodeKey, permissionCodeKey);
    }
    const normalizedPermissionCodes = [...dedupedPermissionCodes.values()];

    await loadValidatedPlatformRoleCatalogEntriesForRoleFacts({
      roles: [{ roleId: normalizedRoleId }],
      allowDisabledRoles: true
    });

    if (typeof authStore.replacePlatformRolePermissionGrantsAndSyncSnapshots === 'function') {
      let atomicWriteResult;
      try {
        atomicWriteResult =
          await authStore.replacePlatformRolePermissionGrantsAndSyncSnapshots({
            roleId: normalizedRoleId,
            permissionCodes: normalizedPermissionCodes,
            operatorUserId,
            operatorSessionId,
            maxAffectedUsers: MAX_ROLE_PERMISSION_ATOMIC_AFFECTED_USERS
          });
      } catch (error) {
        if (error instanceof AuthProblemError) {
          throw error;
        }
        if (String(error?.code || '').trim()
          === 'ERR_PLATFORM_ROLE_PERMISSION_AFFECTED_USERS_OVER_LIMIT') {
          throw errors.platformSnapshotDegraded({
            reason: 'platform-role-permission-affected-users-over-limit'
          });
        }
        if (String(error?.code || '').trim() === 'ERR_PLATFORM_ROLE_PERMISSION_SYNC_FAILED') {
          throw errors.platformSnapshotDegraded({
            reason: String(error?.syncReason || 'platform-role-permission-resync-failed')
          });
        }
        const normalizedErrorMessage = String(error?.message || '')
          .trim()
          .toLowerCase();
        throw errors.platformSnapshotDegraded({
          reason: normalizedErrorMessage.includes('deadlock')
            ? 'db-deadlock'
            : 'platform-role-permission-atomic-write-failed'
        });
      }

      if (!atomicWriteResult) {
        throw errors.roleNotFound();
      }

      const savedPermissionCodes = [...new Set(
        (
          Array.isArray(atomicWriteResult?.permissionCodes)
            ? atomicWriteResult.permissionCodes
            : Array.isArray(atomicWriteResult?.permission_codes)
              ? atomicWriteResult.permission_codes
              : []
        )
          .map((permissionCode) => normalizePlatformPermissionCode(permissionCode))
          .filter((permissionCode) => permissionCode.length > 0)
      )];
      const affectedUserIds = toDistinctNormalizedUserIds(
        Array.isArray(atomicWriteResult?.affectedUserIds)
          ? atomicWriteResult.affectedUserIds
          : Array.isArray(atomicWriteResult?.affected_user_ids)
            ? atomicWriteResult.affected_user_ids
            : []
      );
      for (const affectedUserId of affectedUserIds) {
        invalidateSessionCacheByUserId(affectedUserId);
      }
      const resyncedUserCount = Number(
        atomicWriteResult?.affectedUserCount
        ?? atomicWriteResult?.affected_user_count
        ?? affectedUserIds.length
      );

      addAuditEvent({
        type: 'auth.platform_role_permission_grants.updated',
        requestId,
        userId: operatorUserId || 'unknown',
        sessionId: operatorSessionId || 'unknown',
        detail: 'platform role permission grants replaced and affected snapshots resynced',
        metadata: {
          role_id: normalizedRoleId,
          permission_codes: savedPermissionCodes,
          affected_user_count: resyncedUserCount
        }
      });

      return {
        role_id: normalizedRoleId,
        permission_codes: savedPermissionCodes,
        affected_user_count: resyncedUserCount
      };
    }

    if (typeof authStore.replacePlatformRolePermissionGrants !== 'function') {
      throw errors.platformSnapshotDegraded({
        reason: 'platform-role-permission-grants-unsupported'
      });
    }
    if (
      typeof authStore.listUserIdsByPlatformRoleId !== 'function'
      || typeof authStore.listPlatformRoleFactsByUserId !== 'function'
      || typeof authStore.replacePlatformRolesAndSyncSnapshot !== 'function'
    ) {
      throw errors.platformSnapshotDegraded({
        reason: 'platform-role-permission-resync-unsupported'
      });
    }

    let affectedUserIds = [];
    try {
      affectedUserIds = await authStore.listUserIdsByPlatformRoleId({
        roleId: normalizedRoleId
      });
    } catch (_error) {
      throw errors.platformSnapshotDegraded({
        reason: 'platform-role-permission-affected-users-query-failed'
      });
    }
    const precheckedAffectedUserIds = toDistinctNormalizedUserIds(affectedUserIds);
    for (const normalizedAffectedUserId of precheckedAffectedUserIds) {
      try {
        await authStore.listPlatformRoleFactsByUserId({
          userId: normalizedAffectedUserId
        });
      } catch (_error) {
        throw errors.platformSnapshotDegraded({
          reason: 'platform-role-permission-role-facts-query-failed'
        });
      }
    }

    let previousTargetRolePermissionCodes = [];
    try {
      const previousTargetRoleGrantsByRoleIdKey =
        await loadPlatformRolePermissionGrantsByRoleIds({
          roleIds: [normalizedRoleId]
        });
      previousTargetRolePermissionCodes =
        previousTargetRoleGrantsByRoleIdKey.get(normalizedTargetRoleIdKey) || [];
    } catch (error) {
      if (error instanceof AuthProblemError) {
        throw error;
      }
      throw errors.platformSnapshotDegraded({
        reason: 'platform-role-permission-grants-query-failed'
      });
    }

    let savedPermissionCodes = [];
    let grantsWriteApplied = false;
    const preSyncRoleFactsByUserId = new Map();
    const normalizedRoleFactsByUserId = new Map();
    const syncedUserIds = [];
    try {
      const saved = await authStore.replacePlatformRolePermissionGrants({
        roleId: normalizedRoleId,
        permissionCodes: normalizedPermissionCodes,
        operatorUserId,
        operatorSessionId
      });
      if (!saved) {
        throw errors.roleNotFound();
      }
      savedPermissionCodes = [...new Set(
        (Array.isArray(saved) ? saved : [])
          .map((permissionCode) => normalizePlatformPermissionCode(permissionCode))
          .filter((permissionCode) => permissionCode.length > 0)
      )];
      grantsWriteApplied = true;

      let postWriteAffectedUserIds = [];
      try {
        postWriteAffectedUserIds = await authStore.listUserIdsByPlatformRoleId({
          roleId: normalizedRoleId
        });
      } catch (_error) {
        throw errors.platformSnapshotDegraded({
          reason: 'platform-role-permission-affected-users-query-failed'
        });
      }
      const normalizedAffectedUserIds = [...new Set([
        ...precheckedAffectedUserIds,
        ...toDistinctNormalizedUserIds(postWriteAffectedUserIds)
      ])];

      const normalizedAllRoleIds = new Set();
      for (const normalizedAffectedUserId of normalizedAffectedUserIds) {
        let roleFacts = [];
        try {
          roleFacts = await authStore.listPlatformRoleFactsByUserId({
            userId: normalizedAffectedUserId
          });
        } catch (_error) {
          throw errors.platformSnapshotDegraded({
            reason: 'platform-role-permission-role-facts-query-failed'
          });
        }
        preSyncRoleFactsByUserId.set(
          normalizedAffectedUserId,
          cloneRoleFactsSnapshotForRollback(roleFacts)
        );
        const normalizedStoredRoleFacts = normalizeStoredRoleFactsForPermissionResync(roleFacts);
        normalizedRoleFactsByUserId.set(
          normalizedAffectedUserId,
          normalizedStoredRoleFacts
        );
        for (const roleFact of normalizedStoredRoleFacts) {
          normalizedAllRoleIds.add(roleFact.roleIdKey);
        }
      }

      let grantsByRoleIdKey = new Map();
      try {
        grantsByRoleIdKey = await loadPlatformRolePermissionGrantsByRoleIds({
          roleIds: [...normalizedAllRoleIds]
        });
      } catch (error) {
        if (error instanceof AuthProblemError) {
          throw error;
        }
        throw errors.platformSnapshotDegraded({
          reason: 'platform-role-permission-grants-query-failed'
        });
      }

      for (const normalizedAffectedUserId of normalizedAffectedUserIds) {
        const normalizedStoredRoleFacts =
          normalizedRoleFactsByUserId.get(normalizedAffectedUserId) || [];
        const nextRoleFacts = normalizedStoredRoleFacts.map((roleFact) => {
          const permissionCodes = grantsByRoleIdKey.get(roleFact.roleIdKey) || [];
          return {
            roleId: roleFact.roleIdKey,
            status: roleFact.status,
            permission: toPlatformPermissionSnapshotFromCodes(permissionCodes)
          };
        });

        let syncResult;
        try {
          syncResult = await authStore.replacePlatformRolesAndSyncSnapshot({
            userId: normalizedAffectedUserId,
            roles: nextRoleFacts
          });
        } catch (_error) {
          throw errors.platformSnapshotDegraded({
            reason: 'platform-role-permission-resync-failed'
          });
        }
        const syncReason = String(syncResult?.reason || 'unknown').trim().toLowerCase();
        if (syncReason !== 'ok') {
          throw errors.platformSnapshotDegraded({
            reason: syncReason || 'platform-role-permission-resync-failed'
          });
        }
        syncedUserIds.push(normalizedAffectedUserId);
        invalidateSessionCacheByUserId(normalizedAffectedUserId);
      }
    } catch (error) {
      if (grantsWriteApplied) {
        try {
          const restoredGrants = await authStore.replacePlatformRolePermissionGrants({
            roleId: normalizedRoleId,
            permissionCodes: previousTargetRolePermissionCodes,
            operatorUserId,
            operatorSessionId
          });
          if (!restoredGrants) {
            throw new Error('platform-role-permission-grants-rollback-role-not-found');
          }
          for (const syncedUserId of [...syncedUserIds].reverse()) {
            const rollbackRoleFacts = preSyncRoleFactsByUserId.get(syncedUserId) || [];
            const rollbackResult = await authStore.replacePlatformRolesAndSyncSnapshot({
              userId: syncedUserId,
              roles: rollbackRoleFacts
            });
            const rollbackReason = String(
              rollbackResult?.reason || 'unknown'
            ).trim().toLowerCase();
            if (rollbackReason !== 'ok') {
              throw new Error(`platform-role-permission-resync-rollback-failed:${rollbackReason}`);
            }
            invalidateSessionCacheByUserId(syncedUserId);
          }
        } catch (_rollbackError) {
          throw errors.platformSnapshotDegraded({
            reason: 'platform-role-permission-compensation-failed'
          });
        }
      }
      if (error instanceof AuthProblemError) {
        throw error;
      }
      throw errors.platformSnapshotDegraded({
        reason: 'platform-role-permission-resync-failed'
      });
    }
    const resyncedUserCount = syncedUserIds.length;

    addAuditEvent({
      type: 'auth.platform_role_permission_grants.updated',
      requestId,
      userId: operatorUserId || 'unknown',
      sessionId: operatorSessionId || 'unknown',
      detail: 'platform role permission grants replaced and affected snapshots resynced',
      metadata: {
        role_id: normalizedRoleId,
        permission_codes: savedPermissionCodes,
        affected_user_count: resyncedUserCount
      }
    });

    return {
      role_id: normalizedRoleId,
      permission_codes: savedPermissionCodes,
      affected_user_count: resyncedUserCount
    };
  };

  const updateOrganizationStatus = async ({
    requestId,
    orgId,
    nextStatus,
    operatorUserId,
    operatorSessionId,
    reason = null
  }) => {
    const normalizedRequestId = String(requestId || '').trim() || 'request_id_unset';
    const normalizedOrgId = String(orgId || '').trim();
    const normalizedOperatorUserId = String(operatorUserId || '').trim();
    const normalizedOperatorSessionId = String(operatorSessionId || '').trim();
    const normalizedNextStatus = normalizeOrgStatus(nextStatus);
    const normalizedReason = reason === null || reason === undefined
      ? null
      : String(reason).trim() || null;

    if (
      !normalizedOrgId
      || !normalizedOperatorUserId
      || !normalizedOperatorSessionId
      || !VALID_ORG_STATUS.has(normalizedNextStatus)
    ) {
      throw errors.invalidPayload();
    }

    assertStoreMethod(authStore, 'updateOrganizationStatus', 'authStore');
    const result = await authStore.updateOrganizationStatus({
      requestId: normalizedRequestId,
      orgId: normalizedOrgId,
      nextStatus: normalizedNextStatus,
      operatorUserId: normalizedOperatorUserId,
      reason: normalizedReason
    });
    if (!result) {
      throw errors.orgNotFound();
    }

    const previousStatus = normalizeOrgStatus(result.previous_status);
    const currentStatus = normalizeOrgStatus(result.current_status);
    if (!previousStatus || !currentStatus) {
      throw errors.invalidPayload();
    }
    if (previousStatus !== currentStatus) {
      invalidateAllAccessSessionCache();
    }
    addAuditEvent({
      type: 'auth.org.status.updated',
      requestId: normalizedRequestId,
      userId: normalizedOperatorUserId,
      sessionId: normalizedOperatorSessionId,
      detail: previousStatus === currentStatus
        ? 'organization status update treated as no-op'
        : 'organization status updated',
      metadata: {
        org_id: normalizedOrgId,
        previous_status: previousStatus,
        current_status: currentStatus,
        reason: normalizedReason
      }
    });

    return {
      org_id: normalizedOrgId,
      previous_status: previousStatus,
      current_status: currentStatus
    };
  };

  const updatePlatformUserStatus = async ({
    requestId,
    userId,
    nextStatus,
    operatorUserId,
    operatorSessionId,
    reason = null
  }) => {
    const normalizedRequestId = String(requestId || '').trim() || 'request_id_unset';
    const normalizedUserId = String(userId || '').trim();
    const normalizedOperatorUserId = String(operatorUserId || '').trim();
    const normalizedOperatorSessionId = String(operatorSessionId || '').trim();
    const normalizedNextStatus = normalizeOrgStatus(nextStatus);
    const normalizedReason = reason === null || reason === undefined
      ? null
      : String(reason).trim() || null;

    if (
      !normalizedUserId
      || !normalizedOperatorUserId
      || !normalizedOperatorSessionId
      || !VALID_PLATFORM_USER_STATUS.has(normalizedNextStatus)
    ) {
      throw errors.invalidPayload();
    }

    assertStoreMethod(authStore, 'updatePlatformUserStatus', 'authStore');
    const result = await authStore.updatePlatformUserStatus({
      requestId: normalizedRequestId,
      userId: normalizedUserId,
      nextStatus: normalizedNextStatus,
      operatorUserId: normalizedOperatorUserId,
      reason: normalizedReason
    });
    if (!result) {
      throw errors.userNotFound();
    }

    const previousStatus = normalizeOrgStatus(result.previous_status);
    const currentStatus = normalizeOrgStatus(result.current_status);
    if (
      !VALID_PLATFORM_USER_STATUS.has(previousStatus)
      || !VALID_PLATFORM_USER_STATUS.has(currentStatus)
    ) {
      throw errors.platformSnapshotDegraded({
        reason: 'platform-user-status-result-invalid'
      });
    }
    if (previousStatus !== currentStatus) {
      invalidateSessionCacheByUserId(normalizedUserId);
    }
    addAuditEvent({
      type: 'auth.platform.user.status.updated',
      requestId: normalizedRequestId,
      userId: normalizedOperatorUserId,
      sessionId: normalizedOperatorSessionId,
      detail: previousStatus === currentStatus
        ? 'platform user status update treated as no-op'
        : 'platform user status updated',
      metadata: {
        target_user_id: normalizedUserId,
        previous_status: previousStatus,
        current_status: currentStatus,
        reason: normalizedReason
      }
    });

    return {
      user_id: normalizedUserId,
      previous_status: previousStatus,
      current_status: currentStatus
    };
  };

  const rollbackProvisionedUser = async ({
    requestId,
    userId,
    strict = false
  }) => {
    const normalizedUserId = String(userId || '').trim();
    if (!normalizedUserId || typeof authStore.deleteUserById !== 'function') {
      if (strict) {
        throw new Error('rollback-provisioned-user-capability-unavailable');
      }
      return {
        rolledBack: false,
        reason: 'rollback-capability-unavailable'
      };
    }
    try {
      const domainAccess = await getDomainAccessForUser(normalizedUserId);
      if (domainAccess.platform || domainAccess.tenant) {
        if (strict) {
          throw new Error('rollback-skipped-user-has-domain-access');
        }
        return {
          rolledBack: false,
          reason: 'rollback-skipped-user-has-domain-access'
        };
      }
      const tenantOptions = await getTenantOptionsForUser(normalizedUserId);
      if (tenantOptions.length > 0) {
        if (strict) {
          throw new Error('rollback-skipped-user-has-tenant-options');
        }
        return {
          rolledBack: false,
          reason: 'rollback-skipped-user-has-tenant-options'
        };
      }
      if (typeof authStore.hasAnyTenantRelationshipByUserId === 'function') {
        const hasAnyTenantRelationship = await authStore.hasAnyTenantRelationshipByUserId(
          normalizedUserId
        );
        if (hasAnyTenantRelationship) {
          if (strict) {
            throw new Error('rollback-skipped-user-has-tenant-relationship');
          }
          return {
            rolledBack: false,
            reason: 'rollback-skipped-user-has-tenant-relationship'
          };
        }
      }
    } catch (rollbackGuardError) {
      log(
        'warn',
        'Skipped rollback for provisioned user after conflict due to guard check failure',
        {
          request_id: requestId || 'request_id_unset',
          user_id: normalizedUserId,
          reason: String(rollbackGuardError?.message || 'unknown')
        }
      );
      if (strict) {
        throw rollbackGuardError;
      }
      return {
        rolledBack: false,
        reason: 'rollback-guard-check-failed'
      };
    }
    try {
      const rollbackResult = await authStore.deleteUserById(normalizedUserId);
      const rollbackDeleteApplied =
        rollbackResult
        && typeof rollbackResult === 'object'
        && rollbackResult.deleted === true;
      if (!rollbackDeleteApplied) {
        const rollbackReason =
          rollbackResult
          && typeof rollbackResult === 'object'
          && rollbackResult.deleted === false
            ? 'rollback-not-deleted'
            : 'rollback-delete-result-invalid';
        const rollbackNotAppliedError = new Error(
          rollbackReason === 'rollback-not-deleted'
            ? 'rollback-provisioned-user-not-deleted'
            : 'rollback-provisioned-user-delete-result-invalid'
        );
        if (strict) {
          throw rollbackNotAppliedError;
        }
        return {
          rolledBack: false,
          reason: rollbackReason
        };
      }
      return {
        rolledBack: true,
        reason: 'deleted'
      };
    } catch (rollbackError) {
      log('warn', 'Failed to rollback provisioned user after conflict', {
        request_id: requestId || 'request_id_unset',
        user_id: normalizedUserId,
        reason: String(rollbackError?.message || 'unknown')
      });
      if (strict) {
        throw rollbackError;
      }
      return {
        rolledBack: false,
        reason: 'rollback-delete-failed'
      };
    }
  };

  const rollbackProvisionedUserIdentity = async ({ requestId, userId }) =>
    rollbackProvisionedUser({
      requestId,
      userId,
      strict: true
    });

  const rollbackProvisionedTenantMembership = async ({
    requestId,
    userId,
    tenantId
  }) => {
    const normalizedUserId = String(userId || '').trim();
    const normalizedTenantId = normalizeTenantId(tenantId);
    if (
      !normalizedUserId
      || !normalizedTenantId
      || typeof authStore.removeTenantMembershipForUser !== 'function'
    ) {
      return;
    }
    try {
      await authStore.removeTenantMembershipForUser({
        userId: normalizedUserId,
        tenantId: normalizedTenantId
      });
    } catch (rollbackError) {
      log('warn', 'Failed to rollback provisioned tenant membership after conflict', {
        request_id: requestId || 'request_id_unset',
        user_id: normalizedUserId,
        tenant_id: normalizedTenantId,
        reason: String(rollbackError?.message || 'unknown')
      });
    }
    if (typeof authStore.removeTenantDomainAccessForUser !== 'function') {
      return;
    }
    try {
      await authStore.removeTenantDomainAccessForUser(normalizedUserId);
    } catch (rollbackError) {
      log('warn', 'Failed to rollback provisioned tenant domain access after conflict', {
        request_id: requestId || 'request_id_unset',
        user_id: normalizedUserId,
        reason: String(rollbackError?.message || 'unknown')
      });
    }
  };

  const ensureProvisioningRelationship = async ({
    requestId,
    entryDomain,
    activeTenantId,
    userId,
    tenantName
  }) => {
    if (entryDomain === 'platform') {
      const domainAccess = await getDomainAccessForUser(userId);
      if (domainAccess.platform) {
        throw errors.provisionConflict();
      }
      const provisionedDomainAccess = await ensureDefaultDomainAccessForUser({
        requestId,
        userId
      });
      if (!provisionedDomainAccess || provisionedDomainAccess.inserted !== true) {
        throw errors.provisionConflict();
      }
      const updatedDomainAccess = await getDomainAccessForUser(userId);
      if (!updatedDomainAccess.platform) {
        throw errors.provisionConflict();
      }
      return null;
    }

    const normalizedTenantId = normalizeTenantId(activeTenantId);
    if (!normalizedTenantId) {
      throw errors.noDomainAccess();
    }

    const existingTenantOptions = await getTenantOptionsForUser(userId);
    if (existingTenantOptions.some((option) => option.tenant_id === normalizedTenantId)) {
      const domainAccessBefore = await getDomainAccessForUser(userId);
      if (domainAccessBefore.tenant) {
        throw errors.provisionConflict();
      }

      await ensureTenantDomainAccessForUser({
        requestId,
        userId,
        entryDomain: 'tenant'
      });
      const domainAccessAfter = await getDomainAccessForUser(userId);
      if (!domainAccessAfter.tenant) {
        throw errors.provisionConflict();
      }
      return normalizedTenantId;
    }

    assertStoreMethod(authStore, 'createTenantMembershipForUser', 'authStore');
    let createdMembership = null;
    try {
      createdMembership = await authStore.createTenantMembershipForUser({
        userId: String(userId),
        tenantId: normalizedTenantId,
        tenantName
      });
    } catch (error) {
      if (isDataTooLongRoleFactError(error)) {
        throw errors.invalidPayload();
      }
      throw error;
    }
    if (!createdMembership || createdMembership.created !== true) {
      throw errors.provisionConflict();
    }

    try {
      await ensureTenantDomainAccessForUser({
        requestId,
        userId,
        entryDomain: 'tenant'
      });
      const updatedDomainAccess = await getDomainAccessForUser(userId);
      if (!updatedDomainAccess.tenant) {
        throw errors.provisionConflict();
      }
    } catch (error) {
      await rollbackProvisionedTenantMembership({
        requestId,
        userId,
        tenantId: normalizedTenantId
      });
      throw error;
    }
    return normalizedTenantId;
  };

  const resolveProvisionTenantName = async ({
    scope,
    operatorUserId,
    activeTenantId,
    requestedTenantName
  }) => {
    if (scope !== 'tenant') {
      return null;
    }
    const normalizedActiveTenantId = normalizeTenantId(activeTenantId);
    if (!normalizedActiveTenantId) {
      return null;
    }
    const operatorTenantOptions = await getTenantOptionsForUser(operatorUserId);
    const activeTenantOption = operatorTenantOptions.find(
      (option) => option.tenant_id === normalizedActiveTenantId
    );
    const canonicalTenantName = activeTenantOption?.tenant_name
      ? String(activeTenantOption.tenant_name).trim() || null
      : null;
    if (!canonicalTenantName) {
      throw errors.invalidPayload();
    }
    if (
      requestedTenantName
      && canonicalTenantName !== requestedTenantName
    ) {
      throw errors.invalidPayload();
    }
    return canonicalTenantName;
  };

  const recoverProvisioningOutcomeAfterConflict = async ({
    error,
    createdUser,
    userId,
    entryDomain,
    activeTenantId
  }) => {
    if (
      !(error instanceof AuthProblemError)
      || error.errorCode !== 'AUTH-409-PROVISION-CONFLICT'
      || !createdUser
    ) {
      return null;
    }
    const normalizedUserId = String(userId || '').trim();
    if (!normalizedUserId) {
      return null;
    }
    const domainAccess = await getDomainAccessForUser(normalizedUserId);
    if (entryDomain === 'platform') {
      if (!domainAccess.platform) {
        return null;
      }
      return { active_tenant_id: null };
    }

    const normalizedTenantId = normalizeTenantId(activeTenantId);
    if (!normalizedTenantId || !domainAccess.tenant) {
      return null;
    }
    const tenantOptions = await getTenantOptionsForUser(normalizedUserId);
    if (!tenantOptions.some((option) => option.tenant_id === normalizedTenantId)) {
      return null;
    }
    return { active_tenant_id: normalizedTenantId };
  };

  const provisionUserByPhone = async ({
    requestId,
    accessToken,
    phone,
    scope,
    tenantName = undefined,
    payload = undefined,
    authorizationContext = null,
    authorizedRoute = null
  }) => {
    const normalizedScope = String(scope || '').trim().toLowerCase();
    if (normalizedScope !== 'platform' && normalizedScope !== 'tenant') {
      throw errors.invalidPayload();
    }
    const payloadCandidate = payload === undefined
      ? {
        phone,
        ...(tenantName !== undefined ? { tenant_name: tenantName } : {})
      }
      : payload;
    const parsedPayload = parseProvisionPayload({
      payload: payloadCandidate,
      scope: normalizedScope
    });
    if (!parsedPayload.valid) {
      throw errors.invalidPayload();
    }
    const normalizedPhone = normalizePhone(parsedPayload.phone);
    if (normalizedScope === 'platform' && parsedPayload.tenantNameProvided) {
      throw errors.invalidPayload();
    }
    const parsedTenantName = normalizedScope === 'tenant'
      ? parseOptionalTenantName(parsedPayload.tenantName)
      : { valid: true, value: null };
    if (!normalizedPhone) {
      throw errors.invalidPayload();
    }
    if (!parsedTenantName.valid) {
      throw errors.invalidPayload();
    }

    const permissionCode = normalizedScope === 'platform'
      ? 'platform.member_admin.operate'
      : 'tenant.member_admin.operate';
    const normalizedAuthorizedRoute =
      authorizedRoute && typeof authorizedRoute === 'object'
        ? {
          user_id: String(
            authorizedRoute.user_id
            || authorizedRoute.userId
            || ''
          ).trim(),
          session_id: String(
            authorizedRoute.session_id
            || authorizedRoute.sessionId
            || ''
          ).trim(),
          entry_domain: normalizeEntryDomain(
            authorizedRoute.entry_domain
            || authorizedRoute.entryDomain
          ),
          active_tenant_id: normalizeTenantId(
            authorizedRoute.active_tenant_id
            || authorizedRoute.activeTenantId
          )
        }
        : null;
    let resolvedAuthorizedRoute = null;
    if (normalizedAuthorizedRoute) {
      if (
        !normalizedAuthorizedRoute.user_id
        || !normalizedAuthorizedRoute.session_id
        || normalizedAuthorizedRoute.entry_domain !== normalizedScope
      ) {
        throw errors.forbidden();
      }
      resolvedAuthorizedRoute = normalizedAuthorizedRoute;
    } else {
      resolvedAuthorizedRoute = await authorizeRoute({
        requestId,
        accessToken,
        permissionCode,
        scope: normalizedScope,
        authorizationContext
      });
    }
    const operatorUserId = String(resolvedAuthorizedRoute?.user_id || '').trim() || 'unknown';
    const operatorSessionId = String(resolvedAuthorizedRoute?.session_id || '').trim() || 'unknown';
    const sessionEntryDomain = String(resolvedAuthorizedRoute?.entry_domain || '').trim().toLowerCase();
    const activeTenantId = normalizeTenantId(resolvedAuthorizedRoute?.active_tenant_id);
    const resolvedTenantName = await resolveProvisionTenantName({
      scope: normalizedScope,
      operatorUserId,
      activeTenantId,
      requestedTenantName: parsedTenantName.value
    });

    let provisionedUser = null;
    let createdUser = false;
    let relationTenantId = null;
    try {
      const provisionedResult = await getOrCreateProvisionUserByPhone({
        requestId,
        phone: normalizedPhone,
        operatorUserId,
        operatorSessionId
      });
      provisionedUser = provisionedResult.user;
      createdUser = provisionedResult.createdUser;
      relationTenantId = await ensureProvisioningRelationship({
        requestId,
        entryDomain: sessionEntryDomain,
        activeTenantId,
        userId: provisionedUser.id,
        tenantName: resolvedTenantName
      });
    } catch (error) {
      let recoveredOutcome = null;
      try {
        recoveredOutcome = await recoverProvisioningOutcomeAfterConflict({
          error,
          createdUser,
          userId: provisionedUser?.id,
          entryDomain: sessionEntryDomain,
          activeTenantId
        });
      } catch (recoveryError) {
        log('warn', 'Post-conflict provisioning recovery check failed', {
          request_id: requestId || 'request_id_unset',
          user_id: String(provisionedUser?.id || 'unknown'),
          reason: String(recoveryError?.message || 'unknown')
        });
      }
      if (recoveredOutcome) {
        relationTenantId = recoveredOutcome.active_tenant_id;
      } else if (createdUser && provisionedUser?.id) {
        await rollbackProvisionedUser({
          requestId,
          userId: provisionedUser.id
        });
        addAuditEvent({
          type: 'auth.user.provision.rejected',
          requestId,
          userId: operatorUserId || 'unknown',
          sessionId: operatorSessionId || 'unknown',
          detail: 'user provisioning rejected after rollback',
          metadata: {
            operator_user_id: operatorUserId,
            phone_masked: maskPhone(normalizedPhone),
            entry_domain: sessionEntryDomain,
            tenant_id: activeTenantId,
            error_code:
              error instanceof AuthProblemError
                ? error.errorCode
                : 'AUTH-503-TENANT-MEMBER-DEPENDENCY-UNAVAILABLE'
          }
        });
        throw error;
      } else {
        addAuditEvent({
          type: 'auth.user.provision.rejected',
          requestId,
          userId: operatorUserId || 'unknown',
          sessionId: operatorSessionId || 'unknown',
          detail: 'user provisioning rejected',
          metadata: {
            operator_user_id: operatorUserId,
            phone_masked: maskPhone(normalizedPhone),
            entry_domain: sessionEntryDomain,
            tenant_id: activeTenantId,
            error_code:
              error instanceof AuthProblemError
                ? error.errorCode
                : 'AUTH-503-TENANT-MEMBER-DEPENDENCY-UNAVAILABLE'
          }
        });
        throw error;
      }
    }

    addAuditEvent({
      type: createdUser ? 'auth.user.provision.created' : 'auth.user.provision.reused',
      requestId,
      userId: provisionedUser.id,
      sessionId: operatorSessionId,
      detail: createdUser
        ? 'user provisioned with default password policy'
        : 'existing user reused without credential mutation',
      metadata: {
        operator_user_id: operatorUserId,
        phone_masked: maskPhone(normalizedPhone),
        entry_domain: sessionEntryDomain,
        tenant_id: relationTenantId,
        credential_initialized: createdUser,
        first_login_force_password_change: false
      }
    });

    return {
      user_id: provisionedUser.id,
      phone: provisionedUser.phone,
      created_user: createdUser,
      reused_existing_user: !createdUser,
      credential_initialized: createdUser,
      first_login_force_password_change: false,
      entry_domain: sessionEntryDomain,
      active_tenant_id: relationTenantId,
      request_id: requestId || 'request_id_unset'
    };
  };

  const provisionPlatformUserByPhone = async ({
    requestId,
    accessToken,
    phone,
    tenantName = undefined,
    payload = undefined,
    authorizationContext = null,
    authorizedRoute = null
  }) =>
    provisionUserByPhone({
      requestId,
      accessToken,
      phone,
      scope: 'platform',
      tenantName,
      payload,
      authorizationContext,
      authorizedRoute
    });

  const provisionTenantUserByPhone = async ({
    requestId,
    accessToken,
    phone,
    tenantName = undefined,
    payload = undefined,
    authorizationContext = null,
    authorizedRoute = null
  }) =>
    provisionUserByPhone({
      requestId,
      accessToken,
      phone,
      scope: 'tenant',
      tenantName,
      payload,
      authorizationContext,
      authorizedRoute
    });

  const findTenantMembershipByUserAndTenantId = async ({
    userId,
    tenantId
  }) => {
    const normalizedUserId = String(userId || '').trim();
    const normalizedTenantId = normalizeTenantId(tenantId);
    if (!normalizedUserId || !normalizedTenantId) {
      return null;
    }

    assertStoreMethod(authStore, 'findTenantMembershipByUserAndTenantId', 'authStore');
    let membership = null;
    try {
      membership = await authStore.findTenantMembershipByUserAndTenantId({
        userId: normalizedUserId,
        tenantId: normalizedTenantId
      });
    } catch (error) {
      throw errors.tenantMemberDependencyUnavailable({
        reason: String(error?.code || error?.message || 'query-failed')
      });
    }
    if (!membership) {
      return null;
    }
    const normalizedStatus = normalizeTenantMembershipStatus(membership.status);
    if (!normalizedStatus) {
      throw errors.tenantMemberDependencyUnavailable({
        reason: 'tenant-membership-status-invalid'
      });
    }
    const normalizedMembership = {
      membership_id: String(
        membership.membership_id
        || membership.membershipId
        || ''
      ).trim(),
      user_id: String(membership.user_id || membership.userId || '').trim(),
      tenant_id: String(membership.tenant_id || membership.tenantId || '').trim(),
      tenant_name: membership.tenant_name || membership.tenantName || null,
      phone: String(membership.phone || '').trim(),
      status: normalizedStatus,
      joined_at: membership.joined_at || membership.joinedAt || null,
      left_at: membership.left_at || membership.leftAt || null
    };
    const hasTenantMismatch =
      normalizedMembership.tenant_id.length > 0
      && normalizedMembership.tenant_id !== normalizedTenantId;
    const hasUserMismatch =
      normalizedMembership.user_id.length > 0
      && normalizedMembership.user_id !== normalizedUserId;
    if (
      !isValidTenantMembershipId(normalizedMembership.membership_id)
      || !normalizedMembership.user_id
      || !normalizedMembership.tenant_id
      || !normalizePhone(normalizedMembership.phone)
      || hasTenantMismatch
      || hasUserMismatch
    ) {
      throw errors.tenantMemberDependencyUnavailable({
        reason:
          hasTenantMismatch
          || hasUserMismatch
            ? 'tenant-membership-identity-mismatch'
            : 'tenant-membership-record-invalid'
      });
    }
    return normalizedMembership;
  };

  const listTenantMembers = async ({
    requestId,
    tenantId,
    page = 1,
    pageSize = 50
  }) => {
    const normalizedTenantId = normalizeTenantId(tenantId);
    if (!normalizedTenantId) {
      throw errors.noDomainAccess();
    }
    const normalizedPage = normalizeMemberListInteger({
      value: page,
      fallback: 1,
      min: 1,
      max: 100000
    });
    const normalizedPageSize = normalizeMemberListInteger({
      value: pageSize,
      fallback: 50,
      min: 1,
      max: 200
    });
    assertStoreMethod(authStore, 'listTenantMembersByTenantId', 'authStore');
    let members = [];
    try {
      members = await authStore.listTenantMembersByTenantId({
        tenantId: normalizedTenantId,
        page: normalizedPage,
        pageSize: normalizedPageSize
      });
    } catch (error) {
      throw errors.tenantMemberDependencyUnavailable({
        reason: String(error?.code || error?.message || 'query-failed')
      });
    }
    if (!Array.isArray(members)) {
      throw errors.tenantMemberDependencyUnavailable({
        reason: 'tenant-members-list-shape-invalid'
      });
    }
    const normalizedMembers = [];
    for (const member of members) {
      const normalizedStatus = normalizeTenantMembershipStatus(member?.status);
      if (!normalizedStatus) {
        throw errors.tenantMemberDependencyUnavailable({
          reason: 'tenant-membership-status-invalid'
        });
      }
      const normalizedMember = {
        membership_id: String(
          member?.membership_id
          || member?.membershipId
          || ''
        ).trim(),
        user_id: String(member?.user_id || member?.userId || '').trim(),
        tenant_id: String(member?.tenant_id || member?.tenantId || '').trim(),
        tenant_name: member?.tenant_name || member?.tenantName || null,
        phone: String(member?.phone || '').trim(),
        status: normalizedStatus,
        joined_at: member?.joined_at || member?.joinedAt || null,
        left_at: member?.left_at || member?.leftAt || null
      };
      const hasTenantMismatch =
        normalizedMember.tenant_id.length > 0
        && normalizedMember.tenant_id !== normalizedTenantId;
      if (
        !isValidTenantMembershipId(normalizedMember.membership_id)
        || !normalizedMember.user_id
        || !normalizedMember.tenant_id
        || !normalizePhone(normalizedMember.phone)
        || hasTenantMismatch
      ) {
        throw errors.tenantMemberDependencyUnavailable({
          reason: hasTenantMismatch
            ? 'tenant-membership-tenant-mismatch'
            : 'tenant-membership-record-invalid'
        });
      }
      normalizedMembers.push(normalizedMember);
    }
    return normalizedMembers;
  };

  const updateTenantMemberStatus = async ({
    requestId,
    accessToken,
    membershipId,
    nextStatus,
    reason = null,
    authorizationContext = null,
    authorizedRoute = null
  }) => {
    const rawMembershipId = String(membershipId || '');
    const normalizedMembershipId = rawMembershipId.trim();
    const normalizedNextStatus = normalizeTenantMembershipStatus(nextStatus);
    let normalizedReason = null;
    if (reason !== null && reason !== undefined) {
      if (typeof reason !== 'string') {
        throw errors.invalidPayload();
      }
      const normalizedReasonCandidate = String(reason).trim();
      if (
        !normalizedReasonCandidate
        || normalizedReasonCandidate.length > MAX_OWNER_TRANSFER_REASON_LENGTH
        || CONTROL_CHAR_PATTERN.test(normalizedReasonCandidate)
      ) {
        throw errors.invalidPayload();
      }
      normalizedReason = normalizedReasonCandidate;
    }
    if (
      !normalizedMembershipId
      || rawMembershipId !== normalizedMembershipId
      || !normalizedNextStatus
      || !isValidTenantMembershipId(normalizedMembershipId)
    ) {
      throw errors.invalidPayload();
    }

    const normalizedAuthorizedRoute =
      authorizedRoute && typeof authorizedRoute === 'object'
        ? {
          user_id: String(
            authorizedRoute.user_id
            || authorizedRoute.userId
            || ''
          ).trim(),
          session_id: String(
            authorizedRoute.session_id
            || authorizedRoute.sessionId
            || ''
          ).trim(),
          entry_domain: normalizeEntryDomain(
            authorizedRoute.entry_domain
            || authorizedRoute.entryDomain
          ),
          active_tenant_id: normalizeTenantId(
            authorizedRoute.active_tenant_id
            || authorizedRoute.activeTenantId
          )
        }
        : null;
    let resolvedAuthorizedRoute = null;
    if (normalizedAuthorizedRoute) {
      if (
        !normalizedAuthorizedRoute.user_id
        || !normalizedAuthorizedRoute.session_id
        || normalizedAuthorizedRoute.entry_domain !== 'tenant'
      ) {
        throw errors.forbidden();
      }
      resolvedAuthorizedRoute = normalizedAuthorizedRoute;
    } else {
      resolvedAuthorizedRoute = await authorizeRoute({
        requestId,
        accessToken,
        permissionCode: 'tenant.member_admin.operate',
        scope: 'tenant',
        authorizationContext
      });
    }

    const operatorUserId = String(resolvedAuthorizedRoute?.user_id || '').trim();
    const operatorSessionId = String(resolvedAuthorizedRoute?.session_id || '').trim();
    const activeTenantId = normalizeTenantId(resolvedAuthorizedRoute?.active_tenant_id);
    if (!operatorUserId || !operatorSessionId || !activeTenantId) {
      throw errors.noDomainAccess();
    }

    assertStoreMethod(authStore, 'updateTenantMembershipStatus', 'authStore');
    let result = null;
    try {
      result = await authStore.updateTenantMembershipStatus({
        membershipId: normalizedMembershipId,
        tenantId: activeTenantId,
        nextStatus: normalizedNextStatus,
        operatorUserId,
        reason: normalizedReason
      });
    } catch (error) {
      throw errors.tenantMemberDependencyUnavailable({
        reason: String(error?.code || error?.message || 'write-failed')
      });
    }
    if (!result) {
      throw errors.tenantMembershipNotFound();
    }

    const previousStatus = normalizeTenantMembershipStatus(result.previous_status);
    const currentStatus = normalizeTenantMembershipStatus(result.current_status);
    if (!previousStatus || !currentStatus) {
      throw errors.tenantMemberDependencyUnavailable({
        reason: 'tenant-membership-status-result-invalid'
      });
    }
    const resolvedMembershipId = String(
      result.membership_id || normalizedMembershipId
    ).trim();
    const resolvedTenantId = String(result.tenant_id || activeTenantId).trim();
    const isRejoinTransition =
      previousStatus === 'left'
      && normalizedNextStatus === 'active'
      && currentStatus === 'active';
    const hasMembershipIdMismatch = resolvedMembershipId !== normalizedMembershipId;
    if (
      !isValidTenantMembershipId(resolvedMembershipId)
      || !resolvedTenantId
      || resolvedTenantId !== activeTenantId
      || (isRejoinTransition && !hasMembershipIdMismatch)
      || (!isRejoinTransition && hasMembershipIdMismatch)
    ) {
      throw errors.tenantMemberDependencyUnavailable({
        reason: 'tenant-membership-result-shape-invalid'
      });
    }
    if (previousStatus !== currentStatus) {
      invalidateSessionCacheByUserId(String(result.user_id || '').trim());
    }
    addAuditEvent({
      type: 'auth.tenant.member.status.updated',
      requestId,
      userId: operatorUserId || 'unknown',
      sessionId: operatorSessionId || 'unknown',
      detail: previousStatus === currentStatus
        ? 'tenant membership status update treated as no-op'
        : 'tenant membership status updated',
      metadata: {
        membership_id: resolvedMembershipId,
        target_user_id: String(result.user_id || '').trim() || null,
        tenant_id: resolvedTenantId,
        previous_status: previousStatus,
        current_status: currentStatus,
        reason: normalizedReason
      }
    });
    return {
      membership_id: resolvedMembershipId,
      user_id: String(result.user_id || '').trim(),
      tenant_id: resolvedTenantId,
      previous_status: previousStatus,
      current_status: currentStatus
    };
  };

  const selectOrSwitchTenant = async ({
    requestId,
    accessToken,
    tenantId,
    eventType,
    authorizationContext = null
  }) => {
    const normalizedTenantId = normalizeTenantId(tenantId);
    if (!normalizedTenantId) {
      throw errors.invalidPayload();
    }

    const { session, user } = await resolveAuthorizedSession({
      requestId,
      accessToken,
      authorizationContext
    });
    const sessionId = session.sessionId || session.session_id;
    const sessionContext = buildSessionContext(session);

    await assertDomainAccess({
      requestId,
      userId: user.id,
      entryDomain: 'tenant'
    });

    if (sessionContext.entry_domain !== 'tenant') {
      addAuditEvent({
        type: 'auth.domain.rejected',
        requestId,
        userId: user.id,
        sessionId,
        detail: `tenant selection rejected for entry domain ${sessionContext.entry_domain}`,
        metadata: {
          permission_code: null,
          entry_domain: sessionContext.entry_domain,
          tenant_id: normalizedTenantId
        }
      });
      throw errors.noDomainAccess();
    }

    const options = await getTenantOptionsForUser(user.id);
    const matched = options.find((item) => item.tenant_id === normalizedTenantId);
    if (!matched) {
      addAuditEvent({
        type: 'auth.domain.rejected',
        requestId,
        userId: user.id,
        sessionId,
        detail: `tenant selection rejected: ${normalizedTenantId}`,
        metadata: {
          permission_code: null,
          entry_domain: sessionContext.entry_domain,
          tenant_id: normalizedTenantId
        }
      });
      throw errors.noDomainAccess();
    }

    if (typeof authStore.updateSessionContext !== 'function') {
      throw new Error('authStore.updateSessionContext is required');
    }
    await authStore.updateSessionContext({
      sessionId,
      entryDomain: 'tenant',
      activeTenantId: normalizedTenantId
    });
    invalidateSessionCacheBySessionId(sessionId);

    addAuditEvent({
      type: eventType,
      requestId,
      userId: user.id,
      sessionId,
      detail: `active tenant updated: ${normalizedTenantId}`,
      metadata: {
        entry_domain: 'tenant',
        tenant_id: normalizedTenantId
      }
    });

    const tenantPermissionContext = await getTenantPermissionContext({
      requestId,
      userId: user.id,
      sessionId,
      entryDomain: 'tenant',
      activeTenantId: normalizedTenantId
    });

    return {
      session_id: sessionId,
      entry_domain: 'tenant',
      active_tenant_id: normalizedTenantId,
      tenant_selection_required: false,
      tenant_permission_context: tenantPermissionContext,
      request_id: requestId || 'request_id_unset'
    };
  };

  const selectTenant = async ({
    requestId,
    accessToken,
    tenantId,
    authorizationContext = null
  }) =>
    selectOrSwitchTenant({
      requestId,
      accessToken,
      tenantId,
      eventType: 'auth.tenant.selected',
      authorizationContext
    });

  const switchTenant = async ({
    requestId,
    accessToken,
    tenantId,
    authorizationContext = null
  }) =>
    selectOrSwitchTenant({
      requestId,
      accessToken,
      tenantId,
      eventType: 'auth.tenant.switched',
      authorizationContext
    });

  return {
    login,
    sendOtp,
    loginWithOtp,
    tenantOptions,
    authorizeRoute,
    selectTenant,
    switchTenant,
    refresh,
    logout,
    changePassword,
    provisionPlatformUserByPhone,
    provisionTenantUserByPhone,
    findTenantMembershipByUserAndTenantId,
    listTenantMembers,
    updateTenantMemberStatus,
    getOrCreateUserIdentityByPhone,
    createOrganizationWithOwner,
    acquireOwnerTransferLock,
    releaseOwnerTransferLock,
    validateOwnerTransferRequest,
    createPlatformRoleCatalogEntry,
    updatePlatformRoleCatalogEntry,
    deletePlatformRoleCatalogEntry,
    listPlatformRoleCatalogEntries,
    findPlatformRoleCatalogEntryByRoleId,
    listPlatformRolePermissionGrants,
    replacePlatformRolePermissionGrants,
    listPlatformPermissionCatalog,
    updateOrganizationStatus,
    updatePlatformUserStatus,
    rollbackProvisionedUserIdentity,
    replacePlatformRolesAndSyncSnapshot,
    recordIdempotencyEvent,
    // Test support
    _internals: {
      auditTrail,
      authStore,
      accessSessionCache,
      accessSessionCacheTtlMs,
      ownerTransferLocksByOrgId
    }
  };
};

module.exports = {
  ACCESS_TTL_SECONDS,
  REFRESH_TTL_SECONDS,
  OTP_TTL_SECONDS,
  RATE_LIMIT_WINDOW_SECONDS,
  RATE_LIMIT_MAX_ATTEMPTS,
  listSupportedRoutePermissionCodes: () => Object.keys(ROUTE_PERMISSION_EVALUATORS),
  listSupportedRoutePermissionScopes,
  AuthProblemError,
  createAuthService
};
