const { createHash, generateKeyPairSync, pbkdf2Sync, randomBytes, randomUUID, randomInt, timingSafeEqual, createSign, createVerify } = require('node:crypto');
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

  platformSnapshotDegraded: ({ reason = 'db-deadlock' } = {}) =>
    authError({
      status: 503,
      title: 'Service Unavailable',
      detail: '平台权限同步暂时不可用，请稍后重试',
      errorCode: 'AUTH-503-PLATFORM-SNAPSHOT-DEGRADED',
      extensions: {
        degradation_reason: String(reason || 'unknown')
      }
    })
};

const toBase64Url = (input) => {
  const raw = Buffer.isBuffer(input) ? input : Buffer.from(input, 'utf8');
  return raw.toString('base64url');
};

const fromBase64Url = (input) => Buffer.from(input, 'base64url');

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
    log('info', 'Auth audit event', event);
  };

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
      return;
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

  const assertValidAccessSession = async (accessToken) => {
    let payload;
    try {
      payload = verifyJwt({
        token: accessToken,
        publicKeyPem: jwtKeyPair.publicKey,
        expectedTyp: 'access'
      });
    } catch (_error) {
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

    if (!session || !user || String(session.status).toLowerCase() !== 'active') {
      throw errors.invalidAccess();
    }

    if (
      String(session.userId) !== String(payload.sub) ||
      Number(session.sessionVersion) !== Number(payload.sv) ||
      Number(user.sessionVersion) !== Number(payload.sv)
    ) {
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

  const resolveAuthorizedSession = async ({ accessToken, authorizationContext = null }) => {
    const authorizedSession = await assertValidAccessSession(accessToken);
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

    const invalidState = (
      !refreshRecord ||
      !refreshBelongsToClaim ||
      refreshStatus !== 'active' ||
      refreshExpired ||
      !session ||
      String(session.status).toLowerCase() !== 'active' ||
      !user ||
      String(session.userId) !== String(user.id) ||
      Number(session.sessionVersion) !== Number(payload.sv) ||
      Number(user.sessionVersion) !== Number(payload.sv)
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

  const tenantOptions = async ({
    requestId,
    accessToken,
    authorizationContext = null
  }) => {
    const { session, user } = await resolveAuthorizedSession({
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
    scope = 'session'
  }) => {
    const normalizedPermissionCode = String(permissionCode || '').trim();
    if (normalizedPermissionCode.length === 0) {
      throw errors.forbidden();
    }

    const { session, user } = await resolveAuthorizedSession({ accessToken });
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
    // Test support
    _internals: {
      auditTrail,
      authStore,
      accessSessionCache,
      accessSessionCacheTtlMs
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
