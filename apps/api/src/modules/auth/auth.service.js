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

const verifyJwt = ({ token, publicKeyPem, expectedTyp }) => {
  if (typeof token !== 'string' || token.trim().length === 0) {
    throw new Error('jwt missing');
  }

  const sections = token.split('.');
  if (sections.length !== 3) {
    throw new Error('jwt malformed');
  }

  const [encodedHeader, encodedPayload, encodedSignature] = sections;
  const signingInput = `${encodedHeader}.${encodedPayload}`;

  const verifier = createVerify('RSA-SHA256');
  verifier.update(signingInput);
  verifier.end();

  const signature = fromBase64Url(encodedSignature);
  const validSignature = verifier.verify(publicKeyPem, signature);
  if (!validSignature) {
    throw new Error('jwt signature mismatch');
  }

  const header = JSON.parse(fromBase64Url(encodedHeader).toString('utf8'));
  const payload = JSON.parse(fromBase64Url(encodedPayload).toString('utf8'));

  if (header.alg !== 'RS256') {
    throw new Error('jwt alg mismatch');
  }

  if (expectedTyp && payload.typ !== expectedTyp) {
    throw new Error('jwt typ mismatch');
  }

  const nowSeconds = Math.floor(Date.now() / 1000);
  if (typeof payload.exp !== 'number' || payload.exp <= nowSeconds) {
    throw new Error('jwt expired');
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

  const createSessionAndIssueLoginTokens = async ({ userId, sessionVersion }) => {
    const sessionId = randomUUID();
    await authStore.createSession({
      sessionId,
      userId,
      sessionVersion: Number(sessionVersion)
    });

    const { accessToken, refreshToken } = await issueLoginTokenPair({
      userId,
      sessionId,
      sessionVersion: Number(sessionVersion)
    });

    return {
      sessionId,
      accessToken,
      refreshToken
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

  const login = async ({ requestId, phone, password }) => {
    const normalizedPhone = normalizePhone(phone);
    if (!normalizedPhone || typeof password !== 'string' || password.trim() === '') {
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

    const { sessionId, accessToken, refreshToken } = await createSessionAndIssueLoginTokens({
      userId: user.id,
      sessionVersion: Number(user.sessionVersion)
    });

    addAuditEvent({
      type: 'auth.login.succeeded',
      requestId,
      userId: user.id,
      sessionId,
      metadata: {
        phone_masked: maskPhone(normalizedPhone),
        resend_after_seconds: rateLimit.remainingSeconds
      }
    });

    return {
      token_type: 'Bearer',
      access_token: accessToken,
      refresh_token: refreshToken,
      expires_in: ACCESS_TTL_SECONDS,
      refresh_expires_in: REFRESH_TTL_SECONDS,
      session_id: sessionId,
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

  const loginWithOtp = async ({ requestId, phone, otpCode }) => {
    const normalizedPhone = normalizePhone(phone);
    if (!normalizedPhone || typeof otpCode !== 'string' || !/^\d{6}$/.test(otpCode.trim())) {
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

    const { sessionId, accessToken, refreshToken } = await createSessionAndIssueLoginTokens({
      userId: user.id,
      sessionVersion: Number(user.sessionVersion)
    });

    addAuditEvent({
      type: 'auth.otp.login.succeeded',
      requestId,
      userId: user.id,
      sessionId,
      metadata: {
        phone_masked: maskPhone(normalizedPhone)
      }
    });

    return {
      token_type: 'Bearer',
      access_token: accessToken,
      refresh_token: refreshToken,
      expires_in: ACCESS_TTL_SECONDS,
      refresh_expires_in: REFRESH_TTL_SECONDS,
      session_id: sessionId,
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
          session_id_hint: 'unknown'
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
    } catch (_error) {
      addAuditEvent({
        type: 'auth.refresh.replay_or_invalid',
        requestId,
        detail: 'refresh token malformed',
        metadata: {
          session_id_hint: 'unknown'
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

    const invalidState = (
      !refreshRecord ||
      String(refreshRecord.status).toLowerCase() !== 'active' ||
      refreshRecord.expiresAt <= now() ||
      !session ||
      String(session.status).toLowerCase() !== 'active' ||
      !user ||
      String(session.userId) !== String(user.id) ||
      Number(session.sessionVersion) !== Number(payload.sv) ||
      Number(user.sessionVersion) !== Number(payload.sv)
    );

    if (invalidState) {
      const refreshStatus = refreshRecord ? String(refreshRecord.status).toLowerCase() : 'missing';
      const replayDetected = refreshStatus === 'rotated' || refreshStatus === 'revoked';

      if (refreshRecord && refreshRecord.status === 'active') {
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
          session_id_hint: String(payload.sid || 'unknown')
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
            session_id_hint: String(sessionId || 'unknown')
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
      request_id: requestId || 'request_id_unset'
    };
  };

  const logout = async ({ requestId, accessToken }) => {
    const { session, user } = await assertValidAccessSession(accessToken);
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

  const changePassword = async ({ requestId, accessToken, currentPassword, newPassword }) => {
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

    const { session, user } = await assertValidAccessSession(accessToken);
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

  return {
    login,
    sendOtp,
    loginWithOtp,
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
  AuthProblemError,
  createAuthService
};
