const { createHash, createHmac, generateKeyPairSync, pbkdf2Sync, randomBytes, randomUUID, timingSafeEqual, createSign, createVerify } = require('node:crypto');
const { log } = require('../../common/logger');

const ACCESS_TTL_SECONDS = 15 * 60;
const REFRESH_TTL_SECONDS = 7 * 24 * 60 * 60;
const PASSWORD_MIN_LENGTH = 6;
const PBKDF2_ITERATIONS = 150000;
const PBKDF2_KEYLEN = 64;
const PBKDF2_DIGEST = 'sha512';

const DEFAULT_SEED_USERS = [
  {
    id: 'user-platform-1',
    phone: '13800000000',
    password: 'Passw0rd!',
    status: 'active',
    sessionVersion: 1
  },
  {
    id: 'user-platform-disabled',
    phone: '13800000001',
    password: 'Passw0rd!',
    status: 'disabled',
    sessionVersion: 1
  }
];

class AuthProblemError extends Error {
  constructor({ status, title, detail, errorCode }) {
    super(detail);
    this.name = 'AuthProblemError';
    this.status = status;
    this.title = title;
    this.detail = detail;
    this.errorCode = errorCode;
  }
}

const authError = ({ status, title, detail, errorCode }) => new AuthProblemError({
  status,
  title,
  detail,
  errorCode
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

  const actualHex = pbkdf2Sync(
    plainTextPassword,
    salt,
    iterations,
    Buffer.from(expectedHex, 'hex').length,
    digest
  ).toString('hex');

  const expected = Buffer.from(expectedHex, 'hex');
  const actual = Buffer.from(actualHex, 'hex');

  if (expected.length !== actual.length) {
    return false;
  }

  return timingSafeEqual(expected, actual);
};

const tokenHash = (rawToken) => createHash('sha256').update(rawToken).digest('hex');

const refreshFingerprint = (rawToken) => createHmac('sha256', 'refresh-fingerprint').update(rawToken).digest('hex').slice(0, 16);

const createAuthService = (options = {}) => {
  const now = options.now || (() => Date.now());
  const seedUsers = options.seedUsers || DEFAULT_SEED_USERS;

  const jwtKeyPair = options.jwtKeyPair || generateKeyPairSync('rsa', {
    modulusLength: 2048,
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
  });

  const usersByPhone = new Map();
  const usersById = new Map();
  const sessionsById = new Map();
  const refreshTokensByHash = new Map();
  const refreshHashesBySessionId = new Map();
  const auditTrail = [];

  for (const user of seedUsers) {
    const normalizedUser = {
      id: user.id,
      phone: user.phone,
      status: user.status || 'active',
      sessionVersion: user.sessionVersion || 1,
      passwordHash: hashPassword(user.password)
    };

    usersByPhone.set(normalizedUser.phone, normalizedUser);
    usersById.set(normalizedUser.id, normalizedUser);
  }

  const addAuditEvent = ({ type, requestId, userId = 'unknown', sessionId = 'unknown', detail = '' }) => {
    const event = {
      type,
      at: new Date(now()).toISOString(),
      request_id: requestId || 'request_id_unset',
      user_id: userId,
      session_id: sessionId,
      detail
    };

    auditTrail.push(event);
    log('info', 'Auth audit event', event);
  };

  const validatePasswordPolicy = (candidatePassword) => {
    if (typeof candidatePassword !== 'string' || candidatePassword.length < PASSWORD_MIN_LENGTH) {
      throw errors.weakPassword();
    }
  };

  const markRefreshTokenStatus = (refreshHash, nextStatus, note = '') => {
    const record = refreshTokensByHash.get(refreshHash);
    if (!record) {
      return;
    }

    record.status = nextStatus;
    record.updatedAt = now();
    if (note) {
      record.note = note;
    }
  };

  const revokeSession = (sessionId, reason) => {
    const session = sessionsById.get(sessionId);
    if (!session || session.status !== 'active') {
      return;
    }

    session.status = 'revoked';
    session.revokedReason = reason;
    session.updatedAt = now();

    const refreshHashes = refreshHashesBySessionId.get(sessionId) || new Set();
    for (const refreshHash of refreshHashes) {
      const refreshRecord = refreshTokensByHash.get(refreshHash);
      if (refreshRecord && refreshRecord.status === 'active') {
        markRefreshTokenStatus(refreshHash, 'revoked', reason);
      }
    }
  };

  const issueTokenPair = ({ userId, sessionId, sessionVersion }) => {
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

    const refreshToken = signJwt({
      privateKeyPem: jwtKeyPair.privateKey,
      ttlSeconds: REFRESH_TTL_SECONDS,
      payload: {
        sub: userId,
        sid: sessionId,
        sv: sessionVersion,
        jti: randomUUID(),
        typ: 'refresh'
      }
    });

    const refreshHash = tokenHash(refreshToken);
    const expiresAt = now() + REFRESH_TTL_SECONDS * 1000;
    const refreshRecord = {
      tokenHash: refreshHash,
      tokenFingerprint: refreshFingerprint(refreshToken),
      userId,
      sessionId,
      status: 'active',
      createdAt: now(),
      updatedAt: now(),
      expiresAt
    };

    refreshTokensByHash.set(refreshHash, refreshRecord);
    if (!refreshHashesBySessionId.has(sessionId)) {
      refreshHashesBySessionId.set(sessionId, new Set());
    }
    refreshHashesBySessionId.get(sessionId).add(refreshHash);

    return {
      accessToken,
      refreshToken,
      refreshHash
    };
  };

  const assertValidAccessSession = (accessToken) => {
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

    const session = sessionsById.get(payload.sid);
    const user = usersById.get(payload.sub);

    if (!session || !user || session.status !== 'active') {
      throw errors.invalidAccess();
    }

    if (session.userId !== payload.sub || session.sessionVersion !== payload.sv || user.sessionVersion !== payload.sv) {
      throw errors.invalidAccess();
    }

    return { payload, session, user };
  };

  const login = ({ requestId, phone, password }) => {
    if (typeof phone !== 'string' || typeof password !== 'string' || phone.trim() === '' || password.trim() === '') {
      throw errors.invalidPayload();
    }

    const user = usersByPhone.get(phone.trim());
    const validCredentials = Boolean(
      user && user.status === 'active' && verifyPassword(password, user.passwordHash)
    );

    if (!validCredentials) {
      addAuditEvent({
        type: 'auth.login.failed',
        requestId,
        userId: user?.id,
        detail: 'invalid credentials or unavailable user'
      });
      throw errors.loginFailed();
    }

    const sessionId = randomUUID();
    sessionsById.set(sessionId, {
      sessionId,
      userId: user.id,
      sessionVersion: user.sessionVersion,
      status: 'active',
      createdAt: now(),
      updatedAt: now()
    });

    const { accessToken, refreshToken } = issueTokenPair({
      userId: user.id,
      sessionId,
      sessionVersion: user.sessionVersion
    });

    addAuditEvent({
      type: 'auth.login.succeeded',
      requestId,
      userId: user.id,
      sessionId
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

  const refresh = ({ requestId, refreshToken }) => {
    if (typeof refreshToken !== 'string' || refreshToken.trim() === '') {
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
      throw errors.invalidRefresh();
    }

    const refreshHash = tokenHash(refreshToken);
    const refreshRecord = refreshTokensByHash.get(refreshHash);
    const session = sessionsById.get(payload.sid);
    const user = usersById.get(payload.sub);

    const invalidState = (
      !refreshRecord ||
      refreshRecord.status !== 'active' ||
      refreshRecord.expiresAt <= now() ||
      !session ||
      session.status !== 'active' ||
      !user ||
      session.userId !== user.id ||
      session.sessionVersion !== payload.sv ||
      user.sessionVersion !== payload.sv
    );

    if (invalidState) {
      if (refreshRecord && refreshRecord.status === 'active') {
        markRefreshTokenStatus(refreshHash, 'revoked', 'invalid session state');
      }

      addAuditEvent({
        type: 'auth.refresh.replay_or_invalid',
        requestId,
        userId: payload.sub,
        sessionId: payload.sid,
        detail: 'refresh token rejected'
      });
      throw errors.invalidRefresh();
    }

    markRefreshTokenStatus(refreshHash, 'rotated', 'token rotated');

    const { accessToken, refreshToken: nextRefreshToken, refreshHash: nextRefreshHash } = issueTokenPair({
      userId: user.id,
      sessionId: session.sessionId,
      sessionVersion: user.sessionVersion
    });

    const nextRecord = refreshTokensByHash.get(nextRefreshHash);
    nextRecord.rotatedFrom = refreshHash;

    const previousRecord = refreshTokensByHash.get(refreshHash);
    previousRecord.rotatedTo = nextRefreshHash;

    session.updatedAt = now();

    addAuditEvent({
      type: 'auth.refresh.succeeded',
      requestId,
      userId: user.id,
      sessionId: session.sessionId
    });

    return {
      token_type: 'Bearer',
      access_token: accessToken,
      refresh_token: nextRefreshToken,
      expires_in: ACCESS_TTL_SECONDS,
      refresh_expires_in: REFRESH_TTL_SECONDS,
      session_id: session.sessionId,
      request_id: requestId || 'request_id_unset'
    };
  };

  const logout = ({ requestId, accessToken }) => {
    const { session, user } = assertValidAccessSession(accessToken);
    revokeSession(session.sessionId, 'logout-current-session');

    addAuditEvent({
      type: 'auth.logout.current_session',
      requestId,
      userId: user.id,
      sessionId: session.sessionId
    });

    return {
      ok: true,
      session_id: session.sessionId,
      request_id: requestId || 'request_id_unset'
    };
  };

  const changePassword = ({ requestId, accessToken, currentPassword, newPassword }) => {
    if (typeof currentPassword !== 'string' || typeof newPassword !== 'string') {
      throw errors.invalidPayload();
    }

    validatePasswordPolicy(newPassword);

    const { session, user } = assertValidAccessSession(accessToken);
    const currentPasswordValid = verifyPassword(currentPassword, user.passwordHash);

    if (!currentPasswordValid) {
      addAuditEvent({
        type: 'auth.password_change.rejected',
        requestId,
        userId: user.id,
        sessionId: session.sessionId,
        detail: 'current password mismatch'
      });
      throw errors.loginFailed();
    }

    user.passwordHash = hashPassword(newPassword);
    user.sessionVersion += 1;

    for (const candidateSession of sessionsById.values()) {
      if (candidateSession.userId === user.id) {
        revokeSession(candidateSession.sessionId, 'password-changed');
      }
    }

    addAuditEvent({
      type: 'auth.password_change.succeeded',
      requestId,
      userId: user.id,
      sessionId: session.sessionId
    });

    return {
      password_changed: true,
      relogin_required: true,
      request_id: requestId || 'request_id_unset'
    };
  };

  return {
    login,
    refresh,
    logout,
    changePassword,
    // Test support
    _internals: {
      auditTrail,
      usersById,
      sessionsById,
      refreshTokensByHash
    }
  };
};

module.exports = {
  ACCESS_TTL_SECONDS,
  REFRESH_TTL_SECONDS,
  AuthProblemError,
  createAuthService
};
