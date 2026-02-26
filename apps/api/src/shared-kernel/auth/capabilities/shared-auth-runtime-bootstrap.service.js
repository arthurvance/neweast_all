'use strict';

const { generateKeyPairSync } = require('node:crypto');
const { createInMemoryAuthStore } = require('../store/create-in-memory-auth-store');
const {
  ACCESS_SESSION_CACHE_TTL_MS,
  DEFAULT_SEED_USERS,
  assertOtpStoreContract,
  createInMemoryOtpStore,
  createInMemoryRateLimitStore,
  deriveSensitiveConfigKeys,
  hashPassword
} = require('../create-auth-service.helpers');

const createSharedAuthRuntimeBootstrap = ({
  options = {}
} = {}) => {
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
    hasExternalAuthStore
    && !allowInMemoryOtpStores
    && (!options.otpStore || !options.rateLimitStore)
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

  const ownerTransferLocksByOrgId = new Map();

  return {
    now,
    authStore,
    otpStore,
    rateLimitStore,
    accessSessionCache,
    accessSessionCacheTtlMs,
    sensitiveConfigProvider,
    sensitiveConfigDecryptionKey,
    sensitiveConfigDecryptionKeys,
    jwtKeyPair,
    ownerTransferLocksByOrgId
  };
};

module.exports = {
  createSharedAuthRuntimeBootstrap
};
