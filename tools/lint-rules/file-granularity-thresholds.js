'use strict';

const { toPosix } = require('./ast-import-utils');

const DEFAULT_MAX_PRODUCTION_LOC = 800;
const DEFAULT_MIN_CAPABILITY_LOC = 120;
const AUTH_MAX_PRODUCTION_LOC = 500;
const AUTH_MIN_CAPABILITY_LOC = 80;
const AUTH_MIN_TOOLING_LOC = 40;
const SOURCE_FILE_RE = /\.(?:[mc]?js|ts)$/;
const ROUTE_ADAPTER_FILE_RE = /\.routes\.(?:[mc]?js|ts)$/;

function countEffectiveLoc(content = '') {
  return String(content)
    .split(/\r?\n/)
    .filter((line) => line.trim().length > 0).length;
}

function countExportStatements(content = '') {
  const normalized = String(content);
  let count = 0;
  const patterns = [
    /\bmodule\.exports\b/g,
    /\bexports\.[A-Za-z0-9_$]+\b/g,
    /\bexport\s+default\b/g,
    /\bexport\s+(?:const|function|class)\b/g,
    /\bexport\s*\{/g
  ];
  for (const pattern of patterns) {
    const matches = normalized.match(pattern);
    if (matches) {
      count += matches.length;
    }
  }
  return count;
}

function isDomainCapabilitySourceFile(filePath = '') {
  const normalizedPath = toPosix(filePath);
  if (!normalizedPath.includes('/src/domains/')) {
    return false;
  }
  if (!SOURCE_FILE_RE.test(normalizedPath)) {
    return false;
  }
  if (normalizedPath.endsWith('/index.js') || normalizedPath.endsWith('/index.mjs')) {
    return false;
  }
  if (normalizedPath.includes('/runtime/')) {
    return false;
  }
  if (normalizedPath.includes('/domain-extension/registry/')) {
    return false;
  }
  return true;
}

function isRouteAdapterFile(filePath = '') {
  return ROUTE_ADAPTER_FILE_RE.test(toPosix(filePath));
}

function isToolingSourceFile(filePath = '') {
  const normalizedPath = toPosix(filePath);
  return (
    normalizedPath.includes('/utils/')
    || normalizedPath.includes('/helpers/')
    || normalizedPath.includes('/constants/')
  );
}

function isAuthCapabilitySourceFile(filePath = '') {
  const normalizedPath = toPosix(filePath);
  return (
    normalizedPath.includes('/src/domains/platform/auth/')
    || normalizedPath.includes('/src/domains/tenant/auth/')
  );
}

function isAuthBridgeWrapperFile(filePath = '', content = '') {
  const normalizedPath = toPosix(filePath);
  if (!isAuthCapabilitySourceFile(normalizedPath)) {
    return false;
  }
  if (
    !normalizedPath.endsWith('.service.js')
    && !normalizedPath.endsWith('.store.memory.js')
    && !normalizedPath.endsWith('.store.mysql.js')
  ) {
    return false;
  }
  const normalizedContent = String(content || '');
  return (
    normalizedContent.includes('createAuthService(')
    || normalizedContent.includes('createInMemoryAuthStore(')
    || normalizedContent.includes('createMySqlAuthStore(')
  );
}

function checkFile({ filePath, content }) {
  const normalizedPath = toPosix(filePath);
  if (!normalizedPath.includes('/src/')) {
    return [];
  }

  if (!isDomainCapabilitySourceFile(normalizedPath)) {
    return [];
  }

  const errors = [];
  const effectiveLoc = countEffectiveLoc(content);
  const isAuthScope = isAuthCapabilitySourceFile(normalizedPath);
  const maxProductionLoc = isAuthScope
    ? AUTH_MAX_PRODUCTION_LOC
    : DEFAULT_MAX_PRODUCTION_LOC;
  if (effectiveLoc > maxProductionLoc) {
    errors.push(
      `file too large (${effectiveLoc} LOC > ${maxProductionLoc}). Split by responsibility before merge`
    );
  }

  const exportCount = countExportStatements(content);
  if (isAuthBridgeWrapperFile(normalizedPath, content)) {
    return errors;
  }
  const minimumLoc = isToolingSourceFile(normalizedPath)
    ? (isAuthScope ? AUTH_MIN_TOOLING_LOC : DEFAULT_MIN_CAPABILITY_LOC)
    : (isAuthScope ? AUTH_MIN_CAPABILITY_LOC : DEFAULT_MIN_CAPABILITY_LOC);
  if (
    effectiveLoc < minimumLoc
    && exportCount <= 1
    && !isRouteAdapterFile(normalizedPath)
  ) {
    errors.push(
      `file likely over-fragmented (${effectiveLoc} LOC < ${minimumLoc} with ${exportCount} export). Consider capability-level aggregation`
    );
  }

  return errors;
}

module.exports = {
  id: 'file-granularity-thresholds',
  checkFile,
  _internals: {
    DEFAULT_MAX_PRODUCTION_LOC,
    DEFAULT_MIN_CAPABILITY_LOC,
    AUTH_MAX_PRODUCTION_LOC,
    AUTH_MIN_CAPABILITY_LOC,
    AUTH_MIN_TOOLING_LOC,
    countEffectiveLoc,
    countExportStatements,
    isDomainCapabilitySourceFile,
    isRouteAdapterFile,
    isToolingSourceFile,
    isAuthCapabilitySourceFile,
    isAuthBridgeWrapperFile,
    toPosix
  }
};
