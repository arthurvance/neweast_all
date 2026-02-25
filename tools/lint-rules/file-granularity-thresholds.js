'use strict';

const { toPosix } = require('./ast-import-utils');

const MAX_PRODUCTION_LOC = 800;
const MIN_CAPABILITY_LOC = 120;
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
  if (effectiveLoc > MAX_PRODUCTION_LOC) {
    errors.push(
      `file too large (${effectiveLoc} LOC > ${MAX_PRODUCTION_LOC}). Split by responsibility before merge`
    );
  }

  const exportCount = countExportStatements(content);
  if (
    effectiveLoc < MIN_CAPABILITY_LOC
    && exportCount <= 1
    && !isRouteAdapterFile(normalizedPath)
  ) {
    errors.push(
      `file likely over-fragmented (${effectiveLoc} LOC < ${MIN_CAPABILITY_LOC} with ${exportCount} export). Consider capability-level aggregation`
    );
  }

  return errors;
}

module.exports = {
  id: 'file-granularity-thresholds',
  checkFile,
  _internals: {
    MAX_PRODUCTION_LOC,
    MIN_CAPABILITY_LOC,
    countEffectiveLoc,
    countExportStatements,
    isDomainCapabilitySourceFile,
    isRouteAdapterFile,
    toPosix
  }
};
