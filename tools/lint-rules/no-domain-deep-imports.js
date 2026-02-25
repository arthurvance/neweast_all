'use strict';

const DOMAIN_SEGMENTS = new Set(['platform', 'tenant']);
const {
  collectImportSpecifiers,
  resolveSpecifier,
  toPosix
} = require('./ast-import-utils');
const ALLOWED_REMAINDERS = new Set([
  '',
  'index',
  'index.js',
  'index.mjs',
  'index.cjs',
  'index.ts',
  'index.tsx',
  'index.jsx'
]);

function resolveDomainPath(refPath) {
  const normalized = toPosix(refPath);
  const srcMarker = '/src/domains/';
  const sourceRootMarker = 'src/domains/';
  const bareMarker = 'domains/';

  const srcMarkerIndex = normalized.lastIndexOf(srcMarker);
  if (srcMarkerIndex !== -1) {
    return normalized.slice(srcMarkerIndex + srcMarker.length);
  }

  if (normalized.startsWith(sourceRootMarker)) {
    return normalized.slice(sourceRootMarker.length);
  }

  if (normalized.startsWith(bareMarker)) {
    return normalized.slice(bareMarker.length);
  }

  return null;
}

function getDomainRemainder(refPath) {
  const domainPath = resolveDomainPath(refPath);
  if (!domainPath) {
    return null;
  }

  const segments = domainPath.split('/').filter(Boolean);
  if (segments.length === 0) {
    return null;
  }

  const domain = segments[0];
  if (!DOMAIN_SEGMENTS.has(domain)) {
    return null;
  }

  const remainder = segments.slice(1).join('/');
  return {
    domain,
    remainder
  };
}

function checkFile({ filePath, content }) {
  const normalizedPath = toPosix(filePath);
  if (!normalizedPath.includes('/src/')) {
    return [];
  }

  if (normalizedPath.includes('/src/domains/')) {
    return [];
  }

  if (normalizedPath.includes('/src/modules/')) {
    return [];
  }

  const errors = [];
  const { specifiers, parseError } = collectImportSpecifiers(content, filePath);
  if (parseError) {
    errors.push(parseError);
    return errors;
  }

  for (const specifier of specifiers) {
    const resolved = resolveSpecifier(filePath, specifier);
    const remainderInfo = getDomainRemainder(resolved);
    if (!remainderInfo) {
      continue;
    }

    if (!ALLOWED_REMAINDERS.has(remainderInfo.remainder)) {
      errors.push(
        `domain deep import is blocked. Use domains/${remainderInfo.domain}/index instead: ${specifier}`
      );
    }
  }

  return errors;
}

module.exports = {
  id: 'no-domain-deep-imports',
  checkFile,
  _internals: {
    resolveSpecifier,
    resolveDomainPath,
    getDomainRemainder,
    toPosix
  }
};
