'use strict';

const fs = require('node:fs');
const path = require('node:path');

const DOMAIN_RE = /domains\/(platform|tenant)(?:\/|$)/;
const {
  collectImportSpecifiers,
  resolveSpecifier,
  toPosix
} = require('./ast-import-utils');

const NAMING_RULES_PATH = path.resolve(__dirname, '../domain-contract/naming-rules.json');
let cachedAllowlist = null;

function resolveDomain(refPath) {
  const match = refPath.match(DOMAIN_RE);
  return match ? match[1] : null;
}

function compileAllowlist(rawAllowlist = []) {
  if (!Array.isArray(rawAllowlist)) {
    return [];
  }

  const compiled = [];
  for (let index = 0; index < rawAllowlist.length; index += 1) {
    const item = rawAllowlist[index] || {};
    const fromDomain = String(item.from_domain || '*').trim().toLowerCase() || '*';
    const toDomain = String(item.to_domain || '*').trim().toLowerCase() || '*';
    const specifierRegexRaw = String(item.specifier_regex || '').trim();
    const resolvedPathRegexRaw = String(item.resolved_path_regex || '').trim();

    if (!specifierRegexRaw && !resolvedPathRegexRaw) {
      continue;
    }

    let specifierRegex = null;
    let resolvedPathRegex = null;
    try {
      specifierRegex = specifierRegexRaw ? new RegExp(specifierRegexRaw) : null;
    } catch (_error) {
      continue;
    }
    try {
      resolvedPathRegex = resolvedPathRegexRaw ? new RegExp(resolvedPathRegexRaw) : null;
    } catch (_error) {
      continue;
    }

    compiled.push({
      index,
      fromDomain,
      toDomain,
      specifierRegex,
      resolvedPathRegex
    });
  }
  return compiled;
}

function loadCrossDomainAllowlist() {
  if (cachedAllowlist) {
    return cachedAllowlist;
  }

  let parsed = null;
  try {
    parsed = JSON.parse(fs.readFileSync(NAMING_RULES_PATH, 'utf8'));
  } catch (_error) {
    cachedAllowlist = [];
    return cachedAllowlist;
  }

  const rules = parsed && parsed.rules && typeof parsed.rules === 'object'
    ? parsed.rules
    : {};
  const rawAllowlist = Array.isArray(rules.cross_domain_import_allowlist)
    ? rules.cross_domain_import_allowlist
    : [];
  cachedAllowlist = compileAllowlist(rawAllowlist);
  return cachedAllowlist;
}

function isAllowlisted({
  currentDomain,
  referencedDomain,
  specifier,
  resolved,
  allowlist
}) {
  for (const entry of allowlist) {
    if (entry.fromDomain !== '*' && entry.fromDomain !== currentDomain) {
      continue;
    }
    if (entry.toDomain !== '*' && entry.toDomain !== referencedDomain) {
      continue;
    }
    if (entry.specifierRegex && !entry.specifierRegex.test(specifier)) {
      continue;
    }
    if (entry.resolvedPathRegex && !entry.resolvedPathRegex.test(resolved)) {
      continue;
    }
    return true;
  }
  return false;
}

function checkFile({ filePath, content, crossDomainAllowlist }) {
  const normalizedPath = toPosix(filePath);
  if (!normalizedPath.includes('/src/')) {
    return [];
  }
  const currentDomain = resolveDomain(normalizedPath);

  if (!currentDomain || !normalizedPath.includes('/src/domains/')) {
    return [];
  }

  const errors = [];
  const { specifiers, parseError } = collectImportSpecifiers(content, filePath);
  if (parseError) {
    errors.push(parseError);
    return errors;
  }
  const allowlist = Array.isArray(crossDomainAllowlist)
    ? compileAllowlist(crossDomainAllowlist)
    : loadCrossDomainAllowlist();

  for (const specifier of specifiers) {
    const resolved = resolveSpecifier(filePath, specifier);

    if (resolved.includes('/shared-kernel/')) {
      continue;
    }

    const referencedDomain = resolveDomain(resolved);
    if (referencedDomain && referencedDomain !== currentDomain) {
      if (
        isAllowlisted({
          currentDomain,
          referencedDomain,
          specifier,
          resolved,
          allowlist
        })
      ) {
        continue;
      }
      errors.push(
        `cross-domain import is not allowed (${currentDomain} -> ${referencedDomain}): ${specifier}`
      );
    }
  }

  return errors;
}

module.exports = {
  id: 'no-cross-domain-imports',
  checkFile,
  _internals: {
    compileAllowlist,
    loadCrossDomainAllowlist,
    isAllowlisted,
    resolveSpecifier,
    resolveDomain,
    toPosix
  }
};
