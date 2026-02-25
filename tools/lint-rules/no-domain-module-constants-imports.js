'use strict';

const {
  collectImportSpecifiers,
  resolveSpecifier,
  toPosix
} = require('./ast-import-utils');

const MODULE_CONSTANTS_IMPORT_RE =
  /\/src\/modules\/(platform|tenant)\/[^/]+\.constants(?:\.(?:[mc]?js|tsx?|jsx))?$/;

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
    const match = toPosix(resolved).match(MODULE_CONSTANTS_IMPORT_RE);
    if (!match) {
      continue;
    }

    const domain = match[1];
    errors.push(
      `import from modules/${domain}/*.constants is blocked. Use domains/${domain} public API instead: ${specifier}`
    );
  }

  return errors;
}

module.exports = {
  id: 'no-domain-module-constants-imports',
  checkFile,
  _internals: {
    MODULE_CONSTANTS_IMPORT_RE,
    resolveSpecifier,
    toPosix
  }
};
