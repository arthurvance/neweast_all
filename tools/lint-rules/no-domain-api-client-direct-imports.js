'use strict';

const {
  collectImportSpecifiers,
  resolveSpecifier,
  toPosix
} = require('./ast-import-utils');

const WEB_API_CLIENT_RE =
  /\/apps\/web\/src\/api\/(platform-management|tenant-management)\.mjs$/;

function checkFile({ filePath, content }) {
  const normalizedPath = toPosix(filePath);
  if (!normalizedPath.includes('/apps/web/src/')) {
    return [];
  }

  if (normalizedPath.includes('/apps/web/src/domains/')) {
    return [];
  }

  const errors = [];
  const { specifiers, parseError } = collectImportSpecifiers(content, filePath);
  if (parseError) {
    errors.push(parseError);
    return errors;
  }

  for (const specifier of specifiers) {
    const resolved = toPosix(resolveSpecifier(filePath, specifier));
    const match = resolved.match(WEB_API_CLIENT_RE);
    if (!match) {
      continue;
    }
    const domain = match[1] === 'platform-management' ? 'platform' : 'tenant';
    errors.push(
      `direct api client import is blocked. Use domains/${domain}/index.mjs public API instead: ${specifier}`
    );
  }

  return errors;
}

module.exports = {
  id: 'no-domain-api-client-direct-imports',
  checkFile,
  _internals: {
    WEB_API_CLIENT_RE,
    resolveSpecifier,
    toPosix
  }
};
