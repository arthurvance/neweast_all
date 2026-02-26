#!/usr/bin/env node

const {
  validateRoutePermissionDeclarations
} = require('../src/route-permissions');
const { listExecutableRouteKeys } = require('../src/server');
const {
  listSupportedRoutePermissionCodes,
  listSupportedRoutePermissionScopes
} = require('../src/shared-kernel/auth/create-auth-service');

const result = validateRoutePermissionDeclarations(undefined, {
  executableRouteKeys: listExecutableRouteKeys(),
  supportedPermissionCodes: listSupportedRoutePermissionCodes(),
  supportedPermissionScopes: listSupportedRoutePermissionScopes()
});
if (!result.ok) {
  const details = [];
  if (result.missing.length > 0) {
    details.push(
      `Missing protected declarations:\n${result.missing
        .map((item) => `${item.method} ${item.path}`)
        .join('\n')}`
    );
  }
  if (result.invalid.length > 0) {
    details.push(
      `Invalid declaration fields:\n${result.invalid
        .map((item) => `${item.method} ${item.path} (${item.field}=${item.value || '(empty)'})`)
        .join('\n')}`
    );
  }
  if (result.unknown.length > 0) {
    details.push(
      `Unknown permission codes:\n${result.unknown
        .map((item) => `${item.method} ${item.path} (permission_code=${item.permission_code})`)
        .join('\n')}`
    );
  }
  if (result.incompatible.length > 0) {
    details.push(
      `Incompatible permission scopes:\n${result.incompatible
        .map(
          (item) =>
            `${item.method} ${item.path} (permission_code=${item.permission_code}, scope=${item.scope}, allowed_scopes=${item.allowed_scopes.join('|')})`
        )
        .join('\n')}`
    );
  }
  if (result.duplicate.length > 0) {
    details.push(
      `Duplicate route declarations:\n${result.duplicate
        .map((item) => `${item.method} ${item.path}`)
        .join('\n')}`
    );
  }
  if (result.undeclared.length > 0) {
    details.push(
      `Executable routes missing declarations:\n${result.undeclared
        .map((item) => `${item.method} ${item.path}`)
        .join('\n')}`
    );
  }
  if (result.unhandled.length > 0) {
    details.push(
      `Declared routes missing executable handlers:\n${result.unhandled
        .map((item) => `${item.method} ${item.path}`)
        .join('\n')}`
    );
  }
  process.stderr.write(`Route permission declaration check failed.\n${details.join('\n\n')}\n`);
  process.exit(1);
}

process.stdout.write('Route permission declaration check passed.\n');
