const test = require('node:test');
const assert = require('node:assert/strict');
const {
  ROUTE_DEFINITIONS,
  toRouteDefinitionsSnapshot,
  createRouteDefinitionMap,
  findRouteDefinition,
  findRouteDefinitionInMap,
  extractRoutePathParams,
  validateRoutePermissionDeclarations
} = require('../src/route-permissions');
const {
  listSupportedRoutePermissionCodes,
  listSupportedRoutePermissionScopes
} = require('../src/modules/auth/auth.service');
const { listExecutableRouteKeys } = require('../src/server');

test('tenant protected auth routes expose explicit permission declarations', () => {
  const tenantOptions = findRouteDefinition({
    method: 'GET',
    path: '/auth/tenant/options'
  });
  const tenantSelect = findRouteDefinition({
    method: 'POST',
    path: '/auth/tenant/select'
  });
  const tenantSwitch = findRouteDefinition({
    method: 'POST',
    path: '/auth/tenant/switch'
  });
  const memberAdminProbe = findRouteDefinition({
    method: 'GET',
    path: '/auth/tenant/member-admin/probe'
  });
  const memberAdminProvisionUser = findRouteDefinition({
    method: 'POST',
    path: '/auth/tenant/member-admin/provision-user'
  });

  assert.ok(tenantOptions);
  assert.equal(tenantOptions.access, 'protected');
  assert.equal(tenantOptions.scope, 'tenant');
  assert.equal(tenantOptions.permission_code, 'tenant.context.read');

  for (const route of [tenantSelect, tenantSwitch]) {
    assert.ok(route);
    assert.equal(route.access, 'protected');
    assert.equal(route.scope, 'tenant');
    assert.equal(typeof route.permission_code, 'string');
    assert.ok(route.permission_code.length > 0);
  }

  assert.ok(memberAdminProbe);
  assert.equal(memberAdminProbe.access, 'protected');
  assert.equal(memberAdminProbe.scope, 'tenant');
  assert.equal(memberAdminProbe.permission_code, 'tenant.member_admin.operate');

  assert.ok(memberAdminProvisionUser);
  assert.equal(memberAdminProvisionUser.access, 'protected');
  assert.equal(memberAdminProvisionUser.scope, 'tenant');
  assert.equal(memberAdminProvisionUser.permission_code, 'tenant.member_admin.operate');
});

test('tenant member governance routes expose explicit permission declarations', () => {
  const tenantMemberList = findRouteDefinition({
    method: 'GET',
    path: '/tenant/members'
  });
  const tenantMemberCreate = findRouteDefinition({
    method: 'POST',
    path: '/tenant/members'
  });
  const tenantMemberStatusUpdate = findRouteDefinition({
    method: 'PATCH',
    path: '/tenant/members/:membership_id/status'
  });
  const tenantMemberDetailRead = findRouteDefinition({
    method: 'GET',
    path: '/tenant/members/:membership_id'
  });
  const tenantMemberProfileUpdate = findRouteDefinition({
    method: 'PATCH',
    path: '/tenant/members/:membership_id/profile'
  });
  const tenantMemberRoleBindingsRead = findRouteDefinition({
    method: 'GET',
    path: '/tenant/members/:membership_id/roles'
  });
  const tenantMemberRoleBindingsUpdate = findRouteDefinition({
    method: 'PUT',
    path: '/tenant/members/:membership_id/roles'
  });

  assert.ok(tenantMemberList);
  assert.equal(tenantMemberList.access, 'protected');
  assert.equal(tenantMemberList.scope, 'tenant');
  assert.equal(tenantMemberList.permission_code, 'tenant.member_admin.view');

  assert.ok(tenantMemberCreate);
  assert.equal(tenantMemberCreate.access, 'protected');
  assert.equal(tenantMemberCreate.scope, 'tenant');
  assert.equal(tenantMemberCreate.permission_code, 'tenant.member_admin.operate');

  assert.ok(tenantMemberStatusUpdate);
  assert.equal(tenantMemberStatusUpdate.access, 'protected');
  assert.equal(tenantMemberStatusUpdate.scope, 'tenant');
  assert.equal(tenantMemberStatusUpdate.permission_code, 'tenant.member_admin.operate');

  assert.ok(tenantMemberDetailRead);
  assert.equal(tenantMemberDetailRead.access, 'protected');
  assert.equal(tenantMemberDetailRead.scope, 'tenant');
  assert.equal(tenantMemberDetailRead.permission_code, 'tenant.member_admin.view');

  assert.ok(tenantMemberProfileUpdate);
  assert.equal(tenantMemberProfileUpdate.access, 'protected');
  assert.equal(tenantMemberProfileUpdate.scope, 'tenant');
  assert.equal(tenantMemberProfileUpdate.permission_code, 'tenant.member_admin.operate');

  assert.ok(tenantMemberRoleBindingsRead);
  assert.equal(tenantMemberRoleBindingsRead.access, 'protected');
  assert.equal(tenantMemberRoleBindingsRead.scope, 'tenant');
  assert.equal(tenantMemberRoleBindingsRead.permission_code, 'tenant.member_admin.view');

  assert.ok(tenantMemberRoleBindingsUpdate);
  assert.equal(tenantMemberRoleBindingsUpdate.access, 'protected');
  assert.equal(tenantMemberRoleBindingsUpdate.scope, 'tenant');
  assert.equal(tenantMemberRoleBindingsUpdate.permission_code, 'tenant.member_admin.operate');
});

test('tenant role governance routes expose explicit permission declarations', () => {
  const tenantRoleList = findRouteDefinition({
    method: 'GET',
    path: '/tenant/roles'
  });
  const tenantRoleCreate = findRouteDefinition({
    method: 'POST',
    path: '/tenant/roles'
  });
  const tenantRoleUpdate = findRouteDefinition({
    method: 'PATCH',
    path: '/tenant/roles/demo-role'
  });
  const tenantRoleDelete = findRouteDefinition({
    method: 'DELETE',
    path: '/tenant/roles/demo-role'
  });
  const tenantRolePermissionRead = findRouteDefinition({
    method: 'GET',
    path: '/tenant/roles/demo-role/permissions'
  });
  const tenantRolePermissionUpdate = findRouteDefinition({
    method: 'PUT',
    path: '/tenant/roles/demo-role/permissions'
  });

  assert.ok(tenantRoleList);
  assert.equal(tenantRoleList.access, 'protected');
  assert.equal(tenantRoleList.scope, 'tenant');
  assert.equal(tenantRoleList.permission_code, 'tenant.member_admin.view');

  assert.ok(tenantRoleCreate);
  assert.equal(tenantRoleCreate.access, 'protected');
  assert.equal(tenantRoleCreate.scope, 'tenant');
  assert.equal(tenantRoleCreate.permission_code, 'tenant.member_admin.operate');

  assert.ok(tenantRoleUpdate);
  assert.equal(tenantRoleUpdate.access, 'protected');
  assert.equal(tenantRoleUpdate.scope, 'tenant');
  assert.equal(tenantRoleUpdate.permission_code, 'tenant.member_admin.operate');

  assert.ok(tenantRoleDelete);
  assert.equal(tenantRoleDelete.access, 'protected');
  assert.equal(tenantRoleDelete.scope, 'tenant');
  assert.equal(tenantRoleDelete.permission_code, 'tenant.member_admin.operate');

  assert.ok(tenantRolePermissionRead);
  assert.equal(tenantRolePermissionRead.access, 'protected');
  assert.equal(tenantRolePermissionRead.scope, 'tenant');
  assert.equal(tenantRolePermissionRead.permission_code, 'tenant.member_admin.view');

  assert.ok(tenantRolePermissionUpdate);
  assert.equal(tenantRolePermissionUpdate.access, 'protected');
  assert.equal(tenantRolePermissionUpdate.scope, 'tenant');
  assert.equal(tenantRolePermissionUpdate.permission_code, 'tenant.member_admin.operate');
});

test('platform protected auth route exposes explicit permission declaration', () => {
  const platformMemberAdminProbe = findRouteDefinition({
    method: 'GET',
    path: '/auth/platform/member-admin/probe'
  });
  const platformMemberAdminProvisionUser = findRouteDefinition({
    method: 'POST',
    path: '/auth/platform/member-admin/provision-user'
  });

  assert.ok(platformMemberAdminProbe);
  assert.equal(platformMemberAdminProbe.access, 'protected');
  assert.equal(platformMemberAdminProbe.scope, 'platform');
  assert.equal(platformMemberAdminProbe.permission_code, 'platform.member_admin.view');

  assert.ok(platformMemberAdminProvisionUser);
  assert.equal(platformMemberAdminProvisionUser.access, 'protected');
  assert.equal(platformMemberAdminProvisionUser.scope, 'platform');
  assert.equal(platformMemberAdminProvisionUser.permission_code, 'platform.member_admin.operate');
});

test('platform role-facts replace route exposes explicit permission declaration', () => {
  const replaceRoleFacts = findRouteDefinition({
    method: 'POST',
    path: '/auth/platform/role-facts/replace'
  });

  assert.ok(replaceRoleFacts);
  assert.equal(replaceRoleFacts.access, 'protected');
  assert.equal(replaceRoleFacts.scope, 'platform');
  assert.equal(replaceRoleFacts.permission_code, 'platform.member_admin.operate');
});

test('platform org create route exposes explicit permission declaration', () => {
  const createPlatformOrg = findRouteDefinition({
    method: 'POST',
    path: '/platform/orgs'
  });

  assert.ok(createPlatformOrg);
  assert.equal(createPlatformOrg.access, 'protected');
  assert.equal(createPlatformOrg.scope, 'platform');
  assert.equal(createPlatformOrg.permission_code, 'platform.member_admin.operate');
});

test('platform org status route exposes explicit permission declaration', () => {
  const updatePlatformOrgStatus = findRouteDefinition({
    method: 'POST',
    path: '/platform/orgs/status'
  });

  assert.ok(updatePlatformOrgStatus);
  assert.equal(updatePlatformOrgStatus.access, 'protected');
  assert.equal(updatePlatformOrgStatus.scope, 'platform');
  assert.equal(updatePlatformOrgStatus.permission_code, 'platform.member_admin.operate');
});

test('platform owner-transfer route exposes explicit permission declaration', () => {
  const transferPlatformOrgOwner = findRouteDefinition({
    method: 'POST',
    path: '/platform/orgs/owner-transfer'
  });

  assert.ok(transferPlatformOrgOwner);
  assert.equal(transferPlatformOrgOwner.access, 'protected');
  assert.equal(transferPlatformOrgOwner.scope, 'platform');
  assert.equal(transferPlatformOrgOwner.permission_code, 'platform.member_admin.operate');
});

test('platform user create route exposes explicit permission declaration', () => {
  const createPlatformUser = findRouteDefinition({
    method: 'POST',
    path: '/platform/users'
  });

  assert.ok(createPlatformUser);
  assert.equal(createPlatformUser.access, 'protected');
  assert.equal(createPlatformUser.scope, 'platform');
  assert.equal(createPlatformUser.permission_code, 'platform.member_admin.operate');
});

test('platform user status route exposes explicit permission declaration', () => {
  const updatePlatformUserStatus = findRouteDefinition({
    method: 'POST',
    path: '/platform/users/status'
  });

  assert.ok(updatePlatformUserStatus);
  assert.equal(updatePlatformUserStatus.access, 'protected');
  assert.equal(updatePlatformUserStatus.scope, 'platform');
  assert.equal(updatePlatformUserStatus.permission_code, 'platform.member_admin.operate');
});

test('platform role list route exposes explicit permission declaration', () => {
  const listPlatformRoles = findRouteDefinition({
    method: 'GET',
    path: '/platform/roles'
  });

  assert.ok(listPlatformRoles);
  assert.equal(listPlatformRoles.access, 'protected');
  assert.equal(listPlatformRoles.scope, 'platform');
  assert.equal(listPlatformRoles.permission_code, 'platform.member_admin.view');
});

test('platform role create route exposes explicit permission declaration', () => {
  const createPlatformRole = findRouteDefinition({
    method: 'POST',
    path: '/platform/roles'
  });

  assert.ok(createPlatformRole);
  assert.equal(createPlatformRole.access, 'protected');
  assert.equal(createPlatformRole.scope, 'platform');
  assert.equal(createPlatformRole.permission_code, 'platform.member_admin.operate');
});

test('platform role update route exposes explicit permission declaration', () => {
  const updatePlatformRole = findRouteDefinition({
    method: 'PATCH',
    path: '/platform/roles/demo-role'
  });

  assert.ok(updatePlatformRole);
  assert.equal(updatePlatformRole.access, 'protected');
  assert.equal(updatePlatformRole.scope, 'platform');
  assert.equal(updatePlatformRole.permission_code, 'platform.member_admin.operate');
});

test('platform role permissions read route exposes explicit permission declaration', () => {
  const readPlatformRolePermissions = findRouteDefinition({
    method: 'GET',
    path: '/platform/roles/demo-role/permissions'
  });

  assert.ok(readPlatformRolePermissions);
  assert.equal(readPlatformRolePermissions.access, 'protected');
  assert.equal(readPlatformRolePermissions.scope, 'platform');
  assert.equal(readPlatformRolePermissions.permission_code, 'platform.member_admin.view');
});

test('platform role permissions update route exposes explicit permission declaration', () => {
  const updatePlatformRolePermissions = findRouteDefinition({
    method: 'PUT',
    path: '/platform/roles/demo-role/permissions'
  });

  assert.ok(updatePlatformRolePermissions);
  assert.equal(updatePlatformRolePermissions.access, 'protected');
  assert.equal(updatePlatformRolePermissions.scope, 'platform');
  assert.equal(updatePlatformRolePermissions.permission_code, 'platform.member_admin.operate');
});

test('route parameter extraction decodes URL-encoded path values', () => {
  const params = extractRoutePathParams(
    '/platform/roles/:role_id',
    '/platform/roles/platform%2Eops_admin'
  );
  assert.deepEqual(params, {
    role_id: 'platform.ops_admin'
  });
});

test('route parameter extraction rejects malformed URL-encoded path values', () => {
  const params = extractRoutePathParams(
    '/platform/roles/:role_id',
    '/platform/roles/%E0%A4%A'
  );
  assert.equal(params, null);
});

test('route parameter extraction rejects URL-encoded slash path values', () => {
  const params = extractRoutePathParams(
    '/platform/roles/:role_id',
    '/platform/roles/platform%2Fops_admin'
  );
  assert.equal(params, null);
});

test('route parameter extraction rejects URL-encoded leading or trailing whitespace values', () => {
  const leadingWhitespace = extractRoutePathParams(
    '/platform/roles/:role_id',
    '/platform/roles/%20platform_ops_admin'
  );
  const trailingWhitespace = extractRoutePathParams(
    '/platform/roles/:role_id',
    '/platform/roles/platform_ops_admin%20'
  );

  assert.equal(leadingWhitespace, null);
  assert.equal(trailingWhitespace, null);
});

test('route parameter extraction rejects URL-encoded control character values', () => {
  const params = extractRoutePathParams(
    '/platform/roles/:role_id',
    '/platform/roles/platform%09ops_admin'
  );
  assert.equal(params, null);
});

test('parameterized route matching rejects paths with consecutive slashes', () => {
  const updatePlatformRole = findRouteDefinition({
    method: 'PATCH',
    path: '/platform/roles//demo-role'
  });
  const deletePlatformRole = findRouteDefinition({
    method: 'DELETE',
    path: '/platform/roles//demo-role'
  });

  assert.equal(updatePlatformRole, null);
  assert.equal(deletePlatformRole, null);
  assert.equal(
    extractRoutePathParams(
      '/platform/roles/:role_id',
      '/platform/roles//demo-role'
    ),
    null
  );
});

test('route lookup rejects static paths with trailing slash or consecutive slashes', () => {
  const listTrailingSlash = findRouteDefinition({
    method: 'GET',
    path: '/platform/roles/'
  });
  const listConsecutiveSlashes = findRouteDefinition({
    method: 'GET',
    path: '/platform/roles//'
  });

  assert.equal(listTrailingSlash, null);
  assert.equal(listConsecutiveSlashes, null);
});

test('platform role delete route exposes explicit permission declaration', () => {
  const deletePlatformRole = findRouteDefinition({
    method: 'DELETE',
    path: '/platform/roles/demo-role'
  });

  assert.ok(deletePlatformRole);
  assert.equal(deletePlatformRole.access, 'protected');
  assert.equal(deletePlatformRole.scope, 'platform');
  assert.equal(deletePlatformRole.permission_code, 'platform.member_admin.operate');
});

test('protected routes are fail-closed when declaration is missing', () => {
  const result = validateRoutePermissionDeclarations([
    {
      method: 'GET',
      path: '/health',
      access: 'public',
      permission_code: '',
      scope: 'public'
    },
    {
      method: 'GET',
      path: '/auth/protected-but-missing',
      access: 'protected',
      permission_code: '',
      scope: 'tenant'
    }
  ]);

  assert.equal(result.ok, false);
  assert.equal(result.missing.length, 1);
  assert.deepEqual(result.missing[0], {
    method: 'GET',
    path: '/auth/protected-but-missing'
  });
});

test('baseline route declarations contain no protected route with empty permission', () => {
  const result = validateRoutePermissionDeclarations(ROUTE_DEFINITIONS, {
    supportedPermissionCodes: listSupportedRoutePermissionCodes()
  });
  assert.equal(result.ok, true);
  assert.deepEqual(result.missing, []);
});

test('route permission check fails when declaration uses unknown permission code', () => {
  const result = validateRoutePermissionDeclarations(
    [
      {
        method: 'GET',
        path: '/auth/tenant/options',
        access: 'protected',
        permission_code: 'tenant.context.read',
        scope: 'tenant'
      },
      {
        method: 'GET',
        path: '/auth/tenant/member-admin/probe',
        access: 'protected',
        permission_code: 'tenant.member_admin.operat',
        scope: 'tenant'
      }
    ],
    {
      supportedPermissionCodes: listSupportedRoutePermissionCodes()
    }
  );

  assert.equal(result.ok, false);
  assert.deepEqual(result.unknown, [
    {
      method: 'GET',
      path: '/auth/tenant/member-admin/probe',
      permission_code: 'tenant.member_admin.operat'
    }
  ]);
});

test('route permission check fails when permission_code scope is incompatible', () => {
  const result = validateRoutePermissionDeclarations(
    [
      {
        method: 'GET',
        path: '/health',
        access: 'public',
        permission_code: '',
        scope: 'public'
      },
      {
        method: 'GET',
        path: '/auth/tenant/member-admin/probe',
        access: 'protected',
        permission_code: 'tenant.member_admin.operate',
        scope: 'session'
      }
    ],
    {
      supportedPermissionCodes: listSupportedRoutePermissionCodes(),
      supportedPermissionScopes: listSupportedRoutePermissionScopes()
    }
  );

  assert.equal(result.ok, false);
  assert.deepEqual(result.incompatible, [
    {
      method: 'GET',
      path: '/auth/tenant/member-admin/probe',
      permission_code: 'tenant.member_admin.operate',
      scope: 'session',
      allowed_scopes: ['tenant']
    }
  ]);
});

test('route permission check fails when duplicate method/path declarations exist', () => {
  const result = validateRoutePermissionDeclarations([
    {
      method: 'GET',
      path: '/auth/tenant/options',
      access: 'protected',
      permission_code: 'tenant.context.read',
      scope: 'tenant'
    },
    {
      method: 'GET',
      path: '/auth/tenant/options',
      access: 'public',
      permission_code: '',
      scope: 'public'
    }
  ]);

  assert.equal(result.ok, false);
  assert.deepEqual(result.duplicate, [
    {
      method: 'GET',
      path: '/auth/tenant/options'
    }
  ]);
});

test('route permission check fails when executable route has no declaration', () => {
  const result = validateRoutePermissionDeclarations(
    [
      {
        method: 'GET',
        path: '/health',
        access: 'public',
        permission_code: '',
        scope: 'public'
      }
    ],
    {
      executableRouteKeys: ['GET /health', 'GET /auth/undeclared']
    }
  );

  assert.equal(result.ok, false);
  assert.deepEqual(result.undeclared, [
    {
      method: 'GET',
      path: '/auth/undeclared'
    }
  ]);
});

test('route permission check fails when declaration access/scope enums are invalid', () => {
  const result = validateRoutePermissionDeclarations([
    {
      method: 'GET',
      path: '/auth/tenant/options',
      access: 'protectd',
      permission_code: 'tenant.context.read',
      scope: 'tenantish'
    }
  ]);

  assert.equal(result.ok, false);
  assert.deepEqual(result.invalid, [
    {
      method: 'GET',
      path: '/auth/tenant/options',
      field: 'access',
      value: 'protectd'
    },
    {
      method: 'GET',
      path: '/auth/tenant/options',
      field: 'scope',
      value: 'tenantish'
    }
  ]);
});

test('route permission check fails when public route carries protected declaration fields', () => {
  const result = validateRoutePermissionDeclarations([
    {
      method: 'GET',
      path: '/health',
      access: 'public',
      permission_code: 'tenant.context.read',
      scope: 'tenant'
    }
  ]);

  assert.equal(result.ok, false);
  assert.deepEqual(result.invalid, [
    {
      method: 'GET',
      path: '/health',
      field: 'scope',
      value: 'tenant'
    },
    {
      method: 'GET',
      path: '/health',
      field: 'permission_code',
      value: 'tenant.context.read'
    }
  ]);
});

test('route permission check fails when declaration has no executable route handler', () => {
  const result = validateRoutePermissionDeclarations(
    [
      {
        method: 'GET',
        path: '/health',
        access: 'public',
        permission_code: '',
        scope: 'public'
      },
      {
        method: 'GET',
        path: '/auth/declared-only',
        access: 'protected',
        permission_code: 'tenant.context.read',
        scope: 'tenant'
      }
    ],
    {
      executableRouteKeys: ['GET /health']
    }
  );

  assert.equal(result.ok, false);
  assert.deepEqual(result.unhandled, [
    {
      method: 'GET',
      path: '/auth/declared-only'
    }
  ]);
});

test('route permission check fails when protected route uses scope=public', () => {
  const result = validateRoutePermissionDeclarations([
    {
      method: 'GET',
      path: '/auth/tenant/options',
      access: 'protected',
      permission_code: 'tenant.context.read',
      scope: 'public'
    }
  ]);

  assert.equal(result.ok, false);
  assert.ok(result.invalid.length >= 1);
  const scopeInvalid = result.invalid.find(
    (item) => item.path === '/auth/tenant/options' && item.field === 'scope'
  );
  assert.ok(scopeInvalid, 'expected protected route with scope=public to be flagged');
  assert.equal(scopeInvalid.value, 'public');
});

test('route permission check fails when declaration has empty method or path', () => {
  const result = validateRoutePermissionDeclarations([
    {
      method: '',
      path: '',
      access: 'public',
      permission_code: '',
      scope: 'public'
    }
  ]);

  assert.equal(result.ok, false);
  const methodInvalid = result.invalid.find((item) => item.field === 'method');
  assert.ok(methodInvalid, 'expected empty method to be flagged');
  assert.equal(methodInvalid.value, '(empty)');
  const pathInvalid = result.invalid.find((item) => item.field === 'path');
  assert.ok(pathInvalid, 'expected empty path to be flagged');
  assert.equal(pathInvalid.value, '(empty)');
});

test('route permission check fails when declaration path does not start with /', () => {
  const result = validateRoutePermissionDeclarations([
    {
      method: 'GET',
      path: 'health',
      access: 'public',
      permission_code: '',
      scope: 'public'
    }
  ]);

  assert.equal(result.ok, false);
  const pathInvalid = result.invalid.find((item) => item.field === 'path');
  assert.ok(pathInvalid, 'expected path without leading / to be flagged');
  assert.equal(pathInvalid.value, 'health');
});

test('route permission check fails when declaration path has leading or trailing whitespace', () => {
  const result = validateRoutePermissionDeclarations([
    {
      method: 'GET',
      path: ' /health',
      access: 'public',
      permission_code: '',
      scope: 'public'
    },
    {
      method: 'GET',
      path: '/openapi.json ',
      access: 'public',
      permission_code: '',
      scope: 'public'
    }
  ]);

  assert.equal(result.ok, false);
  const leadingSpaceInvalid = result.invalid.find(
    (item) => item.field === 'path' && item.value === ' /health'
  );
  const trailingSpaceInvalid = result.invalid.find(
    (item) => item.field === 'path' && item.value === '/openapi.json '
  );
  assert.ok(leadingSpaceInvalid, 'expected leading whitespace path to be flagged');
  assert.ok(trailingSpaceInvalid, 'expected trailing whitespace path to be flagged');
});

test('route permission check fails when declaration path contains inline whitespace', () => {
  const result = validateRoutePermissionDeclarations([
    {
      method: 'GET',
      path: '/auth bad',
      access: 'public',
      permission_code: '',
      scope: 'public'
    },
    {
      method: 'GET',
      path: '/auth\tbad',
      access: 'public',
      permission_code: '',
      scope: 'public'
    }
  ]);

  assert.equal(result.ok, false);
  const inlineSpaceInvalid = result.invalid.find(
    (item) => item.field === 'path' && item.value === '/auth bad'
  );
  const inlineTabInvalid = result.invalid.find(
    (item) => item.field === 'path' && item.value === '/auth\tbad'
  );
  assert.ok(inlineSpaceInvalid, 'expected inline whitespace path to be flagged');
  assert.ok(inlineTabInvalid, 'expected inline tab path to be flagged');
});

test('route permission check fails when declaration path contains query or hash fragments', () => {
  const result = validateRoutePermissionDeclarations([
    {
      method: 'GET',
      path: '/health?x=1',
      access: 'public',
      permission_code: '',
      scope: 'public'
    },
    {
      method: 'GET',
      path: '/openapi.json#v1',
      access: 'public',
      permission_code: '',
      scope: 'public'
    }
  ]);

  assert.equal(result.ok, false);
  const queryInvalid = result.invalid.find(
    (item) => item.field === 'path' && item.value === '/health?x=1'
  );
  const hashInvalid = result.invalid.find(
    (item) => item.field === 'path' && item.value === '/openapi.json#v1'
  );
  assert.ok(queryInvalid, 'expected query fragment path to be flagged');
  assert.ok(hashInvalid, 'expected hash fragment path to be flagged');
});

test('route permission check fails when declaration uses non-standard HTTP method', () => {
  const result = validateRoutePermissionDeclarations([
    {
      method: 'FETCH',
      path: '/health',
      access: 'public',
      permission_code: '',
      scope: 'public'
    }
  ]);

  assert.equal(result.ok, false);
  const methodInvalid = result.invalid.find((item) => item.field === 'method');
  assert.ok(methodInvalid, 'expected non-standard method to be flagged');
  assert.equal(methodInvalid.value, 'FETCH');
});

test('route permission check fails when declaration uses HEAD method', () => {
  const result = validateRoutePermissionDeclarations([
    {
      method: 'HEAD',
      path: '/health',
      access: 'public',
      permission_code: '',
      scope: 'public'
    }
  ]);

  assert.equal(result.ok, false);
  const methodInvalid = result.invalid.find((item) => item.field === 'method');
  assert.ok(methodInvalid, 'expected HEAD method declaration to be flagged');
  assert.equal(methodInvalid.value, 'HEAD');
});

test('route permission check fails when declaration uses OPTIONS method', () => {
  const result = validateRoutePermissionDeclarations([
    {
      method: 'OPTIONS',
      path: '/auth/login',
      access: 'public',
      permission_code: '',
      scope: 'public'
    }
  ]);

  assert.equal(result.ok, false);
  const methodInvalid = result.invalid.find((item) => item.field === 'method');
  assert.ok(methodInvalid, 'expected OPTIONS method declaration to be flagged');
  assert.equal(methodInvalid.value, 'OPTIONS');
});

test('baseline route declarations are fully aligned with executable route table', () => {
  const result = validateRoutePermissionDeclarations(ROUTE_DEFINITIONS, {
    executableRouteKeys: listExecutableRouteKeys(),
    supportedPermissionCodes: listSupportedRoutePermissionCodes(),
    supportedPermissionScopes: listSupportedRoutePermissionScopes()
  });

  assert.equal(result.ok, true);
  assert.deepEqual(result.missing, []);
  assert.deepEqual(result.invalid, []);
  assert.deepEqual(result.unknown, []);
  assert.deepEqual(result.incompatible, []);
  assert.deepEqual(result.duplicate, []);
  assert.deepEqual(result.undeclared, []);
  assert.deepEqual(result.unhandled, []);
});

test('runtime mutation cannot downgrade baseline protected route declaration', () => {
  const declaration = ROUTE_DEFINITIONS.find(
    (route) => route.path === '/auth/tenant/member-admin/probe' && route.method === 'GET'
  );
  assert.ok(declaration);

  const previousAccess = declaration.access;
  const mutated = Reflect.set(declaration, 'access', 'public');

  assert.equal(mutated, false);
  assert.equal(
    findRouteDefinition({
      method: 'GET',
      path: '/auth/tenant/member-admin/probe'
    }).access,
    previousAccess
  );
});

test('route definition map keeps immutable declaration snapshot', () => {
  const customRouteDefinitions = [
    {
      method: 'GET',
      path: '/health',
      access: 'protected',
      permission_code: 'auth.session.logout',
      scope: 'session'
    }
  ];
  const routeDefinitionMap = createRouteDefinitionMap(customRouteDefinitions);

  customRouteDefinitions[0].access = 'public';
  customRouteDefinitions[0].scope = 'public';
  customRouteDefinitions[0].permission_code = '';

  assert.deepEqual(
    findRouteDefinitionInMap(routeDefinitionMap, {
      method: 'GET',
      path: '/health'
    }),
    {
      method: 'GET',
      path: '/health',
      access: 'protected',
      permission_code: 'auth.session.logout',
      scope: 'session'
    }
  );
});

test('toRouteDefinitionsSnapshot refreshes mutable route declaration snapshots when content changes', () => {
  const mutableRouteDefinitions = [
    {
      method: 'GET',
      path: '/health',
      access: 'public',
      permission_code: '',
      scope: 'public'
    }
  ];

  const firstSnapshot = toRouteDefinitionsSnapshot(mutableRouteDefinitions);
  mutableRouteDefinitions[0].access = 'protected';
  mutableRouteDefinitions[0].permission_code = 'auth.session.logout';
  mutableRouteDefinitions[0].scope = 'session';
  const secondSnapshot = toRouteDefinitionsSnapshot(mutableRouteDefinitions);

  assert.notEqual(
    secondSnapshot,
    firstSnapshot,
    'mutable route definitions should produce a fresh snapshot when declaration content changes'
  );
  assert.equal(firstSnapshot[0].access, 'public');
  assert.equal(secondSnapshot[0].access, 'protected');
  assert.equal(secondSnapshot[0].permission_code, 'auth.session.logout');
  assert.equal(secondSnapshot[0].scope, 'session');
});
