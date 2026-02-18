const test = require('node:test');
const assert = require('node:assert/strict');
const { createRouteHandlers } = require('../src/http-routes');
const { createPlatformOrgService } = require('../src/modules/platform/org.service');
const { AuthProblemError } = require('../src/modules/auth/auth.routes');
const { readConfig } = require('../src/config/env');
const {
  createServer,
  handleApiRoute,
  dispatchApiRoute,
  resolveRouteDeclarationLookup
} = require('../src/server');
const { ROUTE_DEFINITIONS } = require('../src/route-permissions');
const {
  markRoutePreauthorizedContext
} = require('../src/modules/auth/route-preauthorization');

const config = readConfig({ ALLOW_MOCK_BACKENDS: 'false' });
const dependencyProbe = async () => ({
  db: { ok: true },
  redis: { ok: true }
});
const UUID_PATTERN =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const cloneRouteDefinitions = (routeDefinitions = []) =>
  routeDefinitions.map((routeDefinition) => ({
    ...routeDefinition
  }));

const listProblemExamplesMissingRetryable = (openapiPayload = {}) => {
  const missing = [];
  for (const [path, pathItem] of Object.entries(openapiPayload.paths || {})) {
    for (const [method, operation] of Object.entries(pathItem || {})) {
      for (const [statusCode, response] of Object.entries(operation?.responses || {})) {
        const examples = response?.content?.['application/problem+json']?.examples;
        if (!examples || typeof examples !== 'object') {
          continue;
        }
        for (const [exampleName, example] of Object.entries(examples)) {
          const value = example?.value;
          if (!value || typeof value !== 'object' || Array.isArray(value)) {
            continue;
          }
          if (
            Object.prototype.hasOwnProperty.call(value, 'error_code')
            && typeof value.retryable !== 'boolean'
          ) {
            missing.push(`${method.toUpperCase()} ${path} ${statusCode}#${exampleName}`);
          }
        }
      }
    }
  }
  return missing;
};

const startServer = async (overrides = {}, serverOptions = {}) => {
  const server = createServer(readConfig(overrides), {
    dependencyProbe,
    ...serverOptions
  });
  await new Promise((resolve, reject) => {
    server.listen(0, '127.0.0.1', (error) => {
      if (error) {
        reject(error);
        return;
      }
      resolve();
    });
  });
  const address = server.address();
  const port = typeof address === 'object' && address ? address.port : 0;
  return {
    baseUrl: `http://127.0.0.1:${port}`,
    close: async () => {
      await new Promise((resolve, reject) => {
        server.close((error) => {
          if (error) {
            reject(error);
            return;
          }
          resolve();
        });
      });
    }
  };
};

test('openapi endpoint is exposed with auth placeholder', () => {
  const handlers = createRouteHandlers(config, {
    dependencyProbe
  });

  const payload = handlers.openapi('openapi-test');
  assert.equal(payload.openapi, '3.1.0');
  assert.ok(payload.paths['/auth/ping']);
  assert.ok(payload.paths['/health']);
  assert.ok(payload.paths['/auth/otp/send']);
  assert.ok(payload.paths['/auth/otp/login']);
  assert.ok(payload.paths['/auth/tenant/member-admin/probe']);
  assert.ok(payload.paths['/auth/platform/member-admin/probe']);
  assert.ok(payload.paths['/auth/tenant/member-admin/provision-user']);
  assert.ok(payload.paths['/auth/platform/member-admin/provision-user']);
  assert.ok(payload.paths['/auth/platform/role-facts/replace']);
  assert.ok(payload.paths['/platform/roles']);
  assert.ok(payload.paths['/platform/roles/{role_id}']);
  assert.ok(payload.paths['/platform/roles/{role_id}/permissions']);
  assert.ok(payload.paths['/platform/orgs']);
  assert.ok(payload.paths['/platform/orgs/status']);
  assert.ok(payload.paths['/platform/orgs/owner-transfer']);
  assert.ok(payload.paths['/platform/users']);
  assert.ok(payload.paths['/platform/users/status']);
  assert.ok(payload.paths['/smoke']);
  assert.equal(
    payload.components.schemas.CreatePlatformRoleRequest.properties.role_id.pattern,
    '^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$'
  );
  assert.equal(
    payload.paths['/platform/roles/{role_id}'].patch.parameters.find(
      (parameter) => parameter.in === 'path' && parameter.name === 'role_id'
    ).schema.pattern,
    '^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$'
  );
  assert.equal(
    payload.paths['/platform/roles/{role_id}'].delete.parameters.find(
      (parameter) => parameter.in === 'path' && parameter.name === 'role_id'
    ).schema.pattern,
    '^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$'
  );
  assert.equal(
    payload.paths['/health'].get.responses['200'].content['application/json'].schema.properties
      .dependencies.properties.db.properties.mode.type,
    'string'
  );
  assert.equal(
    payload.paths['/health'].get.responses['503'].content['application/json'].schema.properties
      .dependencies.properties.redis.properties.detail.type,
    'string'
  );
  assert.equal(
    payload.paths['/smoke'].get.responses['200'].content['application/json'].schema.properties
      .dependencies.properties.db.properties.ok.type,
    'boolean'
  );
  assert.equal(
    payload.paths['/smoke'].get.responses['503'].content['application/json'].schema.properties
      .dependencies.properties.redis.properties.mode.type,
    'string'
  );
  assert.ok(
    payload.paths['/auth/tenant/member-admin/provision-user'].post.parameters.some(
      (parameter) => parameter.in === 'header' && parameter.name === 'Idempotency-Key'
    )
  );
  assert.ok(
    payload.paths['/auth/platform/member-admin/provision-user'].post.parameters.some(
      (parameter) => parameter.in === 'header' && parameter.name === 'Idempotency-Key'
    )
  );
  assert.ok(
    payload.paths['/auth/platform/role-facts/replace'].post.parameters.some(
      (parameter) => parameter.in === 'header' && parameter.name === 'Idempotency-Key'
    )
  );
  assert.ok(
    payload.paths['/platform/roles'].post.parameters.some(
      (parameter) => parameter.in === 'header' && parameter.name === 'Idempotency-Key'
    )
  );
  assert.ok(
    payload.paths['/platform/roles/{role_id}'].patch.parameters.some(
      (parameter) => parameter.in === 'header' && parameter.name === 'Idempotency-Key'
    )
  );
  assert.ok(
    payload.paths['/platform/roles/{role_id}'].delete.parameters.some(
      (parameter) => parameter.in === 'header' && parameter.name === 'Idempotency-Key'
    )
  );
  assert.ok(
    payload.paths['/platform/roles/{role_id}/permissions'].put.parameters.some(
      (parameter) => parameter.in === 'header' && parameter.name === 'Idempotency-Key'
    )
  );
  assert.ok(
    payload.paths['/platform/orgs'].post.parameters.some(
      (parameter) => parameter.in === 'header' && parameter.name === 'Idempotency-Key'
    )
  );
  assert.ok(
    payload.paths['/platform/orgs/status'].post.parameters.some(
      (parameter) => parameter.in === 'header' && parameter.name === 'Idempotency-Key'
    )
  );
  assert.ok(
    payload.paths['/platform/orgs/owner-transfer'].post.parameters.some(
      (parameter) => parameter.in === 'header' && parameter.name === 'Idempotency-Key'
    )
  );
  assert.ok(
    payload.paths['/platform/users'].post.parameters.some(
      (parameter) => parameter.in === 'header' && parameter.name === 'Idempotency-Key'
    )
  );
  assert.ok(
    payload.paths['/platform/users/status'].post.parameters.some(
      (parameter) => parameter.in === 'header' && parameter.name === 'Idempotency-Key'
    )
  );
  assert.equal(
    payload.paths['/auth/tenant/member-admin/provision-user'].post.parameters.find(
      (parameter) => parameter.in === 'header' && parameter.name === 'Idempotency-Key'
    ).schema.pattern,
    '^(?=.*\\S)[^,]{1,128}$'
  );
  assert.equal(
    payload.paths['/auth/platform/member-admin/provision-user'].post.parameters.find(
      (parameter) => parameter.in === 'header' && parameter.name === 'Idempotency-Key'
    ).schema.pattern,
    '^(?=.*\\S)[^,]{1,128}$'
  );
  assert.equal(
    payload.paths['/auth/platform/role-facts/replace'].post.parameters.find(
      (parameter) => parameter.in === 'header' && parameter.name === 'Idempotency-Key'
    ).schema.pattern,
    '^(?=.*\\S)[^,]{1,128}$'
  );
  assert.equal(
    payload.paths['/platform/roles'].post.parameters.find(
      (parameter) => parameter.in === 'header' && parameter.name === 'Idempotency-Key'
    ).schema.pattern,
    '^(?=.*\\S)[^,]{1,128}$'
  );
  assert.equal(
    payload.paths['/platform/roles/{role_id}'].patch.parameters.find(
      (parameter) => parameter.in === 'header' && parameter.name === 'Idempotency-Key'
    ).schema.pattern,
    '^(?=.*\\S)[^,]{1,128}$'
  );
  assert.equal(
    payload.paths['/platform/roles/{role_id}'].delete.parameters.find(
      (parameter) => parameter.in === 'header' && parameter.name === 'Idempotency-Key'
    ).schema.pattern,
    '^(?=.*\\S)[^,]{1,128}$'
  );
  assert.equal(
    payload.paths['/platform/roles/{role_id}/permissions'].put.parameters.find(
      (parameter) => parameter.in === 'header' && parameter.name === 'Idempotency-Key'
    ).schema.pattern,
    '^(?=.*\\S)[^,]{1,128}$'
  );
  assert.equal(
    payload.paths['/platform/orgs'].post.parameters.find(
      (parameter) => parameter.in === 'header' && parameter.name === 'Idempotency-Key'
    ).schema.pattern,
    '^(?=.*\\S)[^,]{1,128}$'
  );
  assert.equal(
    payload.paths['/platform/orgs/status'].post.parameters.find(
      (parameter) => parameter.in === 'header' && parameter.name === 'Idempotency-Key'
    ).schema.pattern,
    '^(?=.*\\S)[^,]{1,128}$'
  );
  assert.equal(
    payload.paths['/platform/orgs/owner-transfer'].post.parameters.find(
      (parameter) => parameter.in === 'header' && parameter.name === 'Idempotency-Key'
    ).schema.pattern,
    '^(?=.*\\S)[^,]{1,128}$'
  );
  assert.equal(
    payload.paths['/platform/users'].post.parameters.find(
      (parameter) => parameter.in === 'header' && parameter.name === 'Idempotency-Key'
    ).schema.pattern,
    '^(?=.*\\S)[^,]{1,128}$'
  );
  assert.equal(
    payload.paths['/platform/users/status'].post.parameters.find(
      (parameter) => parameter.in === 'header' && parameter.name === 'Idempotency-Key'
    ).schema.pattern,
    '^(?=.*\\S)[^,]{1,128}$'
  );
  assert.equal(
    payload.paths['/platform/roles'].post.parameters.find(
      (parameter) => parameter.in === 'header' && parameter.name === 'Idempotency-Key'
    ).description,
    '关键写幂等键；同键同载荷返回首次持久化语义，参数校验失败等非持久响应不会占用该键'
  );
  assert.equal(
    payload.paths['/platform/roles/{role_id}'].patch.parameters.find(
      (parameter) => parameter.in === 'header' && parameter.name === 'Idempotency-Key'
    ).description,
    '关键写幂等键；同键同载荷返回首次持久化语义，参数校验失败等非持久响应不会占用该键'
  );
  assert.equal(
    payload.paths['/platform/roles/{role_id}'].delete.parameters.find(
      (parameter) => parameter.in === 'header' && parameter.name === 'Idempotency-Key'
    ).description,
    '关键写幂等键；同键同载荷返回首次持久化语义，参数校验失败等非持久响应不会占用该键'
  );
  assert.equal(
    payload.paths['/platform/roles/{role_id}/permissions'].put.parameters.find(
      (parameter) => parameter.in === 'header' && parameter.name === 'Idempotency-Key'
    ).description,
    '关键写幂等键；同键同载荷返回首次持久化语义，参数校验失败等非持久响应不会占用该键'
  );
  assert.equal(
    payload.paths['/platform/orgs'].post.parameters.find(
      (parameter) => parameter.in === 'header' && parameter.name === 'Idempotency-Key'
    ).description,
    '关键写幂等键；同键同载荷返回首次持久化语义，参数校验失败等非持久响应不会占用该键'
  );
  assert.equal(
    payload.paths['/platform/orgs/status'].post.parameters.find(
      (parameter) => parameter.in === 'header' && parameter.name === 'Idempotency-Key'
    ).description,
    '关键写幂等键；同键同载荷返回首次持久化语义，参数校验失败等非持久响应不会占用该键'
  );
  assert.equal(
    payload.paths['/platform/orgs/owner-transfer'].post.parameters.find(
      (parameter) => parameter.in === 'header' && parameter.name === 'Idempotency-Key'
    ).description,
    '关键写幂等键；同键同载荷返回首次持久化语义，参数校验失败等非持久响应不会占用该键'
  );
  assert.equal(
    payload.paths['/platform/users'].post.parameters.find(
      (parameter) => parameter.in === 'header' && parameter.name === 'Idempotency-Key'
    ).description,
    '关键写幂等键；同键同载荷返回首次持久化语义，参数校验失败等非持久响应不会占用该键'
  );
  assert.equal(
    payload.paths['/platform/users/status'].post.parameters.find(
      (parameter) => parameter.in === 'header' && parameter.name === 'Idempotency-Key'
    ).description,
    '关键写幂等键；同键同载荷返回首次持久化语义，参数校验失败等非持久响应不会占用该键'
  );
  assert.ok(payload.paths['/auth/login'].post.responses['400']);
  assert.ok(payload.paths['/auth/login'].post.responses['413']);
  assert.ok(payload.paths['/auth/login'].post.responses['429']);
  assert.ok(payload.paths['/auth/otp/send'].post.responses['413']);
  assert.ok(payload.paths['/auth/otp/login'].post.responses['413']);
  assert.ok(payload.paths['/auth/refresh'].post.responses['400']);
  assert.ok(payload.paths['/auth/refresh'].post.responses['413']);
  assert.ok(payload.paths['/auth/change-password'].post.responses['413']);
  assert.ok(payload.paths['/auth/platform/role-facts/replace'].post.responses['400']);
  assert.ok(payload.paths['/auth/platform/role-facts/replace'].post.responses['413']);
  assert.ok(payload.paths['/auth/platform/role-facts/replace'].post.responses['503']);
  assert.ok(payload.paths['/auth/tenant/member-admin/provision-user'].post.responses['413']);
  assert.ok(payload.paths['/auth/tenant/member-admin/provision-user'].post.responses['409']);
  assert.ok(payload.paths['/auth/tenant/member-admin/provision-user'].post.responses['503']);
  assert.ok(payload.paths['/auth/platform/member-admin/provision-user'].post.responses['413']);
  assert.ok(payload.paths['/auth/platform/member-admin/provision-user'].post.responses['409']);
  assert.ok(payload.paths['/auth/platform/member-admin/provision-user'].post.responses['503']);
  assert.ok(payload.paths['/platform/roles'].post.responses['400']);
  assert.ok(payload.paths['/platform/roles'].post.responses['401']);
  assert.ok(payload.paths['/platform/roles'].post.responses['403']);
  assert.ok(payload.paths['/platform/roles'].post.responses['409']);
  assert.ok(payload.paths['/platform/roles'].post.responses['503']);
  assert.ok(payload.paths['/platform/roles/{role_id}'].patch.responses['400']);
  assert.ok(payload.paths['/platform/roles/{role_id}'].patch.responses['401']);
  assert.ok(payload.paths['/platform/roles/{role_id}'].patch.responses['403']);
  assert.ok(payload.paths['/platform/roles/{role_id}'].patch.responses['404']);
  assert.ok(payload.paths['/platform/roles/{role_id}'].patch.responses['409']);
  assert.ok(payload.paths['/platform/roles/{role_id}'].patch.responses['503']);
  assert.ok(payload.paths['/platform/roles/{role_id}'].delete.responses['400']);
  assert.ok(payload.paths['/platform/roles/{role_id}'].delete.responses['401']);
  assert.ok(payload.paths['/platform/roles/{role_id}'].delete.responses['403']);
  assert.ok(payload.paths['/platform/roles/{role_id}'].delete.responses['404']);
  assert.ok(payload.paths['/platform/roles/{role_id}'].delete.responses['413']);
  assert.ok(payload.paths['/platform/roles/{role_id}'].delete.responses['503']);
  assert.ok(payload.paths['/platform/roles/{role_id}/permissions'].get.responses['400']);
  assert.ok(payload.paths['/platform/roles/{role_id}/permissions'].get.responses['401']);
  assert.ok(payload.paths['/platform/roles/{role_id}/permissions'].get.responses['403']);
  assert.ok(payload.paths['/platform/roles/{role_id}/permissions'].get.responses['404']);
  assert.ok(payload.paths['/platform/roles/{role_id}/permissions'].get.responses['503']);
  assert.ok(payload.paths['/platform/roles/{role_id}/permissions'].put.responses['400']);
  assert.ok(payload.paths['/platform/roles/{role_id}/permissions'].put.responses['401']);
  assert.ok(payload.paths['/platform/roles/{role_id}/permissions'].put.responses['403']);
  assert.ok(payload.paths['/platform/roles/{role_id}/permissions'].put.responses['404']);
  assert.ok(payload.paths['/platform/roles/{role_id}/permissions'].put.responses['409']);
  assert.ok(payload.paths['/platform/roles/{role_id}/permissions'].put.responses['413']);
  assert.ok(payload.paths['/platform/roles/{role_id}/permissions'].put.responses['503']);
  assert.ok(payload.paths['/platform/orgs'].post.responses['400']);
  assert.ok(payload.paths['/platform/orgs'].post.responses['413']);
  assert.ok(payload.paths['/platform/orgs'].post.responses['403']);
  assert.ok(payload.paths['/platform/orgs'].post.responses['409']);
  assert.ok(payload.paths['/platform/orgs'].post.responses['503']);
  assert.ok(payload.paths['/platform/orgs/status'].post.responses['400']);
  assert.ok(payload.paths['/platform/orgs/status'].post.responses['404']);
  assert.ok(payload.paths['/platform/orgs/status'].post.responses['409']);
  assert.ok(payload.paths['/platform/orgs/status'].post.responses['503']);
  assert.ok(payload.paths['/platform/orgs/owner-transfer'].post.responses['400']);
  assert.ok(payload.paths['/platform/orgs/owner-transfer'].post.responses['401']);
  assert.ok(payload.paths['/platform/orgs/owner-transfer'].post.responses['403']);
  assert.ok(payload.paths['/platform/orgs/owner-transfer'].post.responses['404']);
  assert.ok(payload.paths['/platform/orgs/owner-transfer'].post.responses['409']);
  assert.ok(payload.paths['/platform/orgs/owner-transfer'].post.responses['413']);
  assert.ok(payload.paths['/platform/orgs/owner-transfer'].post.responses['503']);
  assert.ok(payload.paths['/platform/users'].post.responses['400']);
  assert.ok(payload.paths['/platform/users'].post.responses['401']);
  assert.ok(payload.paths['/platform/users'].post.responses['403']);
  assert.ok(payload.paths['/platform/users'].post.responses['409']);
  assert.ok(payload.paths['/platform/users'].post.responses['503']);
  assert.ok(payload.paths['/platform/users/status'].post.responses['400']);
  assert.ok(payload.paths['/platform/users/status'].post.responses['401']);
  assert.ok(payload.paths['/platform/users/status'].post.responses['403']);
  assert.ok(payload.paths['/platform/users/status'].post.responses['404']);
  assert.ok(payload.paths['/platform/users/status'].post.responses['409']);
  assert.ok(payload.paths['/platform/users/status'].post.responses['503']);
  assert.equal(
    payload.paths['/platform/orgs/status'].post.summary,
    'Update organization status (active|disabled, tenant-domain scoped)'
  );
  assert.equal(
    payload.paths['/platform/orgs/status'].post.description,
    '组织状态治理仅影响 tenant 域访问可用性；平台域（platform）访问不因该接口直接改变。'
  );
  assert.equal(
    payload.paths['/platform/orgs/status'].post.responses['200'].description,
    'Organization status updated (or no-op). Only tenant-domain access is affected.'
  );
  assert.equal(
    payload.paths['/platform/orgs/owner-transfer'].post.summary,
    'Submit organization owner-transfer request (entry + precheck only)'
  );
  assert.equal(
    payload.paths['/platform/orgs/owner-transfer'].post.description,
    '仅交付发起入口与前置校验，不在本接口执行 owner 真正切换与自动接管。'
  );
  assert.equal(
    payload.paths['/platform/orgs/owner-transfer'].post.responses['200'].description,
    'Owner-transfer request accepted for downstream orchestration.'
  );
  assert.equal(
    payload.paths['/platform/users/status'].post.summary,
    'Update platform user status (active|disabled, platform-domain scoped)'
  );
  assert.equal(
    payload.paths['/platform/users/status'].post.description,
    '平台用户状态治理仅影响 platform 域访问可用性；组织域（tenant）访问不因该接口直接改变。'
  );
  assert.equal(
    payload.paths['/platform/users/status'].post.responses['200'].description,
    'Platform user status updated (or no-op). Only platform-domain access is affected.'
  );
  assert.equal(
    payload.paths['/platform/users/status'].post.responses['404'].description,
    'Target platform user not found or has no platform-domain access'
  );
  assert.equal(
    payload.paths['/platform/users/status'].post.responses['404'].content['application/problem+json']
      .examples.user_not_found.value.detail,
    '目标平台用户不存在或无 platform 域访问'
  );
  assert.equal(
    payload.components.schemas.ProvisionPlatformUserRequest.properties.phone.minLength,
    11
  );
  assert.equal(
    payload.components.schemas.ProvisionPlatformUserRequest.properties.phone.maxLength,
    11
  );
  assert.equal(
    payload.components.schemas.ProvisionPlatformUserRequest.properties.phone.pattern,
    '^1\\d{10}$'
  );
  assert.equal(
    Object.prototype.hasOwnProperty.call(
      payload.components.schemas.ProvisionPlatformUserRequest.properties,
      'tenant_name'
    ),
    false
  );
  assert.equal(
    payload.components.schemas.ProvisionUserRequest.properties.tenant_name.maxLength,
    128
  );
  assert.equal(
    payload.components.schemas.ProvisionUserRequest.properties.tenant_name.pattern,
    '.*\\S.*'
  );
  assert.equal(
    payload.components.schemas.CreatePlatformOrgRequest.required.includes('org_name'),
    true
  );
  assert.equal(
    payload.components.schemas.CreatePlatformOrgRequest.required.includes('initial_owner_phone'),
    true
  );
  assert.equal(
    payload.components.schemas.CreatePlatformOrgRequest.properties.org_name.pattern,
    '^[^\\x00-\\x1F\\x7F]*\\S[^\\x00-\\x1F\\x7F]*$'
  );
  assert.equal(
    payload.components.schemas.CreatePlatformOrgRequest.properties.initial_owner_phone.pattern,
    '^1\\d{10}$'
  );
  assert.equal(
    payload.components.schemas.CreatePlatformOrgRequest.additionalProperties,
    false
  );
  assert.equal(
    payload.components.schemas.UpdatePlatformOrgStatusRequest.required.includes('reason'),
    false
  );
  assert.equal(
    payload.components.schemas.UpdatePlatformOrgStatusRequest.properties.reason.pattern,
    '^[^\\x00-\\x1F\\x7F]*\\S[^\\x00-\\x1F\\x7F]*$'
  );
  assert.equal(
    payload.components.schemas.UpdatePlatformOrgStatusRequest.properties.reason.maxLength,
    256
  );
  assert.equal(
    payload.components.schemas.UpdatePlatformOrgStatusRequest.properties.status.description,
    '目标组织状态（仅影响 tenant 域访问可用性，不影响 platform 域）'
  );
  assert.equal(
    payload.components.schemas.UpdatePlatformOrgStatusResponse.properties.previous_status.description,
    '组织状态更新前值（tenant 域治理状态）'
  );
  assert.equal(
    payload.components.schemas.UpdatePlatformOrgStatusResponse.properties.current_status.description,
    '组织状态更新后值（tenant 域治理状态）'
  );
  assert.equal(
    payload.components.schemas.PlatformOrgOwnerTransferRequest.required.includes('org_id'),
    true
  );
  assert.equal(
    payload.components.schemas.PlatformOrgOwnerTransferRequest.required.includes('new_owner_phone'),
    true
  );
  assert.equal(
    payload.components.schemas.PlatformOrgOwnerTransferRequest.required.includes('reason'),
    false
  );
  assert.equal(
    payload.components.schemas.PlatformOrgOwnerTransferRequest.properties.org_id.maxLength,
    64
  );
  assert.equal(
    payload.components.schemas.PlatformOrgOwnerTransferRequest.properties.org_id.pattern,
    '^(?!.*\\s)[^\\x00-\\x1F\\x7F]+$'
  );
  assert.equal(
    payload.components.schemas.PlatformOrgOwnerTransferRequest.properties.reason.pattern,
    '^(?!\\s)(?!.*\\s$)[^\\x00-\\x1F\\x7F]+$'
  );
  assert.equal(
    payload.components.schemas.PlatformOrgOwnerTransferRequest.properties.new_owner_phone.pattern,
    '^1\\d{10}$'
  );
  assert.equal(
    payload.components.schemas.PlatformOrgOwnerTransferRequest.additionalProperties,
    false
  );
  assert.equal(
    payload.components.schemas.PlatformOrgOwnerTransferResponse.required.includes('request_id'),
    true
  );
  assert.equal(
    payload.components.schemas.PlatformOrgOwnerTransferResponse.required.includes('org_id'),
    true
  );
  assert.equal(
    payload.components.schemas.PlatformOrgOwnerTransferResponse.required.includes('old_owner_user_id'),
    true
  );
  assert.equal(
    payload.components.schemas.PlatformOrgOwnerTransferResponse.required.includes('new_owner_user_id'),
    true
  );
  assert.equal(
    payload.components.schemas.PlatformOrgOwnerTransferResponse.required.includes('result_status'),
    true
  );
  assert.equal(
    payload.components.schemas.PlatformOrgOwnerTransferResponse.required.includes('error_code'),
    true
  );
  assert.equal(
    payload.components.schemas.PlatformOrgOwnerTransferResponse.required.includes('retryable'),
    true
  );
  assert.equal(
    payload.components.schemas.PlatformOrgOwnerTransferResponse.additionalProperties,
    false
  );
  assert.equal(
    payload.components.schemas.UpdatePlatformUserStatusRequest.properties.status.description,
    '目标平台用户状态（仅影响 platform 域访问可用性，不影响 tenant 域）'
  );
  assert.equal(
    payload.components.schemas.UpdatePlatformUserStatusResponse.properties.previous_status.description,
    '平台用户状态更新前值（platform 域治理状态）'
  );
  assert.equal(
    payload.components.schemas.UpdatePlatformUserStatusResponse.properties.current_status.description,
    '平台用户状态更新后值（platform 域治理状态）'
  );
  assert.equal(
    payload.components.schemas.CreatePlatformOrgResponse.required.includes('org_id'),
    true
  );
  assert.equal(
    payload.components.schemas.CreatePlatformOrgResponse.required.includes('owner_user_id'),
    true
  );
  assert.equal(
    payload.components.schemas.CreatePlatformOrgResponse.additionalProperties,
    false
  );
  assert.equal(
    payload.paths['/platform/orgs'].post.responses['400'].content['application/problem+json']
      .examples.initial_owner_phone_required.value.error_code,
    'ORG-400-INITIAL-OWNER-PHONE-REQUIRED'
  );
  assert.equal(
    payload.paths['/platform/orgs'].post.responses['400'].content['application/problem+json']
      .examples.invalid_idempotency_key.value.error_code,
    'AUTH-400-IDEMPOTENCY-KEY-INVALID'
  );
  assert.equal(
    payload.paths['/platform/orgs'].post.responses['409'].content['application/problem+json']
      .examples.idempotency_conflict.value.error_code,
    'AUTH-409-IDEMPOTENCY-CONFLICT'
  );
  assert.equal(
    payload.paths['/platform/orgs'].post.responses['503'].content['application/problem+json']
      .examples.dependency_unavailable.value.error_code,
    'ORG-503-DEPENDENCY-UNAVAILABLE'
  );
  assert.equal(
    payload.paths['/platform/users'].post.responses['503'].content['application/problem+json']
      .examples.governance_dependency_unavailable.value.error_code,
    'USR-503-DEPENDENCY-UNAVAILABLE'
  );
  assert.equal(
    payload.paths['/platform/users/status'].post.responses['503'].content[
      'application/problem+json'
    ].examples.platform_snapshot_degraded.value.error_code,
    'AUTH-503-PLATFORM-SNAPSHOT-DEGRADED'
  );
  assert.equal(
    payload.paths['/platform/orgs'].post.responses['503'].content['application/problem+json']
      .examples.idempotency_store_unavailable.value.detail,
    '幂等服务暂时不可用，请稍后重试'
  );
  assert.equal(
    payload.paths['/platform/orgs'].post.responses['503'].content['application/problem+json']
      .examples.idempotency_store_unavailable.value.degradation_reason,
    'idempotency-store-unavailable'
  );
  assert.equal(
    payload.paths['/platform/orgs'].post.responses['503'].content['application/problem+json']
      .examples.idempotency_pending_timeout.value.degradation_reason,
    'idempotency-pending-timeout'
  );
  assert.equal(
    payload.paths['/platform/orgs'].post.responses['413'].content['application/problem+json']
      .examples.payload_too_large.value.error_code,
    'AUTH-413-PAYLOAD-TOO-LARGE'
  );
  assert.equal(
    payload.paths['/platform/orgs'].post.responses['401'].content['application/problem+json']
      .examples.invalid_access_token.value.error_code,
    'AUTH-401-INVALID-ACCESS'
  );
  assert.equal(
    payload.paths['/platform/orgs'].post.responses['401'].content['application/problem+json']
      .examples.invalid_access_token.value.detail,
    '当前会话无效，请重新登录'
  );
  assert.equal(
    payload.paths['/platform/orgs'].post.responses['403'].content['application/problem+json']
      .examples.forbidden.value.error_code,
    'AUTH-403-FORBIDDEN'
  );
  assert.equal(
    Object.prototype.hasOwnProperty.call(
      payload.paths['/platform/roles'].post.responses['400'].content[
        'application/problem+json'
      ].examples.invalid_idempotency_key.value,
      'org_id'
    ),
    false
  );
  assert.equal(
    Object.prototype.hasOwnProperty.call(
      payload.paths['/platform/orgs'].post.responses['409'].content[
        'application/problem+json'
      ].examples.idempotency_conflict.value,
      'result_status'
    ),
    false
  );
  assert.equal(
    Object.prototype.hasOwnProperty.call(
      payload.paths['/platform/orgs'].post.responses['413'].content[
        'application/problem+json'
      ].examples.payload_too_large.value,
      'old_owner_user_id'
    ),
    false
  );
  assert.equal(
    Object.prototype.hasOwnProperty.call(
      payload.paths['/platform/orgs'].post.responses['413'].content[
        'application/problem+json'
      ].examples.payload_too_large.value,
      'result_status'
    ),
    false
  );
  assert.equal(
    Object.prototype.hasOwnProperty.call(
      payload.paths['/platform/orgs/status'].post.responses['503'].content[
        'application/problem+json'
      ].examples.idempotency_store_unavailable.value,
      'old_owner_user_id'
    ),
    false
  );
  assert.equal(
    payload.paths['/platform/orgs/owner-transfer'].post.responses['400'].content[
      'application/problem+json'
    ].examples.invalid_idempotency_key.value.error_code,
    'AUTH-400-IDEMPOTENCY-KEY-INVALID'
  );
  assert.equal(
    payload.paths['/platform/orgs/owner-transfer'].post.responses['400'].content[
      'application/problem+json'
    ].examples.invalid_idempotency_key.value.result_status,
    'rejected'
  );
  assert.equal(
    payload.paths['/platform/orgs/owner-transfer'].post.responses['400'].content[
      'application/problem+json'
    ].examples.invalid_payload.value.result_status,
    'rejected'
  );
  assert.equal(
    payload.paths['/platform/orgs/owner-transfer'].post.responses['400'].content[
      'application/problem+json'
    ].examples.invalid_payload.value.org_id,
    null
  );
  assert.equal(
    payload.paths['/platform/orgs/owner-transfer'].post.responses['409'].content[
      'application/problem+json'
    ].examples.concurrent_conflict.value.error_code,
    'ORG-409-OWNER-TRANSFER-CONFLICT'
  );
  assert.equal(
    payload.paths['/platform/orgs/owner-transfer'].post.responses['409'].content[
      'application/problem+json'
    ].examples.concurrent_conflict.value.result_status,
    'conflict'
  );
  assert.equal(
    payload.paths['/platform/orgs/owner-transfer'].post.responses['409'].content[
      'application/problem+json'
    ].examples.idempotency_conflict.value.result_status,
    'conflict'
  );
  assert.equal(
    payload.paths['/platform/orgs/owner-transfer'].post.responses['503'].content[
      'application/problem+json'
    ].examples.idempotency_store_unavailable.value.error_code,
    'AUTH-503-IDEMPOTENCY-STORE-UNAVAILABLE'
  );
  assert.equal(
    payload.paths['/platform/orgs/owner-transfer'].post.responses['503'].content[
      'application/problem+json'
    ].examples.idempotency_store_unavailable.value.result_status,
    'rejected'
  );
  assert.equal(
    payload.paths['/platform/orgs/owner-transfer'].post.responses['503'].content[
      'application/problem+json'
    ].examples.idempotency_pending_timeout.value.result_status,
    'rejected'
  );
  assert.equal(
    payload.paths['/platform/orgs/owner-transfer'].post.responses['503'].content[
      'application/problem+json'
    ].examples.dependency_unavailable.value.result_status,
    'rejected'
  );
  assert.equal(
    payload.paths['/platform/orgs/owner-transfer'].post.responses['413'].content[
      'application/problem+json'
    ].examples.payload_too_large.value.result_status,
    'rejected'
  );
  assert.equal(
    payload.paths['/platform/orgs/owner-transfer'].post.responses['413'].content[
      'application/problem+json'
    ].examples.payload_too_large.value.org_id,
    null
  );
  assert.equal(
    payload.components.schemas.ReplacePlatformRoleFactsRequest.properties.roles.minItems,
    1
  );
  assert.equal(
    payload.components.schemas.ReplacePlatformRoleFactsRequest.properties.roles.maxItems,
    5
  );
  assert.equal(
    payload.components.schemas.ReplacePlatformRolePermissionGrantsRequest
      .properties.permission_codes.maxItems,
    64
  );
  assert.equal(
    payload.components.schemas.ReplacePlatformRoleFactsRequest.properties.roles.uniqueItems,
    true
  );
  assert.ok(
    String(
      payload.components.schemas.ReplacePlatformRoleFactsRequest.properties.roles.description
      || ''
    ).includes('大小写不敏感')
  );
  assert.equal(
    payload.components.schemas.ReplacePlatformRoleFactsRequest.properties.user_id.minLength,
    1
  );
  assert.equal(
    payload.components.schemas.ReplacePlatformRoleFactsRequest.properties.user_id.pattern,
    '.*\\S.*'
  );
  assert.equal(
    payload.components.schemas.PlatformRoleFact.properties.role_id.minLength,
    1
  );
  assert.equal(
    payload.components.schemas.PlatformRoleFact.properties.role_id.maxLength,
    64
  );
  assert.equal(
    payload.components.schemas.PlatformRoleFact.properties.role_id.pattern,
    '.*\\S.*'
  );
  assert.deepEqual(
    payload.components.schemas.PlatformRoleFact.properties.status.enum,
    ['active', 'enabled']
  );
  assert.ok(
    payload.paths['/auth/tenant/member-admin/probe'].get.responses['403'].content[
      'application/problem+json'
    ].examples.no_domain
  );
  assert.equal(
    payload.paths['/auth/tenant/member-admin/probe'].get.responses['403'].content[
      'application/problem+json'
    ].examples.no_domain.value.error_code,
    'AUTH-403-NO-DOMAIN'
  );
  assert.equal(
    payload.paths['/auth/platform/member-admin/probe'].get.responses['503'].content[
      'application/problem+json'
    ].examples.snapshot_sync_degraded.value.error_code,
    'AUTH-503-PLATFORM-SNAPSHOT-DEGRADED'
  );
  assert.equal(
    payload.paths['/auth/platform/member-admin/probe'].get.responses['503'].content[
      'application/problem+json'
    ].examples.snapshot_sync_degraded.value.retryable,
    true
  );
  assert.equal(
    payload.paths['/auth/tenant/member-admin/provision-user'].post.responses['409'].content[
      'application/problem+json'
    ].examples.idempotency_conflict.value.error_code,
    'AUTH-409-IDEMPOTENCY-CONFLICT'
  );
  assert.equal(
    payload.paths['/auth/platform/member-admin/provision-user'].post.responses['409'].content[
      'application/problem+json'
    ].examples.idempotency_conflict.value.error_code,
    'AUTH-409-IDEMPOTENCY-CONFLICT'
  );
  assert.equal(
    payload.paths['/auth/platform/member-admin/provision-user'].post.responses['503'].content[
      'application/problem+json'
    ].examples.default_password_config_unavailable.value.retryable,
    true
  );
  assert.equal(
    payload.paths['/auth/tenant/member-admin/provision-user'].post.responses['503'].content[
      'application/problem+json'
    ].examples.default_password_config_unavailable.value.degradation_reason,
    'default-password-config-unavailable'
  );
  assert.equal(
    payload.paths['/auth/login'].post.responses['429'].content['application/problem+json'].examples
      .rate_limited.value.retryable,
    true
  );
  assert.equal(
    payload.paths['/auth/login'].post.responses['429'].content['application/problem+json'].examples
      .rate_limited.value.rate_limit_limit,
    10
  );
  assert.equal(
    payload.paths['/auth/login'].post.responses['429'].content['application/problem+json'].examples
      .rate_limited.value.rate_limit_window_seconds,
    60
  );
  assert.equal(
    payload.paths['/auth/otp/send'].post.responses['429'].content['application/problem+json']
      .examples.otp_send_rate_limited.value.rate_limit_limit,
    10
  );
  assert.equal(
    payload.paths['/auth/otp/login'].post.responses['429'].content['application/problem+json']
      .examples.otp_login_rate_limited.value.rate_limit_window_seconds,
    60
  );
  assert.equal(
    payload.paths['/auth/tenant/member-admin/provision-user'].post.responses['400'].content[
      'application/problem+json'
    ].examples.invalid_idempotency_key.value.error_code,
    'AUTH-400-IDEMPOTENCY-KEY-INVALID'
  );
  assert.equal(
    payload.paths['/auth/platform/member-admin/provision-user'].post.responses['400'].content[
      'application/problem+json'
    ].examples.invalid_idempotency_key.value.error_code,
    'AUTH-400-IDEMPOTENCY-KEY-INVALID'
  );
  assert.equal(
    payload.paths['/auth/platform/role-facts/replace'].post.responses['400'].content[
      'application/problem+json'
    ].examples.invalid_idempotency_key.value.error_code,
    'AUTH-400-IDEMPOTENCY-KEY-INVALID'
  );
  assert.equal(
    payload.components.schemas.ProblemDetails.properties.error_code.type,
    'string'
  );
  assert.equal(
    payload.components.schemas.ProblemDetails.required.includes('error_code'),
    true
  );
  assert.equal(
    payload.components.schemas.ProblemDetails.properties.retryable.type,
    'boolean'
  );
  assert.equal(
    payload.components.schemas.ProblemDetails.properties.retry_after_seconds.type,
    'integer'
  );
  assert.equal(
    payload.components.schemas.ProblemDetails.properties.rate_limit_action.type,
    'string'
  );
  assert.equal(
    payload.paths['/auth/login'].post.responses['413'].content['application/problem+json'].examples
      .payload_too_large.value.error_code,
    'AUTH-413-PAYLOAD-TOO-LARGE'
  );
  assert.equal(
    payload.paths['/auth/refresh'].post.responses['413'].content['application/problem+json'].examples
      .payload_too_large.value.error_code,
    'AUTH-413-PAYLOAD-TOO-LARGE'
  );
  assert.deepEqual(listProblemExamplesMissingRetryable(payload), []);
  assert.equal('extensions' in payload.components.schemas.ProblemDetails.properties, false);
});

test('createRouteHandlers wires shared default auth service for platform org and idempotency audit', async () => {
  const handlers = createRouteHandlers(config, {
    dependencyProbe
  });
  assert.equal(typeof handlers.recordAuthIdempotencyEvent, 'function');
  assert.equal(typeof handlers._internals?.authService?.getOrCreateUserIdentityByPhone, 'function');
  assert.equal(typeof handlers._internals?.platformOrgService?.createOrg, 'function');

  await assert.rejects(
    () =>
      handlers.platformCreateOrg(
        'req-default-handler-platform-org',
        undefined,
        {
          org_name: '组织 default-handler',
          initial_owner_phone: '13800000071'
        },
        {
          ...markRoutePreauthorizedContext({
            authorizationContext: {
              entry_domain: 'platform',
              user_id: 'platform-operator',
              session_id: 'platform-session'
            },
            permissionCode: 'platform.member_admin.operate',
            scope: 'platform'
          })
        }
      ),
    (error) => {
      assert.ok(error instanceof AuthProblemError);
      assert.equal(error.status, 503);
      assert.equal(error.errorCode, 'ORG-503-DEPENDENCY-UNAVAILABLE');
      return true;
    }
  );
  const lastAuditEvent =
    handlers._internals.platformOrgService._internals.auditTrail.at(-1);
  assert.equal(lastAuditEvent.type, 'org.create.rejected');
  assert.equal(lastAuditEvent.upstream_error_code, 'AUTH-503-PROVISION-CONFIG-UNAVAILABLE');
});

test('createRouteHandlers reuses platformOrgService authService when authService option is omitted', () => {
  const sharedAuthService = {
    authorizeRoute: async () => ({
      user_id: 'platform-operator',
      session_id: 'platform-session',
      entry_domain: 'platform'
    }),
    getOrCreateUserIdentityByPhone: async ({ phone }) => ({
      user_id: 'owner-user-existing',
      phone,
      created_user: false,
      reused_existing_user: true
    }),
    createOrganizationWithOwner: async ({ orgId, ownerUserId }) => ({
      org_id: orgId,
      owner_user_id: ownerUserId
    }),
    rollbackProvisionedUserIdentity: async () => {},
    recordIdempotencyEvent: async () => {}
  };
  const platformOrgService = createPlatformOrgService({
    authService: sharedAuthService
  });

  const handlers = createRouteHandlers(config, {
    dependencyProbe,
    platformOrgService
  });

  assert.equal(handlers._internals.authService, sharedAuthService);
  assert.equal(handlers._internals.platformOrgService, platformOrgService);
});

test('createRouteHandlers fails fast when injected authService mismatches platformOrgService authService', () => {
  const platformOrgAuthService = {
    authorizeRoute: async () => ({})
  };
  const platformOrgService = createPlatformOrgService({
    authService: platformOrgAuthService
  });
  const differentAuthService = {
    authorizeRoute: async () => ({})
  };

  assert.throws(
    () =>
      createRouteHandlers(config, {
        dependencyProbe,
        authService: differentAuthService,
        platformOrgService
      }),
    /share the same authService instance/
  );
});

test('createRouteHandlers fails fast when platformOrgService and platformUserService authService differ', () => {
  const platformOrgService = {
    createOrg: async () => ({}),
    updateOrgStatus: async () => ({}),
    ownerTransfer: async () => ({}),
    _internals: {
      authService: {
        authorizeRoute: async () => ({})
      }
    }
  };
  const platformUserService = {
    createUser: async () => ({}),
    updateUserStatus: async () => ({}),
    _internals: {
      authService: {
        authorizeRoute: async () => ({})
      }
    }
  };

  assert.throws(
    () =>
      createRouteHandlers(config, {
        dependencyProbe,
        platformOrgService,
        platformUserService
      }),
    /platformOrgService and platformUserService to share the same authService instance/
  );
});

test('health returns degraded when backend connectivity fails', async () => {
  const handlers = createRouteHandlers(config, {
    dependencyProbe: async () => ({
      db: { ok: false, detail: 'db down' },
      redis: { ok: true, detail: 'redis up' }
    })
  });

  const body = await handlers.health('t-1');
  assert.equal(body.ok, false);
  assert.equal(body.request_id, 't-1');
  assert.equal(body.dependencies.db.ok, false);
});

test('smoke marks ok when db and redis are both connected', async () => {
  const handlers = createRouteHandlers(config, {
    dependencyProbe: async () => ({
      db: { ok: true, mode: 'mysql-native' },
      redis: { ok: true, mode: 'ioredis' }
    })
  });

  const body = await handlers.smoke('smoke-route');
  assert.equal(body.ok, true);
  assert.equal(body.chain, 'api -> db/redis');
  assert.equal(body.request_id, 'smoke-route');
});

test('createServer enforces json payload limit with AUTH-413-PAYLOAD-TOO-LARGE', async () => {
  const harness = await startServer({
    ALLOW_MOCK_BACKENDS: 'true',
    API_JSON_BODY_LIMIT_BYTES: '256'
  });

  try {
    const response = await fetch(`${harness.baseUrl}/auth/login`, {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        accept: 'application/json, application/problem+json'
      },
      body: JSON.stringify({
        phone: '13800000000',
        password: 'x'.repeat(1024)
      })
    });
    const payload = await response.json();
    assert.equal(response.status, 413);
    assert.equal(payload.error_code, 'AUTH-413-PAYLOAD-TOO-LARGE');
    assert.equal(payload.detail, 'JSON payload exceeds allowed size');
    assert.equal(String(response.headers.get('connection') || '').toLowerCase(), 'close');
  } finally {
    await harness.close();
  }
});

test('createServer enforces json payload limit on /platform/orgs with AUTH-413-PAYLOAD-TOO-LARGE', async () => {
  const harness = await startServer({
    ALLOW_MOCK_BACKENDS: 'true',
    API_JSON_BODY_LIMIT_BYTES: '256'
  });

  try {
    const response = await fetch(`${harness.baseUrl}/platform/orgs`, {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        accept: 'application/json, application/problem+json',
        authorization: 'Bearer fake-access-token'
      },
      body: JSON.stringify({
        org_name: '组织 payload-too-large',
        initial_owner_phone: '13800000000',
        padding: 'x'.repeat(1024)
      })
    });
    const payload = await response.json();
    assert.equal(response.status, 413);
    assert.equal(payload.error_code, 'AUTH-413-PAYLOAD-TOO-LARGE');
    assert.equal(payload.detail, 'JSON payload exceeds allowed size');
    assert.equal(String(response.headers.get('connection') || '').toLowerCase(), 'close');
  } finally {
    await harness.close();
  }
});

test('createServer enforces json payload limit on /platform/orgs/owner-transfer with stable transfer contract fields', async () => {
  const harness = await startServer({
    ALLOW_MOCK_BACKENDS: 'true',
    API_JSON_BODY_LIMIT_BYTES: '256'
  });

  try {
    const response = await fetch(`${harness.baseUrl}/platform/orgs/owner-transfer`, {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        accept: 'application/json, application/problem+json',
        authorization: 'Bearer fake-access-token'
      },
      body: JSON.stringify({
        org_id: 'org-owner-transfer-payload-too-large',
        new_owner_phone: '13800000099',
        reason: 'x'.repeat(1024)
      })
    });
    const payload = await response.json();
    assert.equal(response.status, 413);
    assert.equal(payload.error_code, 'AUTH-413-PAYLOAD-TOO-LARGE');
    assert.equal(payload.org_id, null);
    assert.equal(payload.old_owner_user_id, null);
    assert.equal(payload.new_owner_user_id, null);
    assert.equal(payload.result_status, 'rejected');
    assert.equal(payload.retryable, false);
    assert.equal(String(response.headers.get('connection') || '').toLowerCase(), 'close');
  } finally {
    await harness.close();
  }
});

test('createServer rejects auth routes with trailing slash path', async () => {
  const harness = await startServer({
    ALLOW_MOCK_BACKENDS: 'true'
  });

  try {
    const response = await fetch(`${harness.baseUrl}/auth/login/`, {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        accept: 'application/json, application/problem+json'
      },
      body: JSON.stringify({
        phone: '13800000000',
        password: 'Passw0rd!'
      })
    });
    const payload = await response.json();
    assert.equal(response.status, 404);
    assert.equal(payload.error_code, 'AUTH-404-NOT-FOUND');
  } finally {
    await harness.close();
  }
});

test('createServer supports CORS preflight for API routes', async () => {
  const harness = await startServer({
    ALLOW_MOCK_BACKENDS: 'true',
    API_CORS_ALLOWED_ORIGINS: 'https://example.test'
  });

  try {
    const response = await fetch(`${harness.baseUrl}/auth/login`, {
      method: 'OPTIONS',
      headers: {
        origin: 'https://example.test',
        'access-control-request-method': 'POST',
        'access-control-request-headers': 'content-type,authorization,x-request-id'
      }
    });
    assert.equal(response.status, 204);
    assert.equal(response.headers.get('access-control-allow-origin'), 'https://example.test');
    const allowMethods = new Set(
      String(response.headers.get('access-control-allow-methods') || '')
        .split(',')
        .map((method) => method.trim().toUpperCase())
        .filter((method) => method.length > 0)
    );
    assert.deepEqual([...allowMethods], ['POST', 'OPTIONS']);
    assert.ok(
      String(response.headers.get('access-control-allow-headers') || '').includes(
        'Content-Type'
      )
    );
    assert.ok(
      String(response.headers.get('access-control-allow-headers') || '').includes(
        'Idempotency-Key'
      )
    );
  } finally {
    await harness.close();
  }
});

test('createServer CORS preflight includes HEAD when route is declared as GET', async () => {
  const harness = await startServer({
    ALLOW_MOCK_BACKENDS: 'true',
    API_CORS_ALLOWED_ORIGINS: 'https://example.test'
  });

  try {
    const response = await fetch(`${harness.baseUrl}/health`, {
      method: 'OPTIONS',
      headers: {
        origin: 'https://example.test',
        'access-control-request-method': 'HEAD'
      }
    });
    assert.equal(response.status, 204);
    const allowMethods = new Set(
      String(response.headers.get('access-control-allow-methods') || '')
        .split(',')
        .map((method) => method.trim().toUpperCase())
        .filter((method) => method.length > 0)
    );
    assert.deepEqual([...allowMethods], ['GET', 'HEAD', 'OPTIONS']);
  } finally {
    await harness.close();
  }
});

test('createServer CORS preflight does not reflect origins outside allowlist', async () => {
  const harness = await startServer({
    ALLOW_MOCK_BACKENDS: 'true',
    API_CORS_ALLOWED_ORIGINS: 'https://allowed.example'
  });

  try {
    const response = await fetch(`${harness.baseUrl}/auth/login`, {
      method: 'OPTIONS',
      headers: {
        origin: 'https://blocked.example',
        'access-control-request-method': 'POST'
      }
    });
    assert.equal(response.status, 204);
    assert.equal(response.headers.get('access-control-allow-origin'), null);
  } finally {
    await harness.close();
  }
});

test('dispatchApiRoute reuses GET handler semantics for HEAD routes', async () => {
  let healthCalls = 0;
  const route = await dispatchApiRoute({
    pathname: '/health',
    method: 'HEAD',
    requestId: 'req-head-health',
    handlers: {
      health: async () => {
        healthCalls += 1;
        return { ok: true };
      }
    }
  });

  assert.equal(route.status, 200);
  assert.equal(route.body, '');
  assert.equal(route.headers['content-type'], 'application/json');
  assert.equal(healthCalls, 1);
});

test('dispatchApiRoute returns empty body for HEAD not-found responses', async () => {
  const route = await dispatchApiRoute({
    pathname: '/not-found',
    method: 'HEAD',
    requestId: 'req-head-not-found',
    handlers: {}
  });

  assert.equal(route.status, 404);
  assert.equal(route.body, '');
});

test('dispatchApiRoute returns AUTH-404-NOT-FOUND for unknown routes', async () => {
  const route = await dispatchApiRoute({
    pathname: '/not-found',
    method: 'GET',
    requestId: 'req-get-not-found',
    handlers: {}
  });

  assert.equal(route.status, 404);
  const payload = JSON.parse(route.body);
  assert.equal(payload.error_code, 'AUTH-404-NOT-FOUND');
  assert.equal(payload.request_id, 'req-get-not-found');
});

test('dispatchApiRoute returns 405 with allow header for declared paths that disallow method', async () => {
  const route = await dispatchApiRoute({
    pathname: '/health',
    method: 'POST',
    requestId: 'req-method-not-allowed',
    handlers: {
      health: async () => ({ ok: true })
    }
  });

  assert.equal(route.status, 405);
  assert.equal(route.headers.allow, 'GET,HEAD,OPTIONS');
  const payload = JSON.parse(route.body);
  assert.equal(payload.error_code, 'AUTH-405-METHOD-NOT-ALLOWED');
  assert.equal(payload.request_id, 'req-method-not-allowed');
});

test('dispatchApiRoute resolves request_id from case-insensitive x-request-id header', async () => {
  const route = await dispatchApiRoute({
    pathname: '/auth/ping',
    method: 'GET',
    headers: {
      'X-Request-Id': 'req-header-upper-case'
    },
    handlers: {
      authPing: (requestId) => ({
        ok: true,
        request_id: requestId
      })
    }
  });

  assert.equal(route.status, 200);
  assert.equal(JSON.parse(route.body).request_id, 'req-header-upper-case');
});

test('handleApiRoute resolves request_id from case-insensitive x-request-id header', async () => {
  const routeDefinitions = [
    {
      method: 'GET',
      path: '/auth/ping',
      access: 'public'
    }
  ];
  const routeDeclarationLookup = resolveRouteDeclarationLookup({
    routeDefinitions
  });

  const route = await handleApiRoute(
    {
      pathname: '/auth/ping',
      method: 'GET',
      headers: {
        'X-Request-Id': 'req-header-upper-case-handle'
      }
    },
    config,
    {
      routeDefinitions,
      routeDeclarationLookup,
      validateRouteDefinitions: false,
      handlers: {
        authPing: (requestId) => ({
          ok: true,
          request_id: requestId
        })
      }
    }
  );

  assert.equal(route.status, 200);
  assert.equal(JSON.parse(route.body).request_id, 'req-header-upper-case-handle');
});

test('dispatchApiRoute falls back to generated request_id for ambiguous x-request-id header values', async () => {
  const route = await dispatchApiRoute({
    pathname: '/auth/ping',
    method: 'GET',
    headers: {
      'x-request-id': ['req-a', 'req-b']
    },
    handlers: {
      authPing: (requestId) => ({
        ok: true,
        request_id: requestId
      })
    }
  });

  assert.equal(route.status, 200);
  const payload = JSON.parse(route.body);
  assert.match(payload.request_id, UUID_PATTERN);
  assert.notEqual(payload.request_id, 'req-a');
  assert.notEqual(payload.request_id, 'req-b');
});

test('handleApiRoute falls back to generated request_id for comma-separated x-request-id header', async () => {
  const routeDefinitions = [
    {
      method: 'GET',
      path: '/auth/ping',
      access: 'public'
    }
  ];
  const routeDeclarationLookup = resolveRouteDeclarationLookup({
    routeDefinitions
  });

  const route = await handleApiRoute(
    {
      pathname: '/auth/ping',
      method: 'GET',
      headers: {
        'x-request-id': 'req-a,req-b'
      }
    },
    config,
    {
      routeDefinitions,
      routeDeclarationLookup,
      validateRouteDefinitions: false,
      handlers: {
        authPing: (requestId) => ({
          ok: true,
          request_id: requestId
        })
      }
    }
  );

  assert.equal(route.status, 200);
  assert.match(JSON.parse(route.body).request_id, UUID_PATTERN);
});

test('dispatchApiRoute falls back to generated request_id for non-header-safe x-request-id header values', async () => {
  const route = await dispatchApiRoute({
    pathname: '/auth/ping',
    method: 'GET',
    headers: {
      'x-request-id': '中文请求ID'
    },
    handlers: {
      authPing: (requestId) => ({
        ok: true,
        request_id: requestId
      })
    }
  });

  assert.equal(route.status, 200);
  const payload = JSON.parse(route.body);
  assert.match(payload.request_id, UUID_PATTERN);
  assert.notEqual(payload.request_id, '中文请求ID');
});

test('dispatchApiRoute falls back to generated request_id when explicit requestId is comma-separated', async () => {
  const route = await dispatchApiRoute({
    pathname: '/auth/ping',
    method: 'GET',
    requestId: 'req-a,req-b',
    handlers: {
      authPing: (requestId) => ({
        ok: true,
        request_id: requestId
      })
    }
  });

  assert.equal(route.status, 200);
  const payload = JSON.parse(route.body);
  assert.match(payload.request_id, UUID_PATTERN);
  assert.notEqual(payload.request_id, 'req-a,req-b');
});

test('dispatchApiRoute sanitizes and bounds request_id from headers', async () => {
  const rawRequestId = `\nreq-sanitize-${'a'.repeat(240)}\r`;
  const route = await dispatchApiRoute({
    pathname: '/auth/ping',
    method: 'GET',
    headers: {
      'x-request-id': rawRequestId
    },
    handlers: {
      authPing: (requestId) => ({
        ok: true,
        request_id: requestId
      })
    }
  });

  assert.equal(route.status, 200);
  const payload = JSON.parse(route.body);
  assert.equal(payload.request_id.includes('\n'), false);
  assert.equal(payload.request_id.includes('\r'), false);
  assert.ok(payload.request_id.startsWith('req-sanitize-'));
  assert.equal(payload.request_id.length, 128);
});

test('dispatchApiRoute rejects ambiguous Idempotency-Key header values', async () => {
  const calls = [];
  const dispatchProvisionRequest = (idempotencyHeaderValue) =>
    dispatchApiRoute({
      pathname: '/auth/platform/member-admin/provision-user',
      method: 'POST',
      requestId: 'req-ambiguous-idempotency',
      headers: {
        authorization: 'Bearer fake-token',
        'idempotency-key': idempotencyHeaderValue
      },
      body: {
        phone: '13800000000'
      },
      handlers: {
        authPlatformMemberAdminProvisionUser: async (requestId) => {
          calls.push(requestId);
          return {
            ok: true,
            request_id: requestId
          };
        },
        authorizeRoute: async () => ({
          user_id: 'operator-user',
          session_id: 'operator-session'
        })
      }
    });

  const arrayHeaderResponse = await dispatchProvisionRequest([
    'idem-platform-001',
    'idem-platform-002'
  ]);
  assert.equal(arrayHeaderResponse.status, 400);
  assert.equal(
    JSON.parse(arrayHeaderResponse.body).error_code,
    'AUTH-400-IDEMPOTENCY-KEY-INVALID'
  );

  const commaHeaderResponse = await dispatchProvisionRequest('idem-platform-001,idem-platform-002');
  assert.equal(commaHeaderResponse.status, 400);
  assert.equal(
    JSON.parse(commaHeaderResponse.body).error_code,
    'AUTH-400-IDEMPOTENCY-KEY-INVALID'
  );

  assert.equal(calls.length, 0);
});

test('dispatchApiRoute rejects non-header-safe Idempotency-Key header values', async () => {
  const calls = [];
  const route = await dispatchApiRoute({
    pathname: '/auth/platform/member-admin/provision-user',
    method: 'POST',
    requestId: 'req-invalid-idempotency-header-char',
    headers: {
      authorization: 'Bearer fake-token',
      'idempotency-key': 'idem-中文'
    },
    body: {
      phone: '13800000000'
    },
    handlers: {
      authPlatformMemberAdminProvisionUser: async (requestId) => {
        calls.push(requestId);
        return {
          ok: true,
          request_id: requestId
        };
      },
      authorizeRoute: async () => ({
        user_id: 'operator-user',
        session_id: 'operator-session'
      })
    }
  });

  assert.equal(route.status, 400);
  assert.equal(
    JSON.parse(route.body).error_code,
    'AUTH-400-IDEMPOTENCY-KEY-INVALID'
  );
  assert.equal(calls.length, 0);
});

test('dispatchApiRoute rejects ambiguous Authorization header values on protected routes', async () => {
  let authorizeCalls = 0;
  let createOrgCalls = 0;
  const dispatchCreateOrgRequest = (authorizationHeaderValue) =>
    dispatchApiRoute({
      pathname: '/platform/orgs',
      method: 'POST',
      requestId: 'req-ambiguous-authorization',
      headers: {
        authorization: authorizationHeaderValue
      },
      body: {
        org_name: '组织 Ambiguous Authorization',
        initial_owner_phone: '13800000066'
      },
      handlers: {
        platformCreateOrg: async () => {
          createOrgCalls += 1;
          return {
            ok: true
          };
        },
        authorizeRoute: async () => {
          authorizeCalls += 1;
          return {
            user_id: 'platform-operator',
            session_id: 'platform-session',
            entry_domain: 'platform'
          };
        }
      }
    });

  const arrayHeaderResponse = await dispatchCreateOrgRequest([
    'Bearer fake-access-token-a',
    'Bearer fake-access-token-b'
  ]);
  assert.equal(arrayHeaderResponse.status, 401);
  assert.equal(
    JSON.parse(arrayHeaderResponse.body).error_code,
    'AUTH-401-INVALID-ACCESS'
  );

  const commaHeaderResponse = await dispatchCreateOrgRequest(
    'Bearer fake-access-token-a, Bearer fake-access-token-b'
  );
  assert.equal(commaHeaderResponse.status, 401);
  assert.equal(
    JSON.parse(commaHeaderResponse.body).error_code,
    'AUTH-401-INVALID-ACCESS'
  );

  assert.equal(authorizeCalls, 0);
  assert.equal(createOrgCalls, 0);
});

test('dispatchApiRoute rejects non-header-safe Authorization header values on protected routes', async () => {
  let authorizeCalls = 0;
  let createOrgCalls = 0;

  const route = await dispatchApiRoute({
    pathname: '/platform/orgs',
    method: 'POST',
    requestId: 'req-invalid-authorization-header-char',
    headers: {
      authorization: 'Bearer 中文'
    },
    body: {
      org_name: '组织 Invalid Authorization Header',
      initial_owner_phone: '13800000066'
    },
    handlers: {
      platformCreateOrg: async () => {
        createOrgCalls += 1;
        return { ok: true };
      },
      authorizeRoute: async () => {
        authorizeCalls += 1;
        return {
          user_id: 'platform-operator',
          session_id: 'platform-session',
          entry_domain: 'platform'
        };
      }
    }
  });

  assert.equal(route.status, 401);
  assert.equal(
    JSON.parse(route.body).error_code,
    'AUTH-401-INVALID-ACCESS'
  );
  assert.equal(authorizeCalls, 0);
  assert.equal(createOrgCalls, 0);
});

test('dispatchApiRoute keeps default idempotency store isolated per handlers instance', async () => {
  let firstHandlersCalls = 0;
  let secondHandlersCalls = 0;
  const buildHandlers = (counterRef) => ({
    authPlatformMemberAdminProvisionUser: async (requestId) => {
      if (counterRef === 'first') {
        firstHandlersCalls += 1;
      } else {
        secondHandlersCalls += 1;
      }
      return {
        ok: true,
        request_id: requestId
      };
    },
    authorizeRoute: async () => ({
      user_id: 'operator-user',
      session_id: 'operator-session'
    })
  });
  const firstHandlers = buildHandlers('first');
  const secondHandlers = buildHandlers('second');

  const first = await dispatchApiRoute({
    pathname: '/auth/platform/member-admin/provision-user',
    method: 'POST',
    requestId: 'req-default-store-isolation-1',
    headers: {
      authorization: 'Bearer fake-token',
      'idempotency-key': 'idem-default-store-isolation-001'
    },
    body: {
      phone: '13800000067'
    },
    handlers: firstHandlers
  });
  const second = await dispatchApiRoute({
    pathname: '/auth/platform/member-admin/provision-user',
    method: 'POST',
    requestId: 'req-default-store-isolation-2',
    headers: {
      authorization: 'Bearer fake-token',
      'idempotency-key': 'idem-default-store-isolation-001'
    },
    body: {
      phone: '13800000067'
    },
    handlers: secondHandlers
  });

  assert.equal(first.status, 200);
  assert.equal(second.status, 200);
  assert.equal(firstHandlersCalls, 1);
  assert.equal(secondHandlersCalls, 1);
});

test('dispatchApiRoute emits idempotency degradation audit when idempotency store is unavailable', async () => {
  const idempotencyEvents = [];

  const route = await dispatchApiRoute({
    pathname: '/auth/platform/member-admin/provision-user',
    method: 'POST',
    requestId: 'req-idempotency-store-unavailable',
    headers: {
      authorization: 'Bearer fake-token',
      'idempotency-key': 'idem-store-unavailable-001'
    },
    body: {
      phone: '13800000051'
    },
    handlers: {
      authPlatformMemberAdminProvisionUser: async () => {
        assert.fail('should not execute when idempotency store is unavailable');
      },
      authorizeRoute: async () => ({
        user_id: 'operator-user',
        session_id: 'operator-session'
      }),
      recordAuthIdempotencyEvent: async (payload) => {
        idempotencyEvents.push(payload);
      },
      authIdempotencyStore: {
        claimOrRead: async () => {
          throw new Error('idempotency-store-down');
        },
        read: async () => null,
        resolve: async () => {},
        releasePending: async () => {}
      }
    }
  });

  assert.equal(route.status, 503);
  const payload = JSON.parse(route.body);
  assert.equal(payload.error_code, 'AUTH-503-IDEMPOTENCY-STORE-UNAVAILABLE');
  assert.equal(idempotencyEvents.length, 1);
  assert.equal(idempotencyEvents[0].outcome, 'store_unavailable');
  assert.equal(
    idempotencyEvents[0].metadata?.degradation_reason,
    'idempotency-store-unavailable'
  );
  assert.equal(
    idempotencyEvents[0].routeKey,
    'POST /auth/platform/member-admin/provision-user'
  );
  assert.equal(idempotencyEvents[0].requestId, 'req-idempotency-store-unavailable');
  assert.equal(idempotencyEvents[0].authorizationContext.user_id, 'operator-user');
});

test('dispatchApiRoute emits idempotency degradation audit when pending replay entry disappears unexpectedly', async () => {
  const idempotencyEvents = [];
  let claimCalls = 0;
  let readCalls = 0;

  const route = await dispatchApiRoute({
    pathname: '/auth/platform/member-admin/provision-user',
    method: 'POST',
    requestId: 'req-idempotency-pending-missing',
    headers: {
      authorization: 'Bearer fake-token',
      'idempotency-key': 'idem-pending-missing-001'
    },
    body: {
      phone: '13800000052'
    },
    handlers: {
      authPlatformMemberAdminProvisionUser: async () => {
        assert.fail('should not execute when replay remains pending');
      },
      authorizeRoute: async () => ({
        user_id: 'operator-user',
        session_id: 'operator-session'
      }),
      recordAuthIdempotencyEvent: async (payload) => {
        idempotencyEvents.push(payload);
      },
      authIdempotencyStore: {
        claimOrRead: async ({ requestHash }) => {
          claimCalls += 1;
          return {
            action: 'existing',
            entry: {
              state: 'pending',
              requestHash
            }
          };
        },
        read: async () => {
          readCalls += 1;
          return null;
        },
        resolve: async () => {},
        releasePending: async () => {}
      }
    }
  });

  assert.equal(route.status, 503);
  const payload = JSON.parse(route.body);
  assert.equal(payload.error_code, 'AUTH-503-IDEMPOTENCY-STORE-UNAVAILABLE');
  assert.equal(payload.degradation_reason, 'idempotency-store-unavailable');
  assert.equal(claimCalls, 1);
  assert.equal(readCalls, 1);
  assert.equal(idempotencyEvents.length, 1);
  assert.equal(idempotencyEvents[0].outcome, 'store_unavailable');
  assert.equal(
    idempotencyEvents[0].metadata?.degradation_reason,
    'idempotency-store-entry-missing'
  );
  assert.equal(idempotencyEvents[0].metadata?.idempotency_stage, 'wait-for-resolved');
  assert.equal(
    idempotencyEvents[0].routeKey,
    'POST /auth/platform/member-admin/provision-user'
  );
  assert.equal(idempotencyEvents[0].requestId, 'req-idempotency-pending-missing');
});

test('dispatchApiRoute emits idempotency degradation audit when replay remains pending until timeout', async () => {
  const idempotencyEvents = [];
  let claimCalls = 0;
  let readCalls = 0;
  let pendingRequestHash = '';
  const originalDateNow = Date.now;
  let dateNowCalls = 0;

  try {
    Date.now = () => {
      dateNowCalls += 1;
      if (dateNowCalls <= 2) {
        return 0;
      }
      return 6001;
    };

    const route = await dispatchApiRoute({
      pathname: '/auth/platform/member-admin/provision-user',
      method: 'POST',
      requestId: 'req-idempotency-pending-timeout',
      headers: {
        authorization: 'Bearer fake-token',
        'idempotency-key': 'idem-pending-timeout-001'
      },
      body: {
        phone: '13800000052'
      },
      handlers: {
        authPlatformMemberAdminProvisionUser: async () => {
          assert.fail('should not execute when replay remains pending');
        },
        authorizeRoute: async () => ({
          user_id: 'operator-user',
          session_id: 'operator-session'
        }),
        recordAuthIdempotencyEvent: async (payload) => {
          idempotencyEvents.push(payload);
        },
        authIdempotencyStore: {
          claimOrRead: async ({ requestHash }) => {
            claimCalls += 1;
            pendingRequestHash = requestHash;
            return {
              action: 'existing',
              entry: {
                state: 'pending',
                requestHash
              }
            };
          },
          read: async ({ scopeKey }) => {
            readCalls += 1;
            return {
              state: 'pending',
              requestHash: pendingRequestHash
            };
          },
          resolve: async () => {},
          releasePending: async () => {}
        }
      }
    });

    assert.equal(route.status, 503);
    const payload = JSON.parse(route.body);
    assert.equal(payload.error_code, 'AUTH-503-IDEMPOTENCY-PENDING-TIMEOUT');
    assert.equal(payload.degradation_reason, 'idempotency-pending-timeout');
    assert.equal(claimCalls, 1);
    assert.equal(readCalls, 1);
    assert.equal(idempotencyEvents.length, 1);
    assert.equal(idempotencyEvents[0].outcome, 'pending_timeout');
    assert.equal(
      idempotencyEvents[0].metadata?.degradation_reason,
      'idempotency-pending-timeout'
    );
    assert.equal(
      idempotencyEvents[0].routeKey,
      'POST /auth/platform/member-admin/provision-user'
    );
    assert.equal(idempotencyEvents[0].requestId, 'req-idempotency-pending-timeout');
  } finally {
    Date.now = originalDateNow;
  }
});

test('dispatchApiRoute emits idempotency degradation audit when resolved entry persistence fails after execution', async () => {
  const idempotencyEvents = [];
  let releaseCalls = 0;

  const route = await dispatchApiRoute({
    pathname: '/auth/platform/member-admin/provision-user',
    method: 'POST',
    requestId: 'req-idempotency-resolve-failed',
    headers: {
      authorization: 'Bearer fake-token',
      'idempotency-key': 'idem-resolve-failed-001'
    },
    body: {
      phone: '13800000053'
    },
    handlers: {
      authPlatformMemberAdminProvisionUser: async (requestId) => ({
        ok: true,
        request_id: requestId
      }),
      authorizeRoute: async () => ({
        user_id: 'operator-user',
        session_id: 'operator-session'
      }),
      recordAuthIdempotencyEvent: async (payload) => {
        idempotencyEvents.push(payload);
      },
      authIdempotencyStore: {
        claimOrRead: async () => ({ action: 'claimed' }),
        read: async () => null,
        resolve: async () => {
          throw new Error('resolve-failed');
        },
        releasePending: async () => {
          releaseCalls += 1;
          return true;
        }
      }
    }
  });

  assert.equal(route.status, 200);
  const payload = JSON.parse(route.body);
  assert.equal(payload.ok, true);
  assert.equal(releaseCalls, 1);
  assert.equal(idempotencyEvents.length, 1);
  assert.equal(idempotencyEvents[0].outcome, 'store_unavailable');
  assert.equal(
    idempotencyEvents[0].metadata?.degradation_reason,
    'idempotency-store-unavailable'
  );
  assert.equal(idempotencyEvents[0].metadata?.idempotency_stage, 'resolve');
});

test('dispatchApiRoute emits idempotency degradation audit when releasePending fails for non-cacheable response', async () => {
  const idempotencyEvents = [];
  let resolveCalls = 0;

  const route = await dispatchApiRoute({
    pathname: '/platform/orgs',
    method: 'POST',
    requestId: 'req-idempotency-release-failed',
    headers: {
      authorization: 'Bearer fake-token',
      'idempotency-key': 'idem-release-failed-001'
    },
    body: {
      org_name: 'Neweast',
      initial_owner_phone: '13800000054'
    },
    handlers: {
      platformCreateOrg: async () => {
        throw new AuthProblemError({
          status: 400,
          title: 'Bad Request',
          detail: 'payload invalid',
          errorCode: 'ORG-400-INVALID-PAYLOAD'
        });
      },
      authorizeRoute: async () => ({
        user_id: 'operator-user',
        session_id: 'operator-session',
        entry_domain: 'platform'
      }),
      recordAuthIdempotencyEvent: async (payload) => {
        idempotencyEvents.push(payload);
      },
      authIdempotencyStore: {
        claimOrRead: async () => ({ action: 'claimed' }),
        read: async () => null,
        resolve: async () => {
          resolveCalls += 1;
          return true;
        },
        releasePending: async () => {
          throw new Error('release-failed');
        }
      }
    }
  });

  assert.equal(route.status, 400);
  const payload = JSON.parse(route.body);
  assert.equal(payload.error_code, 'ORG-400-INVALID-PAYLOAD');
  assert.equal(resolveCalls, 0);
  assert.equal(idempotencyEvents.length, 1);
  assert.equal(idempotencyEvents[0].outcome, 'store_unavailable');
  assert.equal(
    idempotencyEvents[0].metadata?.degradation_reason,
    'idempotency-store-unavailable'
  );
  assert.equal(idempotencyEvents[0].metadata?.idempotency_stage, 'release-pending');
});

test('dispatchApiRoute fails closed when resolved idempotency replay entry is corrupted', async () => {
  const idempotencyEvents = [];

  const route = await dispatchApiRoute({
    pathname: '/auth/platform/member-admin/provision-user',
    method: 'POST',
    requestId: 'req-idempotency-corrupted-replay',
    headers: {
      authorization: 'Bearer fake-token',
      'idempotency-key': 'idem-corrupted-replay-001'
    },
    body: {
      phone: '13800000055'
    },
    handlers: {
      authPlatformMemberAdminProvisionUser: async () => {
        assert.fail('should not execute when resolved replay entry exists');
      },
      authorizeRoute: async () => ({
        user_id: 'operator-user',
        session_id: 'operator-session'
      }),
      recordAuthIdempotencyEvent: async (payload) => {
        idempotencyEvents.push(payload);
      },
      authIdempotencyStore: {
        claimOrRead: async ({ requestHash }) => ({
          action: 'existing',
          entry: {
            state: 'resolved',
            requestHash,
            response: {
              status: 'nan',
              headers: { 'content-type': 'application/json' },
              body: JSON.stringify({ ok: true })
            }
          }
        }),
        read: async () => null,
        resolve: async () => true,
        releasePending: async () => true
      }
    }
  });

  assert.equal(route.status, 503);
  const payload = JSON.parse(route.body);
  assert.equal(payload.error_code, 'AUTH-503-IDEMPOTENCY-STORE-UNAVAILABLE');
  assert.equal(idempotencyEvents.length, 1);
  assert.equal(idempotencyEvents[0].outcome, 'store_unavailable');
  assert.equal(
    idempotencyEvents[0].metadata?.degradation_reason,
    'idempotency-store-corrupted-response'
  );
  assert.equal(idempotencyEvents[0].metadata?.idempotency_stage, 'replay');
});

test('dispatchApiRoute fails closed when existing idempotency entry is corrupted', async () => {
  const idempotencyEvents = [];

  const route = await dispatchApiRoute({
    pathname: '/auth/platform/member-admin/provision-user',
    method: 'POST',
    requestId: 'req-idempotency-corrupted-existing-entry',
    headers: {
      authorization: 'Bearer fake-token',
      'idempotency-key': 'idem-corrupted-existing-entry-001'
    },
    body: {
      phone: '13800000056'
    },
    handlers: {
      authPlatformMemberAdminProvisionUser: async () => {
        assert.fail('should not execute when existing replay entry is corrupted');
      },
      authorizeRoute: async () => ({
        user_id: 'operator-user',
        session_id: 'operator-session'
      }),
      recordAuthIdempotencyEvent: async (payload) => {
        idempotencyEvents.push(payload);
      },
      authIdempotencyStore: {
        claimOrRead: async () => ({
          action: 'existing',
          entry: null
        }),
        read: async () => null,
        resolve: async () => true,
        releasePending: async () => true
      }
    }
  });

  assert.equal(route.status, 503);
  const payload = JSON.parse(route.body);
  assert.equal(payload.error_code, 'AUTH-503-IDEMPOTENCY-STORE-UNAVAILABLE');
  assert.equal(payload.degradation_reason, 'idempotency-store-unavailable');
  assert.equal(idempotencyEvents.length, 1);
  assert.equal(idempotencyEvents[0].outcome, 'store_unavailable');
  assert.equal(
    idempotencyEvents[0].metadata?.degradation_reason,
    'idempotency-store-corrupted-entry'
  );
  assert.equal(idempotencyEvents[0].metadata?.idempotency_stage, 'claim-or-read');
});

test('dispatchApiRoute fails closed when existing idempotency entry has invalid request hash', async () => {
  const idempotencyEvents = [];

  const route = await dispatchApiRoute({
    pathname: '/auth/platform/member-admin/provision-user',
    method: 'POST',
    requestId: 'req-idempotency-corrupted-existing-entry-request-hash',
    headers: {
      authorization: 'Bearer fake-token',
      'idempotency-key': 'idem-corrupted-existing-entry-request-hash-001'
    },
    body: {
      phone: '13800000076'
    },
    handlers: {
      authPlatformMemberAdminProvisionUser: async () => {
        assert.fail('should not execute when existing replay entry request hash is corrupted');
      },
      authorizeRoute: async () => ({
        user_id: 'operator-user',
        session_id: 'operator-session'
      }),
      recordAuthIdempotencyEvent: async (payload) => {
        idempotencyEvents.push(payload);
      },
      authIdempotencyStore: {
        claimOrRead: async () => ({
          action: 'existing',
          entry: {
            state: 'pending',
            requestHash: ''
          }
        }),
        read: async () => null,
        resolve: async () => true,
        releasePending: async () => true
      }
    }
  });

  assert.equal(route.status, 503);
  const payload = JSON.parse(route.body);
  assert.equal(payload.error_code, 'AUTH-503-IDEMPOTENCY-STORE-UNAVAILABLE');
  assert.equal(payload.degradation_reason, 'idempotency-store-unavailable');
  assert.equal(idempotencyEvents.length, 1);
  assert.equal(idempotencyEvents[0].outcome, 'store_unavailable');
  assert.equal(
    idempotencyEvents[0].metadata?.degradation_reason,
    'idempotency-store-corrupted-entry'
  );
  assert.equal(idempotencyEvents[0].metadata?.idempotency_stage, 'claim-or-read');
});

test('dispatchApiRoute fails closed when pending replay entry mutates to corrupted state during wait', async () => {
  const idempotencyEvents = [];
  let pendingRequestHash = '';

  const route = await dispatchApiRoute({
    pathname: '/auth/platform/member-admin/provision-user',
    method: 'POST',
    requestId: 'req-idempotency-corrupted-entry-after-wait',
    headers: {
      authorization: 'Bearer fake-token',
      'idempotency-key': 'idem-corrupted-entry-after-wait-001'
    },
    body: {
      phone: '13800000057'
    },
    handlers: {
      authPlatformMemberAdminProvisionUser: async () => {
        assert.fail('should not execute when pending replay entry becomes corrupted');
      },
      authorizeRoute: async () => ({
        user_id: 'operator-user',
        session_id: 'operator-session'
      }),
      recordAuthIdempotencyEvent: async (payload) => {
        idempotencyEvents.push(payload);
      },
      authIdempotencyStore: {
        claimOrRead: async ({ requestHash }) => {
          pendingRequestHash = requestHash;
          return {
            action: 'existing',
            entry: {
              state: 'pending',
              requestHash
            }
          };
        },
        read: async () => ({
          state: 'corrupted-state',
          requestHash: pendingRequestHash
        }),
        resolve: async () => true,
        releasePending: async () => true
      }
    }
  });

  assert.equal(route.status, 503);
  const payload = JSON.parse(route.body);
  assert.equal(payload.error_code, 'AUTH-503-IDEMPOTENCY-STORE-UNAVAILABLE');
  assert.equal(payload.degradation_reason, 'idempotency-store-unavailable');
  assert.equal(idempotencyEvents.length, 1);
  assert.equal(idempotencyEvents[0].outcome, 'store_unavailable');
  assert.equal(
    idempotencyEvents[0].metadata?.degradation_reason,
    'idempotency-store-corrupted-entry'
  );
  assert.equal(
    idempotencyEvents[0].metadata?.idempotency_stage,
    'wait-for-resolved'
  );
});

test('dispatchApiRoute fails closed when pending replay entry request hash is corrupted during wait', async () => {
  const idempotencyEvents = [];
  let pendingRequestHash = '';

  const route = await dispatchApiRoute({
    pathname: '/auth/platform/member-admin/provision-user',
    method: 'POST',
    requestId: 'req-idempotency-corrupted-entry-request-hash-after-wait',
    headers: {
      authorization: 'Bearer fake-token',
      'idempotency-key': 'idem-corrupted-entry-request-hash-after-wait-001'
    },
    body: {
      phone: '13800000077'
    },
    handlers: {
      authPlatformMemberAdminProvisionUser: async () => {
        assert.fail('should not execute when pending replay request hash becomes corrupted');
      },
      authorizeRoute: async () => ({
        user_id: 'operator-user',
        session_id: 'operator-session'
      }),
      recordAuthIdempotencyEvent: async (payload) => {
        idempotencyEvents.push(payload);
      },
      authIdempotencyStore: {
        claimOrRead: async ({ requestHash }) => {
          pendingRequestHash = requestHash;
          return {
            action: 'existing',
            entry: {
              state: 'pending',
              requestHash
            }
          };
        },
        read: async () => ({
          state: 'pending',
          requestHash: ''
        }),
        resolve: async () => true,
        releasePending: async () => true
      }
    }
  });

  assert.equal(route.status, 503);
  const payload = JSON.parse(route.body);
  assert.equal(payload.error_code, 'AUTH-503-IDEMPOTENCY-STORE-UNAVAILABLE');
  assert.equal(payload.degradation_reason, 'idempotency-store-unavailable');
  assert.equal(idempotencyEvents.length, 1);
  assert.equal(idempotencyEvents[0].outcome, 'store_unavailable');
  assert.equal(
    idempotencyEvents[0].metadata?.degradation_reason,
    'idempotency-store-corrupted-entry'
  );
  assert.equal(
    idempotencyEvents[0].metadata?.idempotency_stage,
    'wait-for-resolved'
  );
  assert.equal(pendingRequestHash.length > 0, true);
});

test('dispatchApiRoute does not persist idempotency replay cache for retryable 5xx responses', async () => {
  let calls = 0;
  const dispatchProvisionRequest = () =>
    dispatchApiRoute({
      pathname: '/auth/platform/member-admin/provision-user',
      method: 'POST',
      requestId: `req-idempotency-5xx-${calls + 1}`,
      headers: {
        authorization: 'Bearer fake-token',
        'idempotency-key': 'idem-platform-retryable-5xx'
      },
      body: {
        phone: '13800000001'
      },
      handlers: {
        authPlatformMemberAdminProvisionUser: async (requestId) => {
          calls += 1;
          if (calls === 1) {
            throw new AuthProblemError({
              status: 503,
              title: 'Service Unavailable',
              detail: 'temporary dependency outage',
              errorCode: 'AUTH-503-PROVISION-CONFIG-UNAVAILABLE',
              extensions: {
                retryable: true,
                degradation_reason: 'default-password-config-unavailable'
              }
            });
          }
          return {
            ok: true,
            request_id: requestId
          };
        },
        authorizeRoute: async () => ({
          user_id: 'operator-user',
          session_id: 'operator-session'
        })
      }
    });

  const first = await dispatchProvisionRequest();
  assert.equal(first.status, 503);

  const second = await dispatchProvisionRequest();
  assert.equal(second.status, 200);
  assert.equal(calls, 2);
});

test('dispatchApiRoute keeps legacy auth idempotency scope at session level', async () => {
  let executionCalls = 0;
  let authorizeCalls = 0;
  const dispatchProvisionRequest = () =>
    dispatchApiRoute({
      pathname: '/auth/platform/member-admin/provision-user',
      method: 'POST',
      requestId: `req-idempotency-session-scope-${authorizeCalls + 1}`,
      headers: {
        authorization: 'Bearer fake-token',
        'idempotency-key': 'idem-platform-session-scope-001'
      },
      body: {
        phone: '13800000009'
      },
      handlers: {
        authPlatformMemberAdminProvisionUser: async (requestId) => {
          executionCalls += 1;
          return {
            ok: true,
            call_no: executionCalls,
            request_id: requestId
          };
        },
        authorizeRoute: async () => {
          authorizeCalls += 1;
          return {
            user_id: 'operator-user',
            session_id: `operator-session-${authorizeCalls}`
          };
        }
      }
    });

  const first = await dispatchProvisionRequest();
  const second = await dispatchProvisionRequest();

  assert.equal(first.status, 200);
  assert.equal(second.status, 200);
  assert.equal(executionCalls, 2);
  assert.equal(authorizeCalls, 2);

  const firstPayload = JSON.parse(first.body);
  const secondPayload = JSON.parse(second.body);
  assert.equal(firstPayload.call_no, 1);
  assert.equal(secondPayload.call_no, 2);
});

test('dispatchApiRoute preserves legacy auth idempotency reservation for non-5xx responses', async () => {
  let executionCalls = 0;
  const handlers = {
    authReplacePlatformRoleFacts: async () => {
      executionCalls += 1;
      throw new AuthProblemError({
        status: 400,
        title: 'Bad Request',
        detail: 'legacy payload rejected',
        errorCode: 'AUTH-400-INVALID-PAYLOAD'
      });
    },
    authorizeRoute: async () => ({
      user_id: 'operator-user',
      session_id: 'operator-session',
      entry_domain: 'platform'
    })
  };
  const dispatchReplaceRoleFacts = ({ body, requestId }) =>
    dispatchApiRoute({
      pathname: '/auth/platform/role-facts/replace',
      method: 'POST',
      requestId,
      headers: {
        authorization: 'Bearer fake-token',
        'idempotency-key': 'idem-legacy-reservation-400'
      },
      body,
      handlers
    });

  const first = await dispatchReplaceRoleFacts({
    requestId: 'req-legacy-idem-reservation-1',
    body: {
      user_id: 'target-user-a',
      roles: []
    }
  });
  const second = await dispatchReplaceRoleFacts({
    requestId: 'req-legacy-idem-reservation-2',
    body: {
      user_id: 'target-user-b',
      roles: [{ role_id: 'platform.member_admin' }]
    }
  });

  assert.equal(first.status, 400);
  assert.equal(second.status, 409);
  assert.equal(JSON.parse(second.body).error_code, 'AUTH-409-IDEMPOTENCY-CONFLICT');
  assert.equal(executionCalls, 1);
});

test('dispatchApiRoute returns empty body for HEAD authorization failures', async () => {
  let healthCalls = 0;
  const customRouteDefinitions = [
    {
      method: 'GET',
      path: '/health',
      access: 'protected',
      permission_code: 'auth.session.logout',
      scope: 'session'
    }
  ];
  const routeDeclarationLookup = resolveRouteDeclarationLookup({
    routeDefinitions: customRouteDefinitions
  });

  const route = await dispatchApiRoute({
    pathname: '/health',
    method: 'HEAD',
    headers: {
      authorization: 'Bearer fake-access-token'
    },
    requestId: 'req-head-forbidden',
    handlers: {
      health: async () => {
        healthCalls += 1;
        return { ok: true };
      },
      authorizeRoute: async () => {
        throw new AuthProblemError({
          status: 403,
          title: 'Forbidden',
          detail: '当前操作无权限',
          errorCode: 'AUTH-403-FORBIDDEN'
        });
      }
    },
    routeDefinitions: customRouteDefinitions,
    routeDeclarationLookup
  });

  assert.equal(route.status, 403);
  assert.equal(route.body, '');
  assert.equal(healthCalls, 0);
});

test('dispatchApiRoute honors injected routeDefinitions as authorization source', async () => {
  let authorizeRouteCalls = 0;
  const customRouteDefinitions = [
    {
      method: 'GET',
      path: '/health',
      access: 'protected',
      permission_code: 'auth.session.logout',
      scope: 'session'
    }
  ];
  const routeDeclarationLookup = resolveRouteDeclarationLookup({
    routeDefinitions: customRouteDefinitions
  });

  const route = await dispatchApiRoute({
    pathname: '/health',
    method: 'GET',
    headers: {
      authorization: 'Bearer fake-access-token'
    },
    requestId: 'req-route-def-source',
    handlers: {
      health: async () => ({ ok: true }),
      authorizeRoute: async () => {
        authorizeRouteCalls += 1;
      }
    },
    routeDefinitions: customRouteDefinitions,
    routeDeclarationLookup
  });

  assert.equal(route.status, 200);
  assert.equal(authorizeRouteCalls, 1);
});

test('dispatchApiRoute ignores injected declaration lookup when it conflicts with routeDefinitions', async () => {
  let authorizeRouteCalls = 0;
  const protectedRouteDefinitions = [
    {
      method: 'GET',
      path: '/health',
      access: 'protected',
      permission_code: 'auth.session.logout',
      scope: 'session'
    }
  ];
  const injectedRouteDeclarationLookup = {
    routeDefinitions: protectedRouteDefinitions,
    routeDefinitionMap: new Map([
      [
        'GET /health',
        {
          method: 'GET',
          path: '/health',
          access: 'public',
          permission_code: '',
          scope: 'public'
        }
      ]
    ]),
    declaredRoutePaths: new Set(['/health'])
  };

  const route = await dispatchApiRoute({
    pathname: '/health',
    method: 'GET',
    headers: {
      authorization: 'Bearer fake-access-token'
    },
    requestId: 'req-route-def-bypass-attempt',
    handlers: {
      health: async () => ({ ok: true, bypass: true }),
      authorizeRoute: async () => {
        authorizeRouteCalls += 1;
        throw new AuthProblemError({
          status: 403,
          title: 'Forbidden',
          detail: '当前操作无权限',
          errorCode: 'AUTH-403-FORBIDDEN'
        });
      }
    },
    routeDefinitions: protectedRouteDefinitions,
    routeDeclarationLookup: injectedRouteDeclarationLookup
  });

  assert.equal(authorizeRouteCalls, 1);
  assert.equal(route.status, 403);
  assert.equal(JSON.parse(route.body).error_code, 'AUTH-403-FORBIDDEN');
});

test('handleApiRoute ignores injected declaration lookup when it conflicts with routeDefinitions', async () => {
  let authorizeRouteCalls = 0;
  const protectedRouteDefinitions = [
    {
      method: 'GET',
      path: '/health',
      access: 'protected',
      permission_code: 'auth.session.logout',
      scope: 'session'
    }
  ];
  const injectedRouteDeclarationLookup = {
    routeDefinitions: protectedRouteDefinitions,
    routeDefinitionMap: new Map([
      [
        'GET /health',
        {
          method: 'GET',
          path: '/health',
          access: 'public',
          permission_code: '',
          scope: 'public'
        }
      ]
    ]),
    declaredRoutePaths: new Set(['/health'])
  };

  const route = await handleApiRoute(
    {
      pathname: '/health',
      method: 'GET',
      headers: {
        authorization: 'Bearer fake-access-token'
      }
    },
    readConfig({ ALLOW_MOCK_BACKENDS: 'true' }),
    {
      dependencyProbe,
      handlers: {
        health: async () => ({ ok: true, bypass: true }),
        authorizeRoute: async () => {
          authorizeRouteCalls += 1;
          throw new AuthProblemError({
            status: 403,
            title: 'Forbidden',
            detail: '当前操作无权限',
            errorCode: 'AUTH-403-FORBIDDEN'
          });
        }
      },
      routeDefinitions: protectedRouteDefinitions,
      routeDeclarationLookup: injectedRouteDeclarationLookup,
      validateRouteDefinitions: false
    }
  );

  assert.equal(authorizeRouteCalls, 1);
  assert.equal(route.status, 403);
  assert.equal(JSON.parse(route.body).error_code, 'AUTH-403-FORBIDDEN');
});

test('dispatchApiRoute passes authorizeRoute context as object payload', async () => {
  const customRouteDefinitions = [
    {
      method: 'GET',
      path: '/health',
      access: 'protected',
      permission_code: 'auth.session.logout',
      scope: 'session'
    }
  ];
  const routeDeclarationLookup = resolveRouteDeclarationLookup({
    routeDefinitions: customRouteDefinitions
  });
  let authorizeRoutePayload = null;

  const route = await dispatchApiRoute({
    pathname: '/health',
    method: 'GET',
    headers: {
      authorization: 'Bearer fake-access-token'
    },
    requestId: 'req-authorize-signature',
    handlers: {
      health: async () => ({ ok: true }),
      authorizeRoute: async (payload) => {
        authorizeRoutePayload = payload;
      }
    },
    routeDefinitions: customRouteDefinitions,
    routeDeclarationLookup
  });

  assert.equal(route.status, 200);
  assert.deepEqual(authorizeRoutePayload, {
    requestId: 'req-authorize-signature',
    authorization: 'Bearer fake-access-token',
    permissionCode: 'auth.session.logout',
    scope: 'session'
  });
});

test('dispatchApiRoute returns structured 500 when authorizeRoute handler is missing', async () => {
  const customRouteDefinitions = [
    {
      method: 'GET',
      path: '/health',
      access: 'protected',
      permission_code: 'auth.session.logout',
      scope: 'session'
    }
  ];
  const routeDeclarationLookup = resolveRouteDeclarationLookup({
    routeDefinitions: customRouteDefinitions
  });

  const route = await dispatchApiRoute({
    pathname: '/health',
    method: 'GET',
    headers: { authorization: 'Bearer fake-token' },
    requestId: 'req-no-authorize-handler',
    handlers: {
      health: async () => ({ ok: true })
    },
    routeDefinitions: customRouteDefinitions,
    routeDeclarationLookup
  });

  assert.equal(route.status, 500);
  const body = JSON.parse(route.body);
  assert.equal(body.error_code, 'AUTH-500-AUTHORIZE-HANDLER-MISSING');
  assert.equal(body.request_id, 'req-no-authorize-handler');
});

test('handleApiRoute fails fast when authService lacks authorizeRoute capability for protected routes', async () => {
  const customRouteDefinitions = [
    {
      method: 'POST',
      path: '/auth/logout',
      access: 'protected',
      permission_code: 'auth.session.logout',
      scope: 'session'
    }
  ];

  await assert.rejects(
    () =>
      handleApiRoute(
        {
          pathname: '/auth/logout',
          method: 'POST',
          headers: {
            authorization: 'Bearer fake-access-token'
          },
          body: {}
        },
        readConfig({ ALLOW_MOCK_BACKENDS: 'true' }),
        {
          dependencyProbe,
          authService: {
            logout: async () => ({ ok: true })
          },
          routeDefinitions: customRouteDefinitions,
          validateRouteDefinitions: false
        }
      ),
    /Route authorization preflight failed: missing authorizeRoute handler for protected routes: POST \/auth\/logout/
  );
});

test('createServer fails fast when protected routes exist but authService lacks authorizeRoute capability', () => {
  assert.throws(
    () =>
      createServer(readConfig({ ALLOW_MOCK_BACKENDS: 'true' }), {
        dependencyProbe,
        authService: {
          logout: async () => ({ ok: true })
        }
      }),
    /Route authorization preflight failed: missing authorizeRoute handler for protected routes:/
  );
});

test('createServer fails fast when route declarations are incomplete', () => {
  assert.throws(
    () =>
      createServer(readConfig({ ALLOW_MOCK_BACKENDS: 'true' }), {
        dependencyProbe,
        routeDefinitions: [
          {
            method: 'GET',
            path: '/health',
            access: 'public',
            permission_code: '',
            scope: 'public'
          }
        ]
      }),
    /executable routes missing declarations/
  );
});

test('resolveRouteDeclarationLookup reuses cached lookup for identical routeDefinitions source', () => {
  const customRouteDefinitions = [
    {
      method: 'GET',
      path: '/health',
      access: 'public',
      permission_code: '',
      scope: 'public'
    },
    {
      method: 'POST',
      path: '/auth/logout',
      access: 'protected',
      permission_code: 'auth.session.logout',
      scope: 'session'
    }
  ];

  const firstLookup = resolveRouteDeclarationLookup({
    routeDefinitions: customRouteDefinitions
  });
  const secondLookup = resolveRouteDeclarationLookup({
    routeDefinitions: customRouteDefinitions
  });

  assert.equal(firstLookup, secondLookup);
});

test('dispatchApiRoute resists lookup poisoning via resolved declaration cache object mutation attempts', async () => {
  let authorizeRouteCalls = 0;
  const protectedRouteDefinitions = [
    {
      method: 'GET',
      path: '/health',
      access: 'protected',
      permission_code: 'auth.session.logout',
      scope: 'session'
    }
  ];
  const routeDeclarationLookup = resolveRouteDeclarationLookup({
    routeDefinitions: protectedRouteDefinitions
  });

  if (routeDeclarationLookup.routeDefinitionMap instanceof Map) {
    routeDeclarationLookup.routeDefinitionMap.set('GET /health', {
      method: 'GET',
      path: '/health',
      access: 'public',
      permission_code: '',
      scope: 'public'
    });
  }
  if (routeDeclarationLookup.declaredRoutePaths instanceof Set) {
    routeDeclarationLookup.declaredRoutePaths.add('/health');
  }

  const route = await dispatchApiRoute({
    pathname: '/health',
    method: 'GET',
    headers: {
      authorization: 'Bearer fake-access-token'
    },
    requestId: 'req-route-declaration-lookup-poisoning',
    handlers: {
      health: async () => ({ ok: true, poisoned: true }),
      authorizeRoute: async () => {
        authorizeRouteCalls += 1;
        throw new AuthProblemError({
          status: 403,
          title: 'Forbidden',
          detail: '当前操作无权限',
          errorCode: 'AUTH-403-FORBIDDEN'
        });
      }
    },
    routeDefinitions: protectedRouteDefinitions,
    routeDeclarationLookup
  });

  assert.equal(authorizeRouteCalls, 1);
  assert.equal(route.status, 403);
  assert.equal(JSON.parse(route.body).error_code, 'AUTH-403-FORBIDDEN');
});

test('createServer uses immutable snapshot for custom routeDefinitions at startup', async () => {
  const customRouteDefinitions = cloneRouteDefinitions(ROUTE_DEFINITIONS);
  const protectedProbeRoute = customRouteDefinitions.find(
    (routeDefinition) =>
      routeDefinition.method === 'GET'
      && routeDefinition.path === '/auth/tenant/member-admin/probe'
  );
  assert.ok(protectedProbeRoute);

  const harness = await startServer(
    { ALLOW_MOCK_BACKENDS: 'true' },
    {
      dependencyProbe,
      routeDefinitions: customRouteDefinitions
    }
  );

  protectedProbeRoute.access = 'public';
  protectedProbeRoute.permission_code = '';
  protectedProbeRoute.scope = 'public';

  try {
    const response = await fetch(`${harness.baseUrl}/auth/tenant/member-admin/probe`, {
      headers: {
        accept: 'application/problem+json'
      }
    });
    const payload = await response.json();

    assert.equal(response.status, 401);
    assert.equal(payload.error_code, 'AUTH-401-INVALID-ACCESS');
  } finally {
    await harness.close();
  }
});

test('handleApiRoute fails fast when route declarations are incomplete', async () => {
  await assert.rejects(
    () =>
      handleApiRoute(
        {
          pathname: '/health',
          method: 'GET',
          headers: {}
        },
        readConfig({ ALLOW_MOCK_BACKENDS: 'true' }),
        {
          dependencyProbe,
          routeDefinitions: [
            {
              method: 'GET',
              path: '/health',
              access: 'public',
              permission_code: '',
              scope: 'public'
            }
          ]
        }
      ),
    /executable routes missing declarations/
  );
});

test('handleApiRoute fails preflight when route declaration uses HEAD method', async () => {
  await assert.rejects(
    () =>
      handleApiRoute(
        {
          pathname: '/health',
          method: 'HEAD',
          headers: {}
        },
        readConfig({ ALLOW_MOCK_BACKENDS: 'true' }),
        {
          dependencyProbe,
          routeDefinitions: [
            {
              method: 'HEAD',
              path: '/health',
              access: 'public',
              permission_code: '',
              scope: 'public'
            }
          ]
        }
      ),
    /invalid route declaration fields: HEAD \/health \(invalid method: HEAD\)/
  );
});

test('handleApiRoute re-evaluates mutable route definitions for authorization preflight', async () => {
  const mutableRouteDefinitions = [
    {
      method: 'GET',
      path: '/health',
      access: 'public',
      permission_code: '',
      scope: 'public'
    }
  ];
  const handlers = {
    health: async () => ({ ok: true })
  };

  const firstRoute = await handleApiRoute(
    {
      pathname: '/health',
      method: 'GET',
      headers: {}
    },
    readConfig({ ALLOW_MOCK_BACKENDS: 'true' }),
    {
      dependencyProbe,
      handlers,
      routeDefinitions: mutableRouteDefinitions,
      validateRouteDefinitions: false
    }
  );
  assert.equal(firstRoute.status, 200);

  mutableRouteDefinitions[0].access = 'protected';
  mutableRouteDefinitions[0].permission_code = 'auth.session.logout';
  mutableRouteDefinitions[0].scope = 'session';

  await assert.rejects(
    () =>
      handleApiRoute(
        {
          pathname: '/health',
          method: 'GET',
          headers: {
            authorization: 'Bearer fake-access-token'
          }
        },
        readConfig({ ALLOW_MOCK_BACKENDS: 'true' }),
        {
          dependencyProbe,
          handlers,
          routeDefinitions: mutableRouteDefinitions,
          validateRouteDefinitions: false
        }
      ),
    /Route authorization preflight failed: missing authorizeRoute handler for protected routes: GET \/health/
  );
});

test('createServer wraps unexpected route errors as Problem Details 500', async () => {
  const originalConsoleError = console.error;
  const capturedConsoleErrors = [];
  console.error = (...args) => {
    capturedConsoleErrors.push(args);
  };

  const harness = await startServer(
    { ALLOW_MOCK_BACKENDS: 'true' },
    {
      authService: {
        authorizeRoute: async () => ({})
      }
    }
  );

  try {
    const response = await fetch(`${harness.baseUrl}/auth/login`, {
      method: 'POST',
      body: JSON.stringify({
        phone: '13800000000',
        password: 'password'
      }),
      signal: AbortSignal.timeout(3000),
      headers: {
        accept: 'application/problem+json',
        'content-type': 'application/json',
        'x-request-id': 'req-create-server-internal'
      }
    });
    const payload = await response.json();
    assert.equal(response.status, 500);
    assert.match(String(response.headers.get('content-type') || ''), /application\/problem\+json/i);
    assert.equal(payload.error_code, 'AUTH-500-INTERNAL');
    assert.equal(payload.request_id, 'req-create-server-internal');
    assert.ok(
      capturedConsoleErrors.some(
        ([message, details]) =>
          message === '[api] unhandled route error'
          && details?.request_id === 'req-create-server-internal'
          && String(details?.error_summary || '').includes(
            'authService.login is not a function'
          )
      )
    );
  } finally {
    console.error = originalConsoleError;
    await harness.close();
  }
});

test('createServer keeps request_id stable when unexpected route errors occur without x-request-id header', async () => {
  const originalConsoleError = console.error;
  const capturedConsoleErrors = [];
  console.error = (...args) => {
    capturedConsoleErrors.push(args);
  };

  const harness = await startServer(
    { ALLOW_MOCK_BACKENDS: 'true' },
    {
      authService: {
        authorizeRoute: async () => ({})
      }
    }
  );

  try {
    const response = await fetch(`${harness.baseUrl}/auth/login`, {
      method: 'POST',
      body: JSON.stringify({
        phone: '13800000000',
        password: 'password'
      }),
      signal: AbortSignal.timeout(3000),
      headers: {
        accept: 'application/problem+json',
        'content-type': 'application/json'
      }
    });
    const payload = await response.json();

    assert.equal(response.status, 500);
    assert.ok(payload.request_id);
    assert.ok(
      capturedConsoleErrors.some(
        ([message, details]) =>
          message === '[api] unhandled route error'
          && details?.request_id === payload.request_id
      )
    );
  } finally {
    console.error = originalConsoleError;
    await harness.close();
  }
});
