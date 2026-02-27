# API Contracts（apps/api）

来源：

- `apps/api/src/route-manifests/iam.route-manifest.js`
- `apps/api/src/route-manifests/tenant.route-manifest.js`
- `apps/api/src/route-manifests/platform.route-manifest.js`

## 1. 路由统计

- 总计：`66`
- 按访问级别：
  - `public`：8
  - `protected`：58
- 按 scope：
  - `public`：8
  - `session`：2
  - `tenant`：18
  - `platform`：38

## 2. IAM / Auth

- `GET /health`
- `GET /openapi.json`
- `GET /auth/ping`
- `POST /auth/login`
- `POST /auth/otp/send`
- `POST /auth/otp/login`
- `POST /auth/refresh`
- `POST /auth/logout`
- `POST /auth/change-password`
- `GET /smoke`

## 3. Tenant Domain

- `GET /auth/tenant/options`
- `POST /auth/tenant/switch`
- `GET /auth/tenant/user-management/probe`
- `POST /auth/tenant/user-management/provision-user`
- `GET /tenant/users`
- `POST /tenant/users`
- `GET /tenant/users/:membership_id`
- `PATCH /tenant/users/:membership_id/status`
- `PATCH /tenant/users/:membership_id/profile`
- `GET /tenant/users/:membership_id/roles`
- `PUT /tenant/users/:membership_id/roles`
- `GET /tenant/roles`
- `POST /tenant/roles`
- `PATCH /tenant/roles/:role_id`
- `DELETE /tenant/roles/:role_id`
- `GET /tenant/roles/:role_id/permissions`
- `PUT /tenant/roles/:role_id/permissions`
- `GET /tenant/audit/events`

## 4. Platform Domain

- `GET /auth/platform/options`
- `GET /auth/platform/user-management/probe`
- `POST /auth/platform/user-management/provision-user`
- `GET /platform/orgs`
- `POST /platform/orgs`
- `POST /platform/orgs/status`
- `POST /platform/orgs/owner-transfer`
- `GET /platform/audit/events`
- `GET /platform/system-configs/:config_key`
- `PUT /platform/system-configs/:config_key`
- `GET /platform/integrations`
- `GET /platform/integrations/:integration_id`
- `POST /platform/integrations`
- `PATCH /platform/integrations/:integration_id`
- `POST /platform/integrations/:integration_id/lifecycle`
- `GET /platform/integrations/:integration_id/contracts`
- `POST /platform/integrations/:integration_id/contracts`
- `POST /platform/integrations/:integration_id/contracts/compatibility-check`
- `POST /platform/integrations/:integration_id/contracts/consistency-check`
- `POST /platform/integrations/:integration_id/contracts/:contract_version/activate`
- `GET /platform/integrations/:integration_id/recovery/queue`
- `POST /platform/integrations/:integration_id/recovery/queue/:recovery_id/replay`
- `GET /platform/integrations/freeze`
- `POST /platform/integrations/freeze`
- `POST /platform/integrations/freeze/release`
- `GET /platform/roles`
- `POST /platform/roles`
- `PATCH /platform/roles/:role_id`
- `DELETE /platform/roles/:role_id`
- `GET /platform/roles/:role_id/permissions`
- `PUT /platform/roles/:role_id/permissions`
- `GET /platform/users`
- `GET /platform/users/:user_id`
- `POST /platform/users`
- `PATCH /platform/users/:user_id`
- `DELETE /platform/users/:user_id`
- `POST /platform/users/status`
- `POST /auth/platform/role-facts/replace`

## 5. 合同实现与消费关系

- 生产方：`apps/api`
- 消费方：
  - `apps/web/src/api/platform-management.mjs`
  - `apps/web/src/api/tenant-management.mjs`
- OpenAPI 文档入口：`GET /openapi.json`

## 6. 变更建议

当新增/修改路由时建议同步执行：

1. 更新 route manifests
2. 更新 `route-permissions` 声明
3. 更新前端 API SDK（`apps/web/src/api/*`）
4. 补充/更新对应测试（API + 前端调用链）

