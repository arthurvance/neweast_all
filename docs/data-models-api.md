# Data Models（apps/api）

来源：

- SQL 迁移：`apps/api/migrations/*.sql`
- TypeORM 配置：`apps/api/typeorm.config.js`

## 1. 存储配置

- 数据库：MySQL
- 迁移目录：`apps/api/migrations/*.sql`
- 当前迁移编号区间：`0001` ~ `0025`

## 2. 已识别核心表

### 2.1 认证与会话

- `iam_users`（由历史迁移可见，基线表）
- `auth_sessions`
- `auth_refresh_tokens`
- `tenant_memberships`
- `tenant_membership_roles`
- `auth_user_tenant_membership_history`
- `platform_user_roles`

### 2.2 平台与租户权限

- `platform_roles`
- `platform_role_permission_grants`
- `tenant_role_permission_grants`
- `platform_users`
- `tenants`

### 2.3 集成治理

- `platform_integration_catalog`
- `platform_integration_contract_versions`
- `platform_integration_contract_compatibility_checks`
- `platform_integration_retry_recovery_queue`
- `platform_integration_freeze_control`

### 2.4 系统与审计

- `audit_events`
- `system_sensitive_configs`
- `schema_migrations`

## 3. 迁移演进要点（摘要）

- 0001：`schema_migrations` 基线
- 0002~0007：会话/刷新 token 与平台角色事实
- 0008~0017：组织与租户成员生命周期、权限授权、owner transfer 收敛
- 0018~0020：审计、敏感配置、权限授权最终清理
- 0021~0024：集成目录、契约版本、恢复队列、冻结控制
- 0025：平台用户表与状态字段完善

## 4. 与业务域映射

- `domains/platform/*`：
  - `platform_users`
  - `platform_roles`
  - `platform_role_permission_grants`
  - `platform_integration_*`
  - `system_sensitive_configs`
- `domains/tenant/*`：
  - `tenant_memberships`
  - `tenant_membership_roles`
  - `tenant_role_permission_grants`
- `modules/audit/*`：
  - `audit_events`

## 5. 建议维护策略

1. 新增业务能力时优先补迁移，再落服务与 handler。
2. 每次迁移后更新本文件与 API 合同文档中的关联实体。
3. 与路由/权限变更一起补充 `contracts` 与 `invariants` 测试。

