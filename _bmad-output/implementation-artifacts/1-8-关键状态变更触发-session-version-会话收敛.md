# Story 1.8: 关键状态变更触发 session_version 会话收敛

Status: done
Story ID: 1.8
Story Key: 1-8-关键状态变更触发-session-version-会话收敛

<!-- Note: Validation is optional. Run validate-create-story for quality check before dev-story. -->

## Story

As a 平台安全治理方,
I want 在身份/权限关键状态变化后通过 session_version 使历史会话失效,
so that 系统可以确保权限变更即时收敛，避免旧会话继续越权访问。

## Acceptance Criteria

1. **Given** 用户角色、权限绑定或账户关键状态发生变更  
   **When** 变更事务提交成功  
   **Then** 系统递增对应主体的 session_version  
   **And** 该版本变化可在后续鉴权链路读取并生效

2. **Given** 用户持有变更前签发的旧会话 token  
   **When** 用户访问任一受保护接口  
   **Then** 服务端识别 session_version 不匹配并拒绝访问  
   **And** 返回统一未授权响应与标准错误语义

3. **Given** 关键状态变更后用户重新登录或刷新成功  
   **When** 新会话建立  
   **Then** 新会话绑定最新 session_version  
   **And** 后续访问按最新权限正常放行

## Tasks / Subtasks

- [x] 任务 1：固化关键状态变更的 `session_version` 收敛触发器（AC: 1, 2）
  - [x] 在存储层提供统一能力：关键状态变更时递增用户 `session_version`，并对当前活跃会话链路执行收敛（至少撤销 refresh 链路；按策略决定是否撤销 `auth_sessions`）
  - [x] 保持 MySQL 与内存存储行为一致：`apps/api/src/modules/auth/auth.store.mysql.js` 与 `apps/api/src/modules/auth/auth.store.memory.js` 同步实现
  - [x] 将已存在的改密链路（`updateUserPasswordAndRevokeSessions`）纳入统一策略，避免分叉实现

- [x] 任务 2：把角色/权限关键变更纳入会话收敛（AC: 1, 2）
  - [x] 在平台角色事实更新链路（`replacePlatformRolesAndSyncSnapshot`）中，当有效权限事实发生变化时触发目标用户 `session_version` 递增
  - [x] 避免无效抖动：当角色事实与权限快照无实质变化时不递增版本
  - [x] 明确处置语义：角色/权限关键变更后，旧 token 必须在受保护接口上被统一拒绝

- [x] 任务 3：强化鉴权链路对版本失配的统一拒绝（AC: 2）
  - [x] 保持 `access` 鉴权对 `session.sessionVersion` 与 `user.sessionVersion` 双重校验（当前在 `assertValidAccessSession` 已有基础）
  - [x] 保持 `refresh` 链路同样校验 `sv`，防止旧 refresh 继续换发新会话
  - [x] 对版本失配拒绝补齐可观测审计事件（含 `request_id`、`user_id`、`session_id`、`disposition_reason`）

- [x] 任务 4：确保新会话总是绑定最新版本（AC: 3）
  - [x] 登录签发与 refresh 轮换签发均使用当前 `user.sessionVersion` 写入 `sv`
  - [x] 关键状态变更后，旧 token 被拒绝且重新登录/刷新得到新 `sv`，保证行为可验证

- [x] 任务 5：缓存与收敛一致性（AC: 1, 2, 3）
  - [x] 关键状态变更后主动触发 `accessSessionCache` 失效（按 `sessionId` 或 `userId`）
  - [x] 避免“版本已变更但缓存仍放行”的短暂窗口

- [x] 任务 6：测试与门禁（AC: 1, 2, 3）
  - [x] 单元测试覆盖：`session_version` 递增、旧 access/refresh 拒绝、新会话签发 `sv` 正确
  - [x] 集成测试覆盖：关键状态变更前后访问受保护接口行为差异（旧 token 401、新 token 200）
  - [x] 回归门禁通过：`pnpm --dir apps/api check:route-permissions`、`pnpm --dir apps/api test`

### Review Follow-ups (AI)

- [x] [AI-Review][HIGH] 将 `replacePlatformRolesAndSyncSnapshot` 接入真实业务入口（HTTP/应用层调用链），避免能力仅在测试中可达，导致“角色事实变更 -> session_version 收敛”在运行时无法稳定触发。 [`apps/api/src/modules/auth/auth.routes.js:33`]
- [x] [AI-Review][MEDIUM] `replacePlatformRolesAndSyncSnapshot` 的“变更前权限”判断当前读取 `auth_user_domain_access` 快照，存在快照漂移时误判风险；改为基于变更前 role facts 聚合值进行对比更稳妥。 [`apps/api/src/modules/auth/auth.store.mysql.js:875`]
- [x] [AI-Review][MEDIUM] 补充“角色事实变更触发会话收敛”的 API/Express 集成用例，覆盖旧 access/refresh 401 与新登录 200 的端到端路径（当前新增集成用例仅覆盖改密触发）。 [`apps/api/test/auth.express.api.test.js:868`]
- [x] [AI-Review][LOW] 清理 Story 内上下文段落中的旧状态描述（`ready-for-dev`），与当前顶部状态保持一致。 [`_bmad-output/implementation-artifacts/1-8-关键状态变更触发-session-version-会话收敛.md:163`]
- [x] [AI-Review][HIGH] 修复“未知 `user_id` 仍返回 200 并可能写入孤儿角色事实”的 fail-open 风险：在 service 与 store 双层拦截未知用户，统一返回 `AUTH-400-INVALID-PAYLOAD`。 [`apps/api/src/modules/auth/auth.service.js:2061`]
- [x] [AI-Review][MEDIUM] 修复 `replacePlatformRolesAndSyncSnapshot` 在 `db-deadlock`/并发竞争时仍返回 200 的失败语义：统一映射为 `AUTH-503-PLATFORM-SNAPSHOT-DEGRADED`，并补齐 OpenAPI `503` 响应声明。 [`apps/api/src/modules/auth/auth.service.js:2089`]
- [x] [AI-Review][MEDIUM] 修复 Story File List 与 Git 实际改动不一致问题：补登记 route/openapi/server 相关实现与测试文件，保证审查对账可追溯。 [`_bmad-output/implementation-artifacts/1-8-关键状态变更触发-session-version-会话收敛.md:252`]
- [x] [AI-Review][HIGH] 修复 `replacePlatformRolesAndSyncSnapshot` 的“缺失 `roles` 默认清空角色”风险：缺少 `roles` 时必须判定为 `AUTH-400-INVALID-PAYLOAD`，防止误请求导致权限被意外清空。 [`apps/api/src/modules/auth/auth.service.js:2056`]
- [x] [AI-Review][MEDIUM] 修复 `roles` 条目缺失 `role_id` 时被静默忽略导致的隐式清空风险：对每个条目执行 `role_id/roleId` 必填校验并 fail-closed。 [`apps/api/src/modules/auth/auth.service.js:2060`]
- [x] [AI-Review][MEDIUM] 修复角色事实替换事务的并发漂移窗口：目标用户存在性查询改为 `FOR UPDATE` 行锁，避免事务期间用户行被并发修改。 [`apps/api/src/modules/auth/auth.store.mysql.js:878`]
- [x] [AI-Review][MEDIUM] 修复未知同步原因的 fail-open：`replacePlatformRolesAndSyncSnapshot` 对非 `ok` 且非已知原因统一降级为 `AUTH-503-PLATFORM-SNAPSHOT-DEGRADED`。 [`apps/api/src/modules/auth/auth.service.js:2098`]
- [x] [AI-Review][MEDIUM] 修复 `roles[].status` 校验依赖底层错误字符串的脆弱性：在 service 层显式白名单校验（`active/enabled/disabled`），避免不同 store 实现下错误语义漂移。 [`apps/api/src/modules/auth/auth.service.js:16`]
- [x] [AI-Review][MEDIUM] 补齐 API 层对非法 `roles[].status` 的负向契约用例，确保统一返回 `AUTH-400-INVALID-PAYLOAD`。 [`apps/api/test/auth.api.test.js:531`]
- [x] [AI-Review][MEDIUM] 补齐 Express + MySQL 集成路径对非法 `roles[].status` 的负向用例，防止仅单元覆盖导致回归漏检。 [`apps/api/test/auth.express.api.test.js:1142`]
- [x] [AI-Review][MEDIUM] 修复 `/auth/platform/role-facts/replace` 的 OpenAPI `413` 漏声明，确保与全局 JSON body-limit 运行时行为一致（`AUTH-413-PAYLOAD-TOO-LARGE`）。 [`apps/api/src/openapi.js:970`]
- [x] [AI-Review][MEDIUM] 补齐 API 层对角色事实替换降级语义的契约用例，覆盖 `db-deadlock -> AUTH-503-PLATFORM-SNAPSHOT-DEGRADED` 映射，防止路由层回归。 [`apps/api/test/auth.api.test.js:658`]
- [x] [AI-Review][LOW] 补齐 API + Express 对 `roles[]` 条目缺失 `role_id` 的负向用例，避免仅 service 层覆盖导致契约回归漏检。 [`apps/api/test/auth.api.test.js:597`]
- [x] [AI-Review][MEDIUM] 修复 `replacePlatformRolesAndSyncSnapshot` 未限制 `roles` 最大数量的问题：新增 `<=5` 上限校验，避免超量角色事实写入导致契约偏离与资源放大风险。 [`apps/api/src/modules/auth/auth.service.js:2053`]
- [x] [AI-Review][MEDIUM] 修复 `roles[].status` 的空白字符串/非字符串 fail-open：仅在字段缺失时默认 `active`，显式传入非法值一律 `AUTH-400-INVALID-PAYLOAD`。 [`apps/api/src/modules/auth/auth.service.js:2069`]
- [x] [AI-Review][LOW] 同步 OpenAPI 约束与回归断言：为 `/auth/platform/role-facts/replace` 的 `roles` 增加 `maxItems: 5`，防止文档与运行时语义漂移。 [`apps/api/src/openapi.js:1094`]
- [x] [AI-Review][MEDIUM] 修复 `roles` 上限校验与去重顺序不一致：改为按去重后唯一 `role_id` 数量判定 `<=5`，避免重复角色条目导致误拒绝。 [`apps/api/src/modules/auth/auth.service.js:2073`]
- [x] [AI-Review][MEDIUM] 修复 MySQL `replacePlatformRolesAndSyncSnapshot` 在 no-op 写入时返回 `synced=false` 的语义漂移，和内存存储统一为成功即 `synced=true`。 [`apps/api/src/modules/auth/auth.store.mysql.js:1026`]
- [x] [AI-Review][LOW] 强化 `/auth/platform/role-facts/replace` 入口的会话再校验：在 handler 侧提取 Bearer token 并在 service 内按 `authorizationContext` 二次校验，降低上下文漂移风险。 [`apps/api/src/modules/auth/auth.routes.js:142`]
- [x] [AI-Review][MEDIUM] 修复重复 `role_id` 的顺序依赖语义：`replacePlatformRolesAndSyncSnapshot` 对重复角色条目统一 `AUTH-400-INVALID-PAYLOAD`，避免“同一集合不同顺序导致结果漂移”。 [`apps/api/src/modules/auth/auth.service.js:2089`]
- [x] [AI-Review][MEDIUM] 修复 OpenAPI 与运行时约束缺口：`/auth/platform/role-facts/replace.roles` 显式声明 `uniqueItems: true` 并补充“`role_id` 必须唯一”描述，降低契约歧义。 [`apps/api/src/openapi.js:1101`]
- [x] [AI-Review][LOW] 补齐重复 `role_id` 的端到端负向覆盖：新增 API/Express/Service 回归断言，锁定重复条目统一 `AUTH-400-INVALID-PAYLOAD`。 [`apps/api/test/auth.api.test.js:731`]
- [x] [AI-Review][MEDIUM] 补齐角色事实替换审计中的“操作者 vs 目标用户”可追踪字段：`auth.platform_role_facts.updated` 增加 `actor_user_id` / `actor_session_id` / `target_user_id`，避免治理操作责任归因缺失。 [`apps/api/src/modules/auth/auth.service.js`]
- [x] [AI-Review][MEDIUM] 修复 `authorizationContext` 失配场景审计缺少主体定位信息：`auth.access.invalid` 在 `access-authorization-context-mismatch` 时补齐 `user_id` 与 `session_id`。 [`apps/api/src/modules/auth/auth.service.js`]
- [x] [AI-Review][LOW] 强化 `/auth/platform/role-facts/replace` OpenAPI 机器可校验约束：补充 `roles.uniqueItems: true` 与 `role_id` 非空模式约束，降低契约与运行时语义漂移。 [`apps/api/src/openapi.js`]
- [x] [AI-Review][HIGH] 修复 `replacePlatformRolesAndSyncSnapshot` 服务层“仅校验会话不校验权限”的越权窗口：当携带 `accessToken` 调用时强制复用 `platform.member_admin.operate` 鉴权判定，避免绕过路由预鉴权链路。 [`apps/api/src/modules/auth/auth.service.js:2090`]
- [x] [AI-Review][MEDIUM] 补齐 service 层无权限负向回归：调用者缺失 `platform.member_admin.operate` 时必须返回 `AUTH-403-FORBIDDEN` 并记录 `auth.route.forbidden`。 [`apps/api/test/auth.service.test.js:1907`]
- [x] [AI-Review][LOW] 补齐 Node HTTP API 路径的无权限负向契约覆盖：`POST /auth/platform/role-facts/replace` 在无操作权限时稳定返回 `403`。 [`apps/api/test/auth.api.test.js:471`]
- [x] [AI-Review][MEDIUM] 修复 `replacePlatformRolesAndSyncSnapshot` 在缺失 `accessToken` 时的 fail-open：服务层改为缺失令牌直接 `AUTH-401-INVALID-ACCESS`，并补齐 service 回归用例对齐 fail-closed 语义。 [`apps/api/src/modules/auth/auth.service.js:2076`]
- [x] [AI-Review][MEDIUM] 修复 `roles[].role_id` 超长输入的契约缺口：服务层新增 `<=64` 校验并补齐 `ER_DATA_TOO_LONG -> AUTH-400-INVALID-PAYLOAD` 映射，避免数据库约束错误上浮为 500。 [`apps/api/src/modules/auth/auth.service.js`]
- [x] [AI-Review][MEDIUM] 修复 `roles[].permission.*` 类型校验缺失导致的静默强转：`can_*` 字段仅接受布尔值，非法类型统一 `AUTH-400-INVALID-PAYLOAD`。 [`apps/api/src/modules/auth/auth.service.js`]
- [x] [AI-Review][LOW] 同步 OpenAPI 机器可校验约束：`PlatformRoleFact.role_id` 增加 `maxLength: 64`，并补齐 server 契约断言，降低文档与运行时语义漂移。 [`apps/api/src/openapi.js`]
- [x] [AI-Review][MEDIUM] 修复 `replacePlatformRolesAndSyncSnapshot` 对非字符串 `user_id` 的隐式 `String(...)` 强转 fail-open：`user_id` 必须为非空字符串并统一返回 `AUTH-400-INVALID-PAYLOAD`。 [`apps/api/src/modules/auth/auth.service.js:2139`]
- [x] [AI-Review][MEDIUM] 修复 `roles[].role_id/roleId` 的隐式强转：仅接受非空字符串，非字符串输入统一 fail-closed 并返回 `AUTH-400-INVALID-PAYLOAD`。 [`apps/api/src/modules/auth/auth.service.js:2151`]
- [x] [AI-Review][LOW] 补齐 OpenAPI 对 `ReplacePlatformRoleFactsRequest.user_id` 的机器可校验约束：新增 `minLength: 1` 与非空白 `pattern`，并补齐 server 契约回归断言。 [`apps/api/src/openapi.js:1098`]
- [x] [AI-Review][MEDIUM] 修复 `roles[].permission` 非对象（`string/array/null`）仍被接受的 fail-open：服务层显式要求 `permission`（若提供）必须为对象，非法类型统一 `AUTH-400-INVALID-PAYLOAD`。 [`apps/api/src/modules/auth/auth.service.js`]
- [x] [AI-Review][MEDIUM] 修复 `roles[]` 顶层 `can_*` 权限字段可绕过请求契约约束的问题：角色权限仅允许通过 `permission` 对象传入，顶层权限字段统一拒绝。 [`apps/api/src/modules/auth/auth.service.js`]
- [x] [AI-Review][LOW] 优化 `replacePlatformRolesAndSyncSnapshot` 重复鉴权开销：复用单次会话解析结果，避免同一请求二次 `resolveAuthorizedSession` 带来的额外查库与延迟。 [`apps/api/src/modules/auth/auth.service.js`]

## Dev Notes

### Developer Context（开发者必须先读）

- 现有基线已具备 `sv` 校验骨架：
  - `access` 鉴权在 `assertValidAccessSession` 中同时校验 `session.sessionVersion` 与 `user.sessionVersion`。
  - `refresh` 链路在 `invalidState` 判定中同样校验 `sessionVersion` 与 `user.sessionVersion`。
- 现有“改密”路径已递增 `session_version` 并撤销会话链路，但“角色/权限关键变更”尚未统一纳入该收敛机制。
- Story 1.8 的核心不是重写认证，而是把“关键状态变更 -> 版本收敛 -> 旧会话拒绝”收敛成统一机制，避免后续故事重复实现。

### Technical Requirements（实现硬约束）

- 关键状态变更触发：
  - 至少覆盖：密码变更、平台角色事实变更（权限并集结果变化）、后续用户状态/成员状态变更扩展点。
- 鉴权拒绝语义：
  - `access` 失配统一返回 `AUTH-401-INVALID-ACCESS`（Problem Details）。
  - `refresh` 失配保持 `AUTH-401-INVALID-REFRESH`（与既有 rotation/replay 语义兼容）。
- 版本绑定规则：
  - 新签发 `access/refresh` 的 `sv` 必须来自最新 `user.sessionVersion`。
- 一致性要求：
  - MySQL 与内存存储实现语义一致。
  - 关键收敛路径必须 fail-closed，不允许“版本不一致仍放行”。

### Architecture Compliance（架构对齐清单）

- 仅在 `modules/auth` 内落地会话收敛核心逻辑，不新增旁路鉴权实现。
- 保持 REST + OpenAPI + Problem Details 契约一致性。
- 关键身份/权限变更必须联动 `session_version`（架构硬约束）。
- 保持双域边界：`platform.*` 与 `tenant.*` 判定逻辑不因本故事被弱化。
- 审计与追踪字段必须可检索（`request_id` 至少可贯穿）。

### Library & Framework Requirements（库与框架要求）

- 版本基线（2026-02-15 核验）：
  - `@nestjs/core`: `11.1.13`
  - `react`: `19.2.4`
  - `vite`: `7.3.1`
  - `typeorm`: `0.3.28`
  - `mysql2`: `3.17.1`（项目范围 `^3.17.0`）
  - `ioredis`: `5.9.3`（项目当前 `5.9.2`）
- 运行时建议：
  - CI/生产优先对齐 Node `24.13.1`（Active LTS），避免 Current 版本漂移影响门禁稳定性。
- 安全提示（与本故事相关的环境卫生）：
  - `pnpm audit` 检出 `qs` 低危漏洞（CVE-2026-2391，`>=6.7.0 <=6.14.1`，修复 `>=6.14.2`）。
  - 建议在主仓加 `pnpm.overrides` 锁定 `qs >=6.14.2`（建议 `6.15.0`）。

### File Structure Requirements（建议变更落点）

- 认证核心：
  - `apps/api/src/modules/auth/auth.service.js`
  - `apps/api/src/modules/auth/auth.store.mysql.js`
  - `apps/api/src/modules/auth/auth.store.memory.js`
- 契约（如错误示例/字段调整）：
  - `apps/api/src/openapi.js`
- 测试：
  - `apps/api/test/auth.service.test.js`
  - `apps/api/test/auth.api.test.js`
  - `apps/api/test/auth.express.api.test.js`
  - `apps/api/test/auth.store.mysql.test.js`

### Testing Requirements（测试要求）

- 单元测试（必须）：
  - 关键状态变更触发 `session_version` 递增。
  - 变更后旧 `access_token` 访问受保护接口被拒绝（401）。
  - 变更后旧 `refresh_token` 换发被拒绝（401）。
  - 重新登录/刷新后新 token 的 `sv` 为最新值。
- 集成测试（必须）：
  - MySQL 场景验证 `users.session_version` 变更与受保护路由拒绝行为一致。
  - 角色事实变更后，历史会话不能继续访问受保护平台路由。
- 回归门禁（必须）：
  - `pnpm --dir apps/api check:route-permissions`
  - `pnpm --dir apps/api test`

### Previous Story Intelligence

- 来自 Story 1.7（refresh/replay）：
  - 已形成 `fail-closed`、rotation/replay 审计、双存储一致性实践。
  - 本故事应复用现有 `auth.service` 与 `auth.store.*` 结构，不做模块外扩。
- 来自 Story 1.6（双域边界）：
  - 平台权限快照与角色事实链路已复杂化，并发守卫与降级语义已建立。
  - 本故事要避免破坏 1.6 的 `platform snapshot` 稳定性，优先做最小侵入改造。

### Git Intelligence Summary

- 最近提交集中在 `apps/api/src/modules/auth/*`、`apps/api/src/openapi.js` 与 `apps/api/test/auth*.test.js`。
- 推断：Story 1.8 应继续沿该路径增量实现，避免重构目录与跨模块改造。

### Latest Tech Information（2026-02-15）

- Node.js：`v25.6.1`（Current），`v24.13.1`（Active LTS）
- MySQL 8.4：最新 LTS 小版本 `8.4.8`（2026-01-20）
- npm 安全：`qs` 漏洞 GHSA-w7fw-mjwx-w883 / CVE-2026-2391 已公开，修复版本已可用

### Project Context Reference

- 未发现 `**/project-context.md`。
- 本故事上下文依据：`epics.md`、`prd.md`、`architecture.md`、`ux-design-specification.md`、Story 1.6/1.7、当前代码基线。

### Story Completion Status

- Story 文档状态：`done`
- Completion Note：`CR 问题已完成修复并通过全量回归，故事满足完成标准`

### Project Structure Notes

- 当前认证收敛关键点：
  - token `sv` 写入：`auth.service` 登录/刷新签发路径
  - token `sv` 校验：`assertValidAccessSession` 与 `refresh` `invalidState`
  - 版本变更入口：`auth.store.*`（当前以改密为主）
- 实施原则：
  - 将“版本递增 + 会话收敛 + 缓存失效”打包成统一原语，供后续故事复用。

### References

- Story 1.8 需求与 AC  
  [Source: _bmad-output/planning-artifacts/epics.md#Story 1.8: 关键状态变更触发 session_version 会话收敛]
- FR30 / FR50 / FR79（会话收敛与权限即时生效）  
  [Source: _bmad-output/planning-artifacts/prd.md]
- 架构硬约束（`session_version`、Problem Details、门禁）  
  [Source: _bmad-output/planning-artifacts/architecture.md]
- UX 失败反馈与可恢复语义（一致性约束）  
  [Source: _bmad-output/planning-artifacts/ux-design-specification.md]
- 前序故事情报（Story 1.7）  
  [Source: _bmad-output/implementation-artifacts/1-7-refresh-rotation-重放识别与并发会话策略.md]
- 前序故事情报（Story 1.6）  
  [Source: _bmad-output/implementation-artifacts/1-6-双域权限边界与服务端租户最终判定.md]
- Node.js Releases  
  [Source: https://nodejs.org/dist/index.json]
- MySQL 8.4 Release Notes  
  [Source: https://dev.mysql.com/doc/relnotes/mysql/8.4/en/]
- GitHub Advisory（qs / CVE-2026-2391）  
  [Source: https://github.com/advisories/GHSA-w7fw-mjwx-w883]

## Dev Agent Record

### Agent Model Used

gpt-5-codex

### Debug Log References

- `cat _bmad-output/implementation-artifacts/sprint-status.yaml`
- `cat _bmad-output/planning-artifacts/epics.md`
- `cat _bmad-output/planning-artifacts/prd.md`
- `cat _bmad-output/planning-artifacts/architecture.md`
- `cat _bmad-output/planning-artifacts/ux-design-specification.md`
- `cat _bmad-output/implementation-artifacts/1-7-refresh-rotation-重放识别与并发会话策略.md`
- `cat _bmad-output/implementation-artifacts/1-6-双域权限边界与服务端租户最终判定.md`
- `git log --oneline -n 5`
- `git log -n 5 --name-status --pretty=format:'COMMIT %H%nAUTHOR %an%nDATE %ad%nSUBJECT %s%n' --date=iso`
- `pnpm view @nestjs/core version`
- `pnpm view react version`
- `pnpm view vite version`
- `pnpm view typeorm version`
- `pnpm view mysql2 version`
- `pnpm view ioredis version`
- `pnpm audit --prod`
- `rg -n "sessionVersion|session_version|AUTH-401-INVALID-ACCESS" apps/api/src apps/api/test -g '*.js'`
- `pnpm --dir apps/api exec node --test test/auth.store.mysql.test.js`
- `pnpm --dir apps/api exec node --test test/auth.service.test.js`
- `pnpm --dir apps/api exec node --test test/auth.api.test.js`
- `pnpm --dir apps/api exec node --test --test-force-exit test/auth.express.api.test.js`
- `pnpm --dir apps/api lint`
- `pnpm --dir apps/api check:route-permissions`
- `pnpm --dir apps/api test`

### Implementation Plan

- 统一会话收敛原语：在 `auth.store.memory.js` 与 `auth.store.mysql.js` 中抽象“递增 `session_version` + 收敛会话链路”。
- 关键变更触发点：`replacePlatformRolesAndSyncSnapshot` 按“有效权限事实变化”决定是否触发收敛，避免无效抖动。
- 鉴权一致语义：`auth.service.js` 为 access/refresh 版本失配补齐审计字段（`request_id`/`user_id`/`session_id`/`disposition_reason`）。
- 缓存一致性：新增服务层平台角色替换入口，在版本变化时主动失效 `accessSessionCache`。
- 覆盖与门禁：补齐 store/service/api/express 测试并执行 lint、路由声明校验与全量回归。

### Completion Notes List

- ✅ 在 `apps/api/src/modules/auth/auth.store.memory.js` 与 `apps/api/src/modules/auth/auth.store.mysql.js` 落地统一会话收敛原语，改密路径已接入统一策略。
- ✅ `replacePlatformRolesAndSyncSnapshot` 已实现“有效权限变化才递增版本”，并在变化时执行会话收敛；无变化时不递增版本。
- ✅ `apps/api/src/modules/auth/auth.service.js` 新增 access 失配审计事件与 refresh 版本失配语义，补齐 `request_id`/`user_id`/`session_id`/`disposition_reason` 可观测字段。
- ✅ 新增 `replacePlatformRolesAndSyncSnapshot` 服务入口并在版本变更后主动失效 `accessSessionCache`，避免缓存放行窗口。
- ✅ 测试补齐：`auth.store.mysql.test.js`、`auth.service.test.js`、`auth.api.test.js`、`auth.express.api.test.js` 新增/更新覆盖；门禁通过（`lint`、`check:route-permissions`、`pnpm --dir apps/api test`）。
- ✅ 修复未知 `user_id` 仍可进入角色事实替换链路的问题：service/store 双层 fail-closed 拦截，未知用户统一 `AUTH-400-INVALID-PAYLOAD`。
- ✅ 修复角色事实替换在死锁/并发竞争时 200 误成功语义：`db-deadlock` 与 `concurrent-role-facts-update` 统一映射 `AUTH-503-PLATFORM-SNAPSHOT-DEGRADED`，并补 OpenAPI `503` 文档。
- ✅ 补齐 Story File List 与 Git 对账遗漏项，确保评审记录与实际变更一致。
- ✅ 修复角色事实替换的请求载荷 fail-open：`roles` 字段缺失或条目缺少 `role_id` 均统一 `AUTH-400-INVALID-PAYLOAD`，避免误清空权限。
- ✅ 修复角色事实替换的未知同步状态 fail-open：非 `ok` 原因统一映射 `AUTH-503-PLATFORM-SNAPSHOT-DEGRADED`。
- ✅ 修复 MySQL 角色事实替换并发窗口：目标用户查询使用 `FOR UPDATE` 行锁；并新增 store/service/api/express 负向用例覆盖。
- ✅ 修复 `roles[].status` 校验脆弱性：service 层新增白名单校验，不再仅依赖 store 抛错字符串；并补齐 service/api/express 三层非法状态回归用例。
- ✅ 修复 `/auth/platform/role-facts/replace` OpenAPI 与运行时语义漂移：补齐 `413` 响应声明并新增断言，保证契约可测试。
- ✅ 补齐角色事实替换 `db-deadlock -> AUTH-503-PLATFORM-SNAPSHOT-DEGRADED` 的 API 契约回归用例，锁定服务到路由的错误码映射。
- ✅ 补齐 API + Express 对 `roles[]` 条目缺失 `role_id` 的负向契约用例，覆盖请求校验 fail-closed 回归场景。
- ✅ 修复角色事实替换输入边界缺口：新增 `roles` 数量上限（`<=5`）与空白/非字符串 `status` 的 fail-closed 校验，并补齐 service/api/express/store/openapi 全链路回归。
- ✅ 修复 `roles` 上限校验与去重顺序不一致：改为“去重后唯一角色数”判定上限，新增 API + service 回归覆盖重复条目场景。
- ✅ 修复 MySQL `replacePlatformRolesAndSyncSnapshot` 在 snapshot no-op 时 `synced=false` 的语义漂移，新增 store 回归用例锁定 `synced=true`。
- ✅ 为 `/auth/platform/role-facts/replace` 增加会话二次校验：handler 提取 access token，service 按 `authorizationContext` 执行一致性校验并补齐负向回归。
- ✅ 修复角色事实替换的重复条目歧义：服务层拒绝重复 `role_id`，并同步 OpenAPI `uniqueItems` 契约与 API/Express/Service 负向回归，避免顺序依赖行为回归。
- ✅ 执行九轮 CR 收敛：补齐角色事实替换审计的操作者追踪字段、修复 `authorizationContext` 失配审计的主体缺失，并增强 OpenAPI 对 `roles` 去重与 `role_id` 非空的机器可校验约束；定向与全量测试均通过。
- ✅ 执行十轮 CR 收敛：修复服务层角色事实替换在“有 token 但缺失权限校验”场景的越权窗口，并补齐 service + API 双路径无权限 `403` 回归用例；全量测试通过。
- ✅ 执行十一轮 CR 收敛：修复服务层 `replacePlatformRolesAndSyncSnapshot` 在缺失 `accessToken` 场景的 fail-open，统一改为缺失令牌即 `AUTH-401-INVALID-ACCESS`，并同步更新 service 相关负向用例与全量回归。
- ✅ 执行十二轮 CR 收敛：补齐 `role_id<=64` 与 `permission.can_*` 布尔类型硬校验，新增 `ER_DATA_TOO_LONG -> AUTH-400-INVALID-PAYLOAD` 映射，并同步 OpenAPI `maxLength` 与 API/Express/Service/Server 回归；全量测试通过。
- ✅ 执行十三轮 CR 收敛：修复 `replacePlatformRolesAndSyncSnapshot` 对非字符串 `user_id` / `role_id` 的隐式强转缺口，强化 OpenAPI `user_id` 非空机器约束（`minLength` + `pattern`），并补齐 service/API/server 回归；全量测试通过。
- ✅ 执行十四轮 CR 收敛：修复 `roles[].permission` 非对象输入与顶层 `can_*` 字段的契约绕过缺口，并优化 `replacePlatformRolesAndSyncSnapshot` 单请求会话解析为一次；补齐 service/API/Express 回归并通过全量测试。
- ✅ 执行十五轮 CR 复核：完成 Story/Git 对账与全量回归（`pnpm --dir apps/api test`，279/279），未发现新增实现缺口，状态保持 `done`。

### File List

- _bmad-output/implementation-artifacts/1-8-关键状态变更触发-session-version-会话收敛.md
- _bmad-output/implementation-artifacts/sprint-status.yaml
- apps/api/src/http-routes.js
- apps/api/src/modules/auth/auth.routes.js
- apps/api/src/route-permissions.js
- apps/api/src/server.js
- apps/api/src/openapi.js
- apps/api/src/modules/auth/auth.store.memory.js
- apps/api/src/modules/auth/auth.store.mysql.js
- apps/api/src/modules/auth/auth.service.js
- apps/api/test/auth.store.mysql.test.js
- apps/api/test/auth.service.test.js
- apps/api/test/auth.api.test.js
- apps/api/test/auth.express.api.test.js
- apps/api/test/route-permissions.test.js
- apps/api/test/server.test.js

### Change Log

- 2026-02-15：创建 Story 1.8 上下文文档并生成 ready-for-dev 交付内容。
- 2026-02-15：完成 Story 1.8 开发实现与测试门禁，状态更新为 `review`。
- 2026-02-15：执行 CR 评审，识别 1 个 HIGH 与 2 个 MEDIUM 实现/覆盖缺口，状态回退为 `in-progress` 并新增 `Review Follow-ups (AI)`。
- 2026-02-15：完成 CR follow-ups：接入运行时入口、修正 MySQL 变更基线、补齐 API/Express 端到端覆盖，并清理文档旧状态描述。
- 2026-02-15：执行二轮 CR：修复未知用户 fail-open 与 deadlock 200 误成功语义，补齐 OpenAPI 503、新增负向用例，并完成 Story File List 对账。
- 2026-02-15：执行三轮 CR：修复 `roles` 缺失/无效条目导致的隐式清空风险、补齐未知同步原因 fail-closed 语义、为 MySQL 角色替换加入 `FOR UPDATE` 行锁，并通过全量测试回归。
- 2026-02-15：执行四轮 CR：修复 `roles[].status` 校验对底层错误字符串的依赖，补齐 API/Express 非法状态负向用例，并通过全量测试回归。
- 2026-02-15：执行五轮 CR：补齐 `/auth/platform/role-facts/replace` 的 OpenAPI `413` 契约，新增 API 降级 `503` 映射回归与 `roles[].role_id` 缺失的 API/Express 负向用例，并通过定向回归测试。
- 2026-02-15：执行六轮 CR：补齐 `roles` 上限约束（`<=5`）与空白 `roles[].status` fail-closed 语义，更新 OpenAPI `maxItems`，并通过全量测试回归。
- 2026-02-15：执行七轮 CR：修复“去重前上限校验”导致的重复角色误拒绝、对齐 MySQL no-op `synced` 语义，并为角色事实替换入口补充会话二次校验；新增 service/api/store 回归并通过全量测试。
- 2026-02-15：执行八轮 CR：修复重复 `role_id` 的顺序依赖语义，统一重复条目为 `AUTH-400-INVALID-PAYLOAD`；同步 OpenAPI `uniqueItems` 与契约描述，并补齐 API/Express/Service 回归后通过全量测试。
- 2026-02-15：执行九轮 CR：补齐角色事实替换审计的 actor/target 追踪字段，修复 `authorizationContext` 失配审计主体缺失，并增强 OpenAPI `roles.uniqueItems` 与 `role_id` 非空约束；通过 `auth.service`、`server` 定向回归与 `pnpm --dir apps/api test` 全量回归。
- 2026-02-15：执行十轮 CR：修复服务层 `replacePlatformRolesAndSyncSnapshot` 的权限复核缺口（强制 `platform.member_admin.operate`），补齐 service/API 无权限 `403` 负向回归，并通过 `pnpm --dir apps/api test` 全量回归。
- 2026-02-15：执行十一轮 CR：修复服务层 `replacePlatformRolesAndSyncSnapshot` 缺失 `accessToken` 的 fail-open（改为 `AUTH-401-INVALID-ACCESS`），同步更新 service 用例并通过 `pnpm --dir apps/api lint`、`pnpm --dir apps/api check:route-permissions`、`pnpm --dir apps/api test`。
- 2026-02-15：执行十二轮 CR：补齐 `roles[].role_id<=64` 与 `roles[].permission.can_*` 类型校验、补充 `ER_DATA_TOO_LONG -> AUTH-400-INVALID-PAYLOAD` 映射，更新 OpenAPI `maxLength` 与 API/Express/Service/Server 回归，并通过 `pnpm --dir apps/api test` 全量回归。
- 2026-02-15：执行十三轮 CR：修复 `replacePlatformRolesAndSyncSnapshot` 对非字符串 `user_id` / `role_id` 的隐式强转 fail-open，补强 OpenAPI `user_id` 非空机器约束（`minLength` + `pattern`），并补齐 service/API/server 回归后通过 `pnpm --dir apps/api test` 全量回归。
- 2026-02-15：执行十四轮 CR：修复 `roles[].permission` 非对象与顶层 `can_*` 字段输入的 fail-open/契约漂移问题，优化角色事实替换路径重复会话解析，新增 service/API/Express 回归并通过 `pnpm --dir apps/api test` 全量回归。
- 2026-02-15：执行十五轮 CR 复核：复查 Story 1.8 AC 与已勾选任务，完成 Git 对账与 `pnpm --dir apps/api test`（279/279）回归，未发现新增问题，状态维持 `done`。

### Senior Developer Review (AI)

- Reviewer: 老大
- Date: 2026-02-15
- Outcome: Resolved
- Summary:
  - Git 与 Story File List 已重新对账并一致（含 route/openapi/server 相关文件）。
  - 相关回归校验通过：`pnpm --dir apps/api check:route-permissions`、`pnpm --dir apps/api test`。
  - 已补齐十四轮 CR 发现：请求载荷 fail-open、未知同步原因 fail-open、MySQL 并发行锁缺口、`roles[].status` 校验脆弱性、OpenAPI `413` 契约缺口、`roles<=5` 与空白状态值 fail-closed 缺口、入口会话二次校验、重复 `role_id` 顺序依赖语义/契约歧义、审计归因/契约可校验性补强、服务层权限复核缺口、缺失 `accessToken` 的 fail-open 缺口、`role_id` 长度/permission 类型输入校验缺口、`user_id`/`role_id` 非字符串隐式强转与 `user_id` OpenAPI 非空约束缺口，以及 `roles[].permission` 非对象与顶层 `can_*` 字段契约绕过、角色事实替换路径重复会话解析性能缺口；`Review Follow-ups (AI)` 已全部完成，Story 状态维持 `done`。
  - 本轮（十五轮）复核结论：未发现新增 HIGH/MEDIUM/LOW 问题；AC 与任务完成声明和实现一致，Story 状态维持 `done`。
