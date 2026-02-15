# Story 1.7: Refresh Rotation、重放识别与并发会话策略

Status: done
Story ID: 1.7
Story Key: 1-7-refresh-rotation-重放识别与并发会话策略

<!-- Note: Validation is optional. Run validate-create-story for quality check before dev-story. -->

## Story

As a 系统安全治理方,
I want refresh token 轮换、重放识别与并发会话策略统一生效,
so that 认证链路在高风险场景下仍可保持安全一致性与可恢复性。

## Acceptance Criteria

1. **Given** 用户使用有效 refresh token 刷新会话  
   **When** 刷新请求成功  
   **Then** 系统签发新的 refresh token 并立即使旧 token 失效  
   **And** 新旧 token 关系可追踪用于审计

2. **Given** 已失效或已使用的 refresh token 被再次提交  
   **When** 系统收到刷新请求  
   **Then** 系统识别为重放行为并拒绝请求  
   **And** 返回统一错误码并记录安全事件

3. **Given** 同一用户存在多个并发会话  
   **When** 其中一个会话执行刷新或登出  
   **Then** 仅影响当前会话 token 链路  
   **And** 其他并发会话保持有效

4. **Given** 重放或异常刷新事件发生  
   **When** 安全审计系统接收事件  
   **Then** 事件包含用户标识、会话标识、request_id 与发生时间  
   **And** 可用于后续告警与排障追踪

## Tasks / Subtasks

- [x] 任务 1：固化 refresh rotation 原子链路与可追踪性（AC: 1）
  - [x] 统一 `auth.store.mysql` 与 `auth.store.memory` 的 rotation 语义：旧 token 失效、新 token 生效、`rotated_from/rotated_to` 链路可追踪
  - [x] 保证 refresh 成功返回前，存储层状态已完成落库/落内存更新，不暴露中间态
  - [x] 保持响应返回 `session_id` 与 `request_id`，用于链路追踪

- [x] 任务 2：重放识别与统一处置（AC: 2, 4）
  - [x] 对 `rotated/revoked/missing/expired/malformed` refresh token 统一返回 `AUTH-401-INVALID-REFRESH`
  - [x] 命中重放时执行当前会话链路处置（撤销当前 session 活跃 refresh token），并记录安全审计事件
  - [x] 审计事件补齐 `user_id`、`session_id`、`request_id`、`detail` 与处置原因，满足排障检索

- [x] 任务 3：并发会话隔离策略（AC: 3）
  - [x] 校验同一用户多会话场景下，`logout` 仅撤销当前 `session_id`
  - [x] 校验同一用户多会话场景下，一个会话 refresh/replay 处置不会误伤其他会话
  - [x] 禁止引入 `logout-all` 语义或跨 session 撤销副作用

- [x] 任务 4：API 契约与错误模型对齐（AC: 2, 4）
  - [x] 对齐 `/auth/refresh` OpenAPI 与运行时错误响应（Problem Details）
  - [x] 确保错误结构稳定包含 `type/title/status/detail/error_code/request_id`
  - [x] 若调整审计字段或响应字段，保持 `snake_case` 契约与示例同步

- [x] 任务 5：测试与回归门禁（AC: 1, 2, 3, 4）
  - [x] 单元测试覆盖 rotation、replay、并发会话隔离、refresh 冲突拒绝与审计字段完整性
  - [x] API 集成测试覆盖 `/auth/login -> /auth/refresh -> replay -> /auth/logout` 主链路与负向场景
  - [x] 通过门禁：`pnpm --dir apps/api test`、`pnpm --dir apps/api check:route-permissions`

### Review Follow-ups (AI)

- [x] [AI-Review][MEDIUM] Story `File List` 漏登记 `apps/api/src/modules/auth/auth.store.mysql.js`，与 git 实际改动不一致；已补齐文件清单记录。[`_bmad-output/implementation-artifacts/1-7-refresh-rotation-重放识别与并发会话策略.md`]
- [x] [AI-Review][MEDIUM] Story `File List` 漏登记 `apps/api/src/modules/auth/auth.store.memory.js`，与 git 实际改动不一致；已补齐文件清单记录。[`_bmad-output/implementation-artifacts/1-7-refresh-rotation-重放识别与并发会话策略.md`]
- [x] [AI-Review][MEDIUM] Story `File List` 漏登记 `apps/api/test/auth.store.mysql.test.js`，与 git 实际改动不一致；已补齐文件清单记录。[`_bmad-output/implementation-artifacts/1-7-refresh-rotation-重放识别与并发会话策略.md`]
- [x] [AI-Review][LOW] Story 状态与冲刺跟踪尚未从 `review` 收敛到 `done`；已同步故事状态与 sprint tracking。[`_bmad-output/implementation-artifacts/1-7-refresh-rotation-重放识别与并发会话策略.md`, `_bmad-output/implementation-artifacts/sprint-status.yaml`]
- [x] [AI-Review][MEDIUM] 过期 refresh 的审计事件未稳定补齐 `user_id/session_id`；已在 JWT 过期路径保留已验签 claims 并落审计字段。[`apps/api/src/modules/auth/auth.service.js`, `apps/api/test/auth.service.test.js`]
- [x] [AI-Review][LOW] 过期 refresh 判定依赖 `error.message` 字符串，存在可维护性脆弱点；已改为基于结构化 `error.code` 判定。[`apps/api/src/modules/auth/auth.service.js`]

## Dev Notes

### Developer Context（开发者必须先读）

- Story 1.2 已落地 refresh rotation/replay/logout 基线；本故事目标是“强化一致性与可观测”，不是重写认证框架。
- Story 1.6 已强化双域权限边界；本故事改动应聚焦 `modules/auth` 的 token 生命周期，避免引入跨域权限行为变化。
- 默认策略继续 `fail-closed`：refresh 状态异常、链路不一致、会话不一致时一律拒绝并留痕。

### Technical Requirements（实现硬约束）

- refresh token 必须按 `JWT(typ=refresh, sid, sv, jti)` 解析并基于 `jti` 哈希进行事实判定。
- refresh 成功必须满足：旧 token 失效 + 新 token 生效 + 旋转关系可追踪。
- replay/异常刷新必须统一返回 `AUTH-401-INVALID-REFRESH`，并写入安全审计事件。
- 并发会话策略必须保持：同用户多会话并存，当前会话登出不影响其他会话。
- 审计事件至少可关联：`request_id`、`user_id`、`session_id`、事件类型、时间语义（由日志系统时间戳保障）。
- 禁止绕过现有 Problem Details 统一错误模型。

### Architecture Compliance（架构对齐清单）

- 遵循安全会话基线：`JWT(access+refresh) + refresh rotation + replay detection + session_version`。
- 认证实现集中在 `modules/auth`，不跨模块新增旁路鉴权实现。
- 保持 REST + OpenAPI 契约优先，错误返回统一 Problem Details。
- 保持 replay gate 测试可执行且阻断回归。
- 仅在必要时新增 migration，且需满足幂等与回滚可用性约束。

### Library & Framework Requirements（库与框架要求）

- 项目基线（package 现状）：
  - Node.js 引擎：`>=24.0.0`
  - NestJS：`11.1.13`
  - React：`19.2.4`
  - Vite：`7.3.1`
  - TypeORM：`^0.3.28`
  - `ioredis`：`5.9.2`
  - `mysql2`：`^3.17.0`
- 最新核验（2026-02-15）：
  - npm registry：`@nestjs/core 11.1.13`、`react 19.2.4`、`vite 7.3.1`、`typeorm 0.3.28`、`ioredis 5.9.3`、`mysql2 3.17.1`
  - Node.js 官方下载页：`v25.6.1 (Current)`、`v24.13.1 (LTS)`
  - MySQL 8.4 Release Notes：最新小版本 `8.4.8 (2026-01-20, LTS)`
- 版本策略：
  - 本故事不引入大版本升级。
  - 可选补丁升级：`ioredis 5.9.2 -> 5.9.3`，`mysql2` 锁文件对齐 `3.17.1`（需单独评估并回归）。

### File Structure Requirements（建议变更落点）

- 后端核心：
  - `apps/api/src/modules/auth/auth.service.js`
  - `apps/api/src/modules/auth/auth.store.mysql.js`
  - `apps/api/src/modules/auth/auth.store.memory.js`
  - `apps/api/src/modules/auth/auth.routes.js`
  - `apps/api/src/http-routes.js`
  - `apps/api/src/openapi.js`
- 测试：
  - `apps/api/test/auth.service.test.js`
  - `apps/api/test/auth.express.api.test.js`
  - `apps/api/test/server.test.js`
- 迁移（仅在必须扩展 token 元数据结构时）：
  - `apps/api/migrations/*`

### Testing Requirements（测试要求）

- 单元测试：
  - refresh 成功后旧 token 立即不可用，新 token 可用且链路可追踪
  - replay 命中（rotated/revoked/missing/expired/malformed）统一 401 语义
  - rotation 冲突/竞态场景 fail-closed（拒绝并记录审计）
  - 多会话并发下 `logout` 仅影响当前 session
- API 集成测试：
  - `/auth/refresh` 的 400/401 响应契约与 OpenAPI 示例一致
  - replay 命中后当前会话链路撤销，其他并发会话仍可刷新
  - 关键失败路径包含 `request_id` 与统一错误码
- 回归门禁：
  - `pnpm --dir apps/api check:route-permissions`
  - `pnpm --dir apps/api test`

### Previous Story Intelligence（来自 Story 1.6）

- 继续复用“实现 + 契约 + 测试”三层同步提交，避免运行时与 OpenAPI 漂移。
- 继续保持 MySQL 与内存存储语义一致，避免双存储行为分叉。
- 继续执行 fail-closed 思路：异常状态不可放行，优先拒绝并审计留痕。
- 若新增迁移，需继承 Story 1.6 的幂等/回滚守卫实践，避免发布与回滚失败。

### Git Intelligence Summary

- 最近提交（`7b50cf9`、`915e74f`、`8b91d99`）显示鉴权改造集中在：
  - `apps/api/src/modules/auth/*`
  - `apps/api/src/openapi.js`
  - `apps/api/src/route-permissions.js`
  - `apps/api/test/auth*.test.js`
- 推断：Story 1.7 应沿现有 auth 模块增量演进，优先补强 refresh/replay 语义与测试，不做目录级重构。

### Latest Tech Information（2026-02-15 核验）

- Node.js（官方）：
  - `v25.6.1 (Current)`
  - `v24.13.1 (LTS)`
- MySQL（官方）：
  - `MySQL 8.4.8`（发布于 `2026-01-20`，LTS 小版本）
- npm registry（`pnpm view`）：
  - `@nestjs/core 11.1.13`
  - `react 19.2.4`
  - `vite 7.3.1`
  - `typeorm 0.3.28`
  - `ioredis 5.9.3`（项目当前 `5.9.2`）
  - `mysql2 3.17.1`（项目范围 `^3.17.0`）

### Project Context Reference

- 未发现 `**/project-context.md`。
- 本故事上下文来源以 `epics/prd/architecture/ux`、Story 1.6 复盘与当前代码基线为准。

### Story Completion Status

- Story 文档状态：`done`
- Completion Note：`Story 1.7 code review completed; high/medium issues fixed and regression gates passed`

### Project Structure Notes

- 当前认证与 token 生命周期主逻辑已集中在 `apps/api/src/modules/auth/*`，本故事应在该边界内实现。
- `refresh_tokens` 与 `auth_sessions` 已具备可演进的数据结构，优先复用现有字段与索引；仅在确有缺口时新增迁移。
- 若调整 API 字段或错误示例，必须同步 `openapi` 与测试断言，防止契约漂移。

### References

- Story 1.7 定义与 AC  
  [Source: _bmad-output/planning-artifacts/epics.md#Story 1.7: Refresh Rotation、重放识别与并发会话策略]
- FR53 / FR67 与安全一致性约束  
  [Source: _bmad-output/planning-artifacts/prd.md#安全一致性与发布门禁]
- NFR8 / NFR31（重放识别与并发会话目标）  
  [Source: _bmad-output/planning-artifacts/prd.md#Security]  
  [Source: _bmad-output/planning-artifacts/prd.md#Reliability]
- 安全会话基线与 replay gate  
  [Source: _bmad-output/planning-artifacts/architecture.md#Authentication & Security]  
  [Source: _bmad-output/planning-artifacts/architecture.md#Enforcement Guidelines]
- 可观测与 request_id 追踪要求  
  [Source: _bmad-output/planning-artifacts/ux-design-specification.md#Journey 6（MVP）Non-UI 执行模式]
- 前序故事复盘  
  [Source: _bmad-output/implementation-artifacts/1-6-双域权限边界与服务端租户最终判定.md]
- Node.js 官方下载  
  [Source: https://nodejs.org/en/download/current]
- MySQL 8.4 Release Notes  
  [Source: https://dev.mysql.com/doc/relnotes/mysql/8.4/en/]

## Dev Agent Record

### Agent Model Used

gpt-5-codex

### Debug Log References

- `cat _bmad-output/implementation-artifacts/sprint-status.yaml`
- `cat _bmad-output/planning-artifacts/epics.md`
- `cat _bmad-output/planning-artifacts/prd.md`
- `cat _bmad-output/planning-artifacts/architecture.md`
- `cat _bmad-output/planning-artifacts/ux-design-specification.md`
- `cat _bmad-output/implementation-artifacts/1-6-双域权限边界与服务端租户最终判定.md`
- `git log --oneline -n 5`
- `git show --name-only --pretty=format:'COMMIT %H%nTITLE %s%nDATE %cI%n' -n 5`
- `pnpm view @nestjs/core version`
- `pnpm view react version`
- `pnpm view vite version`
- `pnpm view typeorm version`
- `pnpm view ioredis version`
- `pnpm view mysql2 version`
- `node -v`
- `rg -n "rotate|replay|AUTH-401-INVALID-REFRESH|session_id|request_id" apps/api/src/modules/auth/*.js apps/api/src/openapi.js`
- `pnpm --dir apps/api exec node --test test/auth.service.test.js`
- `pnpm --dir apps/api exec node --test --test-force-exit test/auth.express.api.test.js`
- `pnpm --dir apps/api check:route-permissions`
- `pnpm --dir apps/api test`
- `pnpm --dir apps/api lint`
- `pnpm --dir apps/api exec node --test test/auth.service.test.js`
- `pnpm --dir apps/api exec node --test test/auth.store.mysql.test.js`
- `pnpm --dir apps/api exec node --test --test-force-exit test/auth.express.api.test.js`

### Completion Notes List

- ✅ 在 `apps/api/src/modules/auth/auth.service.js` 增强 refresh 异常审计：新增 `disposition_reason` 与 `disposition_action`，并补齐 invalid/replay/rotation-conflict 路径的处置原因语义。
- ✅ 在 `apps/api/src/modules/auth/auth.store.mysql.js` 与 `apps/api/src/modules/auth/auth.store.memory.js` 收敛 refresh rotation 所有权校验：仅允许 `session_id + user_id` 匹配链路发生 rotate，阻断跨会话误旋转。
- ✅ 在 `apps/api/test/auth.service.test.js` 新增 Story 1.7 单元覆盖：rotation 链路追踪、`rotated/revoked/missing/expired/malformed` 统一 401、replay 会话隔离、审计字段完整性断言。
- ✅ 在 `apps/api/test/auth.express.api.test.js` 新增 MySQL 集成覆盖：`refresh_tokens` 的 `rotated_from/rotated_to` 持久化链路、replay Problem Details 结构、并发会话隔离。
- ✅ 在 `apps/api/test/auth.store.mysql.test.js` 新增 rotate 所有权守卫回归：ownership mismatch 不可变更 token 链路；更新 SQL 必须携带 `session_id/user_id` 约束。
- ✅ 门禁通过：`pnpm --dir apps/api check:route-permissions`、`pnpm --dir apps/api test`（全量 217 tests 通过）、`pnpm --dir apps/api lint`（35 files checked）。
- ✅ Code Review 补测通过：`test/auth.service.test.js`（54/54）、`test/auth.store.mysql.test.js`（33/33）、`test/auth.express.api.test.js`（30/30）。
- ✅ Code Review（本轮）修复 refresh 过期审计字段缺口：`auth.refresh.replay_or_invalid` 在 JWT 过期场景下补齐 `user_id/session_id/session_id_hint`。
- ✅ Code Review（本轮）将过期 refresh 分类从 `error.message` 匹配升级为 `error.code`，降低后续重构引发的分类漂移风险。

### File List

- _bmad-output/implementation-artifacts/1-7-refresh-rotation-重放识别与并发会话策略.md
- _bmad-output/implementation-artifacts/sprint-status.yaml
- apps/api/src/modules/auth/auth.service.js
- apps/api/src/modules/auth/auth.store.mysql.js
- apps/api/src/modules/auth/auth.store.memory.js
- apps/api/test/auth.service.test.js
- apps/api/test/auth.express.api.test.js
- apps/api/test/auth.store.mysql.test.js

### Change Log

- 2026-02-15：创建 Story 1.7 上下文文档并标记为 `ready-for-dev`。
- 2026-02-15：完成 Story 1.7 实现与测试，状态更新为 `review`。
- 2026-02-15：完成 Code Review（File List 对齐 + 状态收敛 + 回归补测），状态更新为 `done`。
- 2026-02-15：执行 CR 复核并修复 2 项增量问题（expired refresh 审计字段补齐 + 过期判定改用结构化错误码）。

## Senior Developer Review (AI)

### Reviewer

老大（AI）

### Date

2026-02-15

### Outcome

Approve（本轮发现 4 项问题并已全部修复）

### Findings

1. [HIGH] 0
2. [MEDIUM] 0（已修复 3）
3. [LOW] 0（已修复 1）

### Validation

- `pnpm --dir apps/api exec node --test test/auth.service.test.js`
- `pnpm --dir apps/api exec node --test test/auth.store.mysql.test.js`
- `pnpm --dir apps/api exec node --test --test-force-exit test/auth.express.api.test.js`
- `pnpm --dir apps/api check:route-permissions`
- `pnpm --dir apps/api test`

以上命令通过（`auth.service` 54/54，`auth.store.mysql` 33/33，`auth.express.api` 30/30）。

### Re-Review（2026-02-15）

- Outcome：Approve（本轮新增发现 2 项，已在同轮修复）
- Findings（fixed）：
  1. [MEDIUM] JWT 过期场景审计事件缺失稳定 `user_id/session_id`
  2. [LOW] 过期判定依赖 `error.message` 文本匹配
- Validation：
  - `pnpm --dir apps/api check:route-permissions`
  - `pnpm --dir apps/api test`
  - `pnpm --dir apps/api lint`
