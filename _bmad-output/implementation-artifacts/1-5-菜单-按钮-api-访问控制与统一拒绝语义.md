# Story 1.5: 菜单/按钮/API 访问控制与统一拒绝语义

Status: done

<!-- Note: Validation is optional. Run validate-create-story for quality check before dev-story. -->

## Story

As a 平台或组织用户,
I want 系统基于有效权限同时控制菜单、按钮和受保护 API,
so that 前后端权限语义一致，不会出现“看得见但不能做”或“越权放行”。

## Acceptance Criteria

1. **Given** 用户登录并进入任一域工作台
   **When** 前端渲染导航与页面操作区
   **Then** 系统仅展示用户有权访问的菜单与按钮
   **And** 不可访问能力不渲染或置灰且行为一致

2. **Given** 用户调用受保护 API 且具备权限声明对应权限
   **When** 请求到达服务端
   **Then** 服务端允许请求并返回成功结果
   **And** 权限判定基于服务端有效会话与权限快照执行

3. **Given** 用户调用受保护 API 但无对应权限
   **When** 请求到达服务端
   **Then** 服务端统一拒绝并返回标准错误码与问题详情结构
   **And** 拒绝结果可被前端映射为统一可理解提示

4. **Given** 某受保护接口缺失权限声明
   **When** 执行启动自检或发布门禁
   **Then** 系统判定为失败并阻断运行/发布
   **And** 输出缺失声明接口清单供修复

## Tasks / Subtasks

- [x] 建立受保护接口权限声明清单与注册机制（AC: 2, 3, 4）
  - [x] 在路由注册层维护权限声明元数据（建议：`path + method + permission_code + scope`）
  - [x] 区分 `public` 与 `protected` 路由，避免隐式默认放行
  - [x] 为当前已交付认证域相关受保护接口补齐声明（优先：`/auth/tenant/options|select|switch`）

- [x] 落地“缺失声明即失败”的启动/门禁校验（AC: 4）
  - [x] 在应用启动阶段新增权限声明 preflight（与现有 schema preflight 并行）
  - [x] 输出缺失声明接口清单（包含 method/path）
  - [x] 在 CI 门禁加入权限声明校验命令，确保发布前必检

- [x] 落地统一授权判定与拒绝语义（AC: 2, 3）
  - [x] 授权判定只依赖服务端会话与权限快照，不采信客户端权限输入
  - [x] 对“无权限访问”统一返回 Problem Details + 标准错误码（建议新增/明确 `AUTH-403-FORBIDDEN`，与 `AUTH-403-NO-DOMAIN` 语义分层）
  - [x] 错误响应保留 `request_id` 与可观测字段，便于前端映射与排障

- [x] 前端菜单/按钮渲染与可操作性收敛（AC: 1, 3）
  - [x] 建立统一权限选择器（single source of truth），禁止页面局部推导权限
  - [x] 菜单可见性与按钮可见性规则统一（不可见）
  - [x] 权限变化后（组织选择/切换）即时重算 UI 可见性与可操作性

- [x] OpenAPI 与错误码文档同步（AC: 2, 3, 4）
  - [x] 为受保护接口补齐权限相关 403 示例（Problem Details）
  - [x] 保证接口契约与实现一致（字段命名、错误码、示例）
  - [x] 在文档中明确“缺失权限声明阻断发布”的规则

- [x] 测试与门禁补齐（AC: 1, 2, 3, 4）
  - [x] API 正向：有权限可访问受保护接口
  - [x] API 负向：无权限返回统一 403 语义，不出现 200/500 漂移
  - [x] 启动/CI 负向：缺失权限声明时启动失败或门禁失败
  - [x] Web Chrome 场景：菜单隐藏、按钮隐藏、统一错误提示与重算行为

### Review Follow-ups (AI)

- [x] [AI-Review][HIGH] API 当前在两条入口都以 `*` 放开 `access-control-allow-origin`，会把所有鉴权路由默认暴露给任意来源页面读取响应，缺少环境级 allowlist 收敛；建议改为配置化白名单并按环境区分。 [`apps/api/src/server.js:61`] [`apps/api/src/server.js:77`] [`apps/api/src/app.js:281`]
- [x] [AI-Review][MEDIUM] 权限声明校验允许 `OPTIONS` 方法声明，但可执行路由基线并未产出 `OPTIONS /path` 键；声明可通过字段合法性检查却会被判定为 `declared routes missing executable handlers`，规则语义不一致。建议在校验层禁用 `OPTIONS` 声明或在可执行路由发现中显式纳入。 [`apps/api/src/route-permissions.js:93`] [`apps/api/src/server.js:417`] [`apps/api/src/server.js:553`]
- [x] [AI-Review][MEDIUM] `resolveTenantMutationUiState` 在 `hasTenantOptions=false` 且“无历史选项”时会直接采用 `nextActiveTenantId` 作为选择值，可能生成“不在候选列表中的选中值”，导致组织切换控件状态漂移。建议该分支改为仅在候选可验证时设置选中值，否则保持空值并触发显式刷新。 [`apps/web/src/tenant-mutation.mjs:157`] [`apps/web/src/tenant-mutation.mjs:166`] [`apps/web/src/App.jsx:848`]
- [x] [AI-Review][HIGH] CORS allowlist 未命中时仍回写 fallback origin（而非拒绝/省略 `access-control-allow-origin`），会导致跨域拒绝语义与审计观测偏差。建议未命中 origin 直接拒绝或至少不下发 ACAO。 [`apps/api/src/server.js:151`] [`apps/api/src/server.js:167`] [`apps/api/test/server.test.js:253`]
- [x] [AI-Review][MEDIUM] Story 子任务“菜单可见性与按钮可见性规则统一（不可见）”已勾选完成，但实现与回归测试仍保留“菜单可见、按钮隐藏”的分离规则；任务口径与交付行为不一致。建议明确修正文档口径或统一实现规则并更新测试。 [`_bmad-output/implementation-artifacts/1-5-菜单-按钮-api-访问控制与统一拒绝语义.md:54`] [`apps/web/src/App.jsx:136`] [`apps/web/test/chrome.playwright.test.js:1140`]
- [x] [AI-Review][MEDIUM] `resolveTenantMutationUiState` 在 `hasTenantOptions=true` 且 options 为空时，仍把 `nextActiveTenantId` 写入选择值，可能再次出现“选中值不在候选列表”的状态漂移。建议空 options 分支强制清空选择值并触发显式刷新。 [`apps/web/src/tenant-mutation.mjs:164`] [`apps/web/test/server.test.js:123`]


### Senior Developer Review (AI)

- Reviewer: 老大
- Date: 2026-02-14
- Outcome: Changes Requested
- Scope: Story 1.5 + `File List` 对应源码文件（排除 `_bmad/` 与 `_bmad-output/`）
- Git vs Story Discrepancies: 0（Story File List 与当前 git 变更已对齐）
- Validation Run:
  - 源码审阅：覆盖 story `File List` 与当前 git 变更文件
  - 校验命令：`pnpm --dir apps/api run check:route-permissions`、`pnpm --dir apps/api exec node --test test/server.test.js`、`pnpm --dir apps/web exec node --test test/server.test.js`（均通过）
  - 运行时复现：`node` 脚本复现 `resolveTenantMutationUiState` 在 `hasTenantOptions=false` 且无历史选项时产出无候选项选择值
- Findings Summary: High 1 / Medium 2 / Low 0
- Decision: 更新为 `in-progress`

### Senior Developer Review (AI) - CR #24

- Reviewer: 老大
- Date: 2026-02-14
- Outcome: Changes Requested
- Scope: Story 1.5 + `File List` 对应源码文件（排除 `_bmad/` 与 `_bmad-output/`）
- Git vs Story Discrepancies: 0（Story File List 与当前 git 变更已对齐）
- Validation Run:
  - 源码审阅：覆盖 story `File List` 与当前 git 变更文件
  - 校验命令：`pnpm --dir apps/api run check:route-permissions`、`pnpm --dir apps/api exec node --test test/server.test.js`、`pnpm --dir apps/web exec node --test test/server.test.js`（均通过）
- Findings Summary: High 1 / Medium 2 / Low 0
- Decision: 维持 `in-progress`，新增 3 条 follow-ups 待处理

### Senior Developer Review (AI) - CR #25

- Reviewer: 老大
- Date: 2026-02-14
- Outcome: Approved
- Scope: Story 1.5 + `File List` 对应源码文件（排除 `_bmad/` 与 `_bmad-output/`）
- Git vs Story Discrepancies: 0（Story File List 与当前 git 变更已对齐）
- Validation Run:
  - 源码审阅：覆盖 story `File List` 与当前 git 变更文件
  - 校验命令：`pnpm --dir apps/api run check:route-permissions`、`pnpm --dir apps/api exec node --test test/route-permissions.test.js test/server.test.js`、`pnpm --dir apps/web exec node --test test/server.test.js`、`pnpm nx lint`、`pnpm nx test`（均通过）
- Findings Summary: High 0 / Medium 0 / Low 0
- Decision: 更新为 `done`，无新增 follow-ups

## Dev Notes

### Developer Context（开发者必须先读）

- 本故事是 Story 1.4 的直接延续：1.4 已实现入口域识别、组织选择/切换与服务端权限快照回传；1.5 要把“权限快照”扩展为“菜单/按钮/API 全链路一致执行”。
- 目标是 **一致性与 fail-closed**，不是堆新功能。避免复制第二套鉴权逻辑。
- 优先复用既有认证/会话链路：`auth.service`、`dispatchApiRoute`、`Problem Details`、`request_id`。

### Technical Requirements（实现硬约束）

- 受保护接口必须有显式权限声明；无声明即失败（启动或 CI）。
- 授权判定必须基于服务端上下文：`access_token`、`entry_domain`、`active_tenant_id`、`tenant_permission_context`。
- 对无权限请求统一返回 Problem Details，不允许返回裸文本或结构漂移。
- 前端菜单与按钮必须由同一权限源驱动，避免“菜单可见但按钮禁用逻辑不一致”。
- 组织切换后权限结果需即时重算并反映到页面可见性与可操作性。

### Architecture Compliance（架构对齐清单）

- 遵循双域 RBAC 隔离：`platform.*` 与 `tenant.*` 不得混用。
- 遵循 API 错误模型：`Problem Details + error_code + request_id`。
- 遵循发布门禁：受保护接口权限声明覆盖率必须可校验。
- 维持模块边界：
  - API 授权决策集中于后端（`apps/api`）
  - 前端仅消费权限快照并执行渲染/交互约束（`apps/web`）

### Library & Framework Requirements（库与框架要求）

- 沿用当前仓库版本（2026-02-12 核验）：
  - `@nestjs/core`: `11.1.13`
  - `react`: `19.2.4`
  - `typeorm`: `0.3.28`
  - `mysql2`: `3.17.0`
  - `vite`: `7.3.1`
  - `ioredis`: `5.9.2`
- 最新版本情报（2026-02-12 实时查询）：
  - `ioredis` 最新为 `5.9.3`（当前落后一个 patch，若升级需先跑全量回归）
  - `antd` 最新为 `6.3.0`，`@ant-design/icons` 最新为 `6.1.0`（当前前端尚未显式引入）
  - Node LTS 最新：`v24.13.1 (Krypton)`；工程 `node >=24` 约束保持有效
  - MySQL 8.4 LTS 补丁线：`8.4.8`

### File Structure Requirements（建议变更落点）

- 后端核心：
  - `apps/api/src/http-routes.js`（路由权限声明元数据）
  - `apps/api/src/server.js`（分发前授权检查、统一 403 语义）
  - `apps/api/src/modules/auth/auth.service.js`（权限快照读取/标准化能力复用）
  - `apps/api/src/openapi.js`（权限拒绝示例与错误码契约）
  - `apps/api/src/app.js`（启动期权限声明 preflight 接入）
- 测试：
  - `apps/api/test/auth.domain.api.test.js`
  - `apps/api/test/auth.express.api.test.js`
  - `apps/api/test/auth.service.test.js`
  - `apps/web/test/chrome.playwright.test.js`
- 前端：
  - `apps/web/src/App.jsx`（当前可见性/可操作性主入口）
  - 若开始页面拆分，保持权限选择器在共享层（避免重复实现）

### Testing Requirements（测试要求）

- API 必测
  - 有声明且有权限：受保护接口返回 200
  - 有声明但无权限：返回统一 403（Problem Details + 标准错误码）
  - 缺失声明：启动失败或门禁失败（必须可观测到接口清单）
- 契约必测
  - OpenAPI 403 示例与真实返回字段一致
  - 错误响应含 `error_code`、`request_id`
- Web（Chrome）必测
  - 菜单仅展示可访问项
  - 按钮显示/禁用与权限快照一致
  - 无权限动作反馈采用统一语义（原因 + 请稍后重试）
  - 组织切换后 UI 权限状态即时刷新

### Previous Story Intelligence（来自 Story 1.4）

- 关键经验 1：鉴权策略必须 fail-closed，严禁“数据缺失时默认放行”。
- 关键经验 2：权限可见性必须来自服务端真实 `tenant_permission_context`，禁止前端本地推导。
- 关键经验 3：启动期 preflight 能显著降低“运行时才暴雷”的概率；权限声明校验应沿用此策略。
- 关键经验 4：迁移、契约、测试三者容易漂移，必须用“官方迁移链 + 实际登录链路”集成测试兜底。
- 关键经验 5：Story 文档需保持与 git 变更一致，避免评审阶段信息失真。

### Git Intelligence Summary

- 最近提交显示实现重心持续集中在 `apps/api/src/modules/auth/*`、`apps/api/src/openapi.js`、`apps/web/src/App.jsx` 与 `apps/api/test/*`。
- 提交模式表明：每轮都伴随“实现 + 契约 + 测试”同步修改；Story 1.5 应保持该节奏，避免只改单层。
- 从 Story 1.4 历次 follow-ups 看，最常见回归点是：
  - fail-open 鉴权
  - 权限上下文与 UI 表现不一致
  - preflight 覆盖不足导致运行期错误

### Latest Tech Information（2026-02-12 核验）

- NPM 查询：
  - `@nestjs/core` `11.1.13`
  - `react` `19.2.4`
  - `typeorm` `0.3.28`
  - `mysql2` `3.17.0`
  - `vite` `7.3.1`
  - `antd` `6.3.0`
  - `@ant-design/icons` `6.1.0`
  - `ioredis` `5.9.3`
- Node 发布线：`v24.13.1` 为当前 LTS（Krypton）。
- MySQL 8.4 LTS：当前补丁线为 `8.4.8`。

### Project Context Reference

- 未发现 `project-context.md`（匹配模式：`**/project-context.md`）。
- 本故事上下文以 `epics/prd/architecture/ux` 与 Story 1.4 为准。

### Story Completion Status

- Story 文档状态：`done`
- Completion Note：`CR #25 approved: no High/Medium/Low findings; route permission declaration gate, API/Web targeted regression sets, and workspace lint/test all passed; story status promoted to done.`

### Project Structure Notes

- 当前仓库仍以 `App.jsx` 承载主要登录与工作台状态；Story 1.5 如需拆分页面，优先保持行为一致再做结构演进。
- 权限声明门禁建议先在认证域路由落地，再推广到后续 Epic 2/3 模块，避免一次性改造过大。

### References

- Story 1.5 定义与 AC
  [Source: _bmad-output/planning-artifacts/epics.md#Story 1.5: 菜单/按钮/API 访问控制与统一拒绝语义]
- Epic 1 上下文与前后故事依赖
  [Source: _bmad-output/planning-artifacts/epics.md#Epic 1: 认证与访问控制基线及双入口体验]
- 安全与架构约束（双域 RBAC、权限声明门禁、Problem Details）
  [Source: _bmad-output/planning-artifacts/architecture.md]
- 产品约束与 FR 映射（FR27/28/72/73）
  [Source: _bmad-output/planning-artifacts/prd.md]
- UX 一致性约束（反馈语义、按钮防重、交互一致）
  [Source: _bmad-output/planning-artifacts/ux-design-specification.md]
- 上一故事实现与复盘经验
  [Source: _bmad-output/implementation-artifacts/1-4-双入口域识别与组织选择-切换.md]

## Dev Agent Record

### Agent Model Used

claude-opus-4-6

### Debug Log References

- `cat _bmad-output/implementation-artifacts/sprint-status.yaml`
- `cat _bmad-output/planning-artifacts/epics.md`
- `cat _bmad-output/planning-artifacts/prd.md`
- `cat _bmad-output/planning-artifacts/architecture.md`
- `cat _bmad-output/planning-artifacts/ux-design-specification.md`
- `cat _bmad-output/implementation-artifacts/1-4-双入口域识别与组织选择-切换.md`
- `git log --oneline -n 5`
- `git show --name-only --pretty=format:'%h %s' <commit>`
- `pnpm view @nestjs/core version`
- `pnpm view react version`
- `pnpm view typeorm version`
- `pnpm view mysql2 version`
- `pnpm view vite version`
- `pnpm view antd version`
- `pnpm view @ant-design/icons version`
- `pnpm view ioredis version`
- `curl -fsSL https://nodejs.org/dist/index.json | jq ...`
- `curl -fsSL https://dev.mysql.com/doc/relnotes/mysql/8.4/en/ | rg ...`
- `pnpm --dir apps/api exec node --test test/route-permissions.test.js`
- `pnpm --dir apps/api exec node --test test/auth.service.test.js`
- `pnpm --dir apps/api exec node --test test/server.test.js`
- `pnpm --dir apps/api run check:route-permissions`
- `pnpm --dir apps/api run test`
- `pnpm --dir apps/web exec node --test test/chrome.playwright.test.js`
- `pnpm --dir apps/web run test`
- `pnpm nx lint`
- `pnpm nx test`
- `pnpm --dir apps/api exec node --test test/route-permissions.test.js`
- `pnpm --dir apps/api exec node --test test/server.test.js`
- `pnpm --dir apps/web exec node --test --test-name-pattern "otp login flow" test/chrome.playwright.test.js`
- `pnpm --dir apps/api run check:route-permissions`
- `pnpm --dir apps/web exec node --test test/server.test.js`
- `pnpm nx lint`
- `pnpm nx test`
- `pnpm --dir apps/api exec node --test --test-name-pattern "HEAD" test/server.test.js`
- `pnpm --dir apps/api exec node --test --test-name-pattern "permission scope is incompatible|global error handler includes" test/auth.express.api.test.js`
- `pnpm --dir apps/api exec node --test --test-name-pattern "request_id stable" test/server.test.js`
- `pnpm --dir apps/api exec node --test --test-name-pattern "route method declarations with trailing whitespace" test/auth.express.api.test.js`
- `pnpm --dir apps/api exec node --test --test-name-pattern "extractBearerToken accepts case-insensitive" test/auth.service.test.js`
- `pnpm --dir apps/api exec node --test --test-name-pattern "injected declaration lookup" test/server.test.js`
- `pnpm --dir apps/web exec node --test --test-name-pattern "tenant mutation resolver keeps tenantSwitchValue aligned" test/server.test.js`
- `pnpm --dir apps/api exec node --test --test-name-pattern "path has leading or trailing whitespace|path contains query or hash fragments" test/route-permissions.test.js`
- `pnpm --dir apps/api run check:route-permissions`
- `pnpm --dir apps/api exec node --test test/route-permissions.test.js test/server.test.js`
- `pnpm --dir apps/web exec node --test test/server.test.js`
- `pnpm nx lint`
- `pnpm nx test`
- `pnpm --dir apps/api exec node --test --test-name-pattern "createServer uses immutable snapshot for custom routeDefinitions at startup" test/server.test.js`
- `pnpm --dir apps/api exec node --test --test-name-pattern "createApiApp uses immutable snapshot for custom routeDefinitions at startup" test/auth.express.api.test.js`
- `pnpm --dir apps/api exec node --test --test-name-pattern "authorizeRoute returns AUTH-403-NO-DOMAIN for tenant scoped route when active_tenant_id is missing" test/auth.service.test.js`
- `pnpm --dir apps/web exec node --test --test-name-pattern "tenant refresh ui resolver keeps selection and switch values aligned after tenant list shrink" test/server.test.js`
- `pnpm nx lint`
- `pnpm nx test`
- `pnpm --dir apps/web exec node --test --test-name-pattern "chrome regression covers otp login flow with archived evidence" test/chrome.playwright.test.js`
- `pnpm nx test`
- `pnpm --dir apps/api exec node --test test/server.test.js --test-name-pattern "lookup poisoning|lacks authorizeRoute capability|structured 500 when authorizeRoute handler is missing|resolveRouteDeclarationLookup reuses"`
- `pnpm --dir apps/api exec node --test --test-force-exit test/auth.express.api.test.js --test-name-pattern "preflight permission capability overrides from options"`
- `pnpm nx lint`
- `pnpm nx test`
- `pnpm --dir apps/api exec node --test test/server.test.js --test-name-pattern "createServer fails fast when protected routes exist but authService lacks authorizeRoute capability"`
- `pnpm --dir apps/api exec node --test test/auth.express.api.test.js --test-name-pattern "createApiApp fails fast when protected routes exist but authService lacks authorizeRoute capability"`
- `pnpm --dir apps/web exec node --test test/server.test.js --test-name-pattern "differentiates missing tenant_options|session binding check fails"`
- `pnpm nx lint`
- `pnpm nx test`
- `pnpm --dir apps/api exec node --test test/route-permissions.test.js`
- `pnpm --dir apps/api exec node --test test/server.test.js --test-name-pattern "handleApiRoute fails fast when authService lacks authorizeRoute capability for protected routes|handleApiRoute re-evaluates mutable route definitions for authorization preflight"`
- `pnpm --dir apps/web exec node --test test/server.test.js --test-name-pattern "tenant mutation session state consumes rotated session fields from mutation payload"`
- `pnpm nx lint`
- `pnpm nx test`
- `pnpm --dir apps/api exec node --test test/route-permissions.test.js`
- `pnpm --dir apps/web exec node --test test/server.test.js`
- `pnpm --dir apps/api exec node --test test/server.test.js`
- `open -a Docker`
- `pnpm nx lint`
- `pnpm nx test`
- `pnpm --dir apps/api exec node --test test/server.test.js --test-name-pattern "createServer supports CORS preflight for API routes|createServer CORS preflight does not reflect origins outside allowlist|createServer CORS preflight includes HEAD when route is declared as GET"`
- `pnpm --dir apps/api exec node --test --test-force-exit test/auth.express.api.test.js --test-name-pattern "createApiApp parser and fallback error responses include access-control-allow-origin|createApiApp global error handler includes AUTH-500-INTERNAL error_code"`
- `pnpm --dir apps/api exec node --test test/route-permissions.test.js`
- `pnpm --dir apps/web exec node --test test/server.test.js --test-name-pattern "tenant mutation resolver differentiates missing tenant_options vs explicit empty list"`
- `pnpm --dir apps/api run check:route-permissions`
- `pnpm nx lint`
- `pnpm nx test`

### Completion Notes List

- ✅ Resolved review finding [HIGH]: `resolveAuthorizedSession` 现在始终执行 `assertValidAccessSession(accessToken)`，并对 `authorizationContext.session/user` 与已验证会话做强绑定校验（`session_id` + `user_id`）；不匹配或缺失直接返回 `AUTH-401-INVALID-ACCESS`，阻断伪造上下文绕过。
- ✅ Resolved review finding [MEDIUM]: 补齐 Story `File List`，新增 `apps/api/test/auth.domain.api.test.js`，与 git 实际变更对齐。
- ✅ Resolved review finding [MEDIUM]: 新增 auth.service 负向回归测试：覆盖“无效 token + 提供 authorizationContext 必须拒绝”与“context 与 token 绑定不一致必须拒绝”。
- ✅ Resolved review finding [HIGH]: API CORS 改为环境可配置 allowlist，`createServer` 与 `createApiApp` 均按白名单回写 `access-control-allow-origin`，移除默认全域 `*` 暴露。
- ✅ Resolved review finding [MEDIUM]: 权限声明校验不再接受 `OPTIONS` 方法声明，新增回归测试确保声明语义与可执行路由基线一致。
- ✅ Resolved review finding [MEDIUM]: `resolveTenantMutationUiState` 在 `hasTenantOptions=false` 且无历史候选时清空选择值，避免“选中值不在候选列表”导致 UI 状态漂移。
- ✅ Resolved review finding [HIGH]: CORS allowlist 未命中来源不再回写 fallback origin，未命中时移除 `access-control-allow-origin` 响应头，避免跨域拒绝语义与观测偏差。
- ✅ Resolved review finding [MEDIUM]: 菜单与按钮可见性规则统一为“无权限均不可见”；`menu` 与 `action` 统一由同一可操作权限判定驱动，并更新 Chrome 回归断言。
- ✅ Resolved review finding [MEDIUM]: `resolveTenantMutationUiState` 在 `hasTenantOptions=true` 且 options 为空时强制清空选择值，消除“选中值不在候选列表”的状态漂移。

### File List

- _bmad-output/implementation-artifacts/1-5-菜单-按钮-api-访问控制与统一拒绝语义.md
- _bmad-output/implementation-artifacts/sprint-status.yaml
- .env.example
- docker-compose.yml
- apps/api/src/route-permissions.js
- apps/api/src/config/env.js
- apps/api/src/modules/auth/auth.service.js
- apps/api/src/modules/auth/auth.routes.js
- apps/api/src/http-routes.js
- apps/api/src/server.js
- apps/api/src/app.js
- apps/api/src/openapi.js
- apps/api/scripts/check-route-permissions.js
- apps/api/package.json
- apps/api/project.json
- package.json
- apps/api/test/route-permissions.test.js
- apps/api/test/auth.service.test.js
- apps/api/test/auth.express.api.test.js
- apps/api/test/auth.domain.api.test.js
- apps/api/test/server.test.js
- apps/web/src/App.jsx
- apps/web/src/latest-request.mjs
- apps/web/src/tenant-mutation.mjs
- apps/web/test/server.test.js
- apps/web/test/chrome.playwright.test.js

## Change Log

- 2026-02-14: 执行 Senior Developer Code Review（CR）复核（本轮 #25）：覆盖 Story 1.5 对应源码与测试改动（排除 `_bmad/` 与 `_bmad-output/`），`git` 与 Story `File List` 无差异；校验 `pnpm --dir apps/api run check:route-permissions`、`pnpm --dir apps/api exec node --test test/route-permissions.test.js test/server.test.js`、`pnpm --dir apps/web exec node --test test/server.test.js`、`pnpm nx lint`、`pnpm nx test` 全绿，本轮无新增问题（High 0 / Medium 0 / Low 0），故事状态更新为 `done`。
- 2026-02-14: 关闭 CR #24 的 3 条 follow-ups（High 1 / Medium 2）：修复 CORS allowlist 未命中时 fallback origin 误回写、统一菜单/按钮无权限不可见规则并更新 UI 回归、修复 `tenant mutation` explicit empty options 分支选中值漂移；校验 `pnpm --dir apps/api run check:route-permissions`、`pnpm --dir apps/api exec node --test test/server.test.js`、`pnpm --dir apps/web exec node --test test/server.test.js`、`pnpm --dir apps/web exec node --test --test-name-pattern "chrome regression covers otp login flow with archived evidence" test/chrome.playwright.test.js`、`pnpm --dir apps/web exec node --test --test-name-pattern "chrome regression validates tenant permission UI against real API authorization semantics" test/chrome.playwright.test.js` 全通过，故事状态更新为 `review`。
- 2026-02-14: 执行 Senior Developer Code Review（CR）复核（本轮 #24）：新增 3 条 follow-ups（1 High / 2 Medium），问题集中在 CORS allowlist 未命中仍回写 fallback origin、Story 子任务“菜单/按钮规则统一”与实现验收口径不一致、以及 `tenant mutation` 在 explicit empty options 分支仍可写入无候选选中值；定向校验 `pnpm --dir apps/api run check:route-permissions`、`pnpm --dir apps/api exec node --test test/server.test.js`、`pnpm --dir apps/web exec node --test test/server.test.js` 全绿，状态维持 `in-progress`。
- 2026-02-14: 执行 Senior Developer Code Review（CR）复核（本轮 #23）：新增 3 条 follow-ups（1 High / 2 Medium），发现鉴权路由 CORS 仍为全域 `*` 放开、声明校验对 `OPTIONS` 方法语义与可执行路由基线不一致、以及 tenant mutation 在无候选集分支可生成无效选择值；定向校验 `pnpm --dir apps/api run check:route-permissions`、`pnpm --dir apps/api exec node --test test/server.test.js`、`pnpm --dir apps/web exec node --test test/server.test.js` 全绿，状态更新为 `in-progress`。
- 2026-02-14: 关闭 CR #23 的 3 条 follow-ups（High 1 / Medium 2）：完成 API CORS allowlist 化（server + app 双入口）、禁用 `OPTIONS` 路由权限声明并补充回归测试、修复 tenant mutation 在无候选列表时的无效选中值漂移；校验 `pnpm --dir apps/api run check:route-permissions`、`pnpm nx lint`、`pnpm nx test` 全通过，故事状态更新为 `review`。
