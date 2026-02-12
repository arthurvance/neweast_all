---
stepsCompleted:
  - 1
  - 2
  - 3
  - 4
  - 5
  - 6
  - 7
  - 8
inputDocuments:
  - '_bmad-output/planning-artifacts/prd.md'
  - '_bmad-output/planning-artifacts/prd-validation-report.md'
  - '_bmad-output/planning-artifacts/prd-appendix-legacy-inputs.md'
  - '_bmad-output/planning-artifacts/ux-design-specification.md'
workflowType: 'architecture'
lastStep: 8
status: 'complete'
completedAt: '2026-02-11T06:30:53Z'
project_name: 'neweast'
user_name: '老大'
date: '2026-02-11T05:16:45Z'
---

# Architecture Decision Document

_This document builds collaboratively through step-by-step discovery. Sections are appended as we work through each architectural decision together._

## Project Context Analysis

### Requirements Overview

**Functional Requirements:**
当前需求包含 80 条 FR，呈现“治理底座型”分层结构：认证入口、平台治理、组织治理、权限执行、成员生命周期、外部集成、审计追踪、治理控制与安全门禁。
从架构角度看，这不是单模块 CRUD，而是围绕“租户边界 + 权限一致性 + 高风险事务 + 集成治理”的系统性工程。FR 对发布门禁有明确绑定（尤其是幂等、负责人并发、租户边界、权限漏声明、删除级联一致性），意味着架构必须天然支持可验证性与可追踪性。

**Non-Functional Requirements:**
NFR 共 38 条，约束强度高：
- 性能：核心 API P95 <= 300ms，关键路径 P95/P99 目标明确。
- 安全：TLS、敏感数据保护、越域阻断、权限声明覆盖、token 重放识别。
- 可靠性：可用性/MTTD/MTTR 目标明确，负责人链路必须全成功/全回滚。
- 集成：重试策略、幂等去重、trace 字段覆盖、契约治理、Integration DoD。
- 可扩展与可访问：10x 增长压测目标、WCAG 2.1 AA 基线。
- 证据化验收：每项关键 NFR 都要求可归档证据。

**Scale & Complexity:**
项目呈现“高约束治理平台”特征，复杂度主要来自一致性与可运营性，而非 UI 花样。

- Primary domain: 全栈 Web 治理平台（API-first）
- Complexity level: High
- Estimated architectural components: 16（认证、会话、租户上下文、平台RBAC、组织RBAC、权限注册与执行、组织生命周期、负责人变更编排、审计、错误码体系、集成网关、异步事件与DLQ、配置中心、可观测、发布门禁、恢复与运维工具链）

### Technical Constraints & Dependencies

- 双域权限强隔离（platform/tenant）与服务端最终租户判定是硬约束。
- 关键写接口幂等键、并发冲突语义、事务一致性必须平台级统一。
- 会话版本与权限变更联动，要求认证与授权子系统强耦合协作。
- 外部集成采用“同步 + 异步”双通道，并要求版本治理、签名校验、重试与回放能力。
- 技术与发布流程依赖契约测试、回归门禁、审计追踪与演练证据链。
- UX 约束对实现方式有明确影响：桌面优先、无离线、统一交互容器与反馈语义、响应式断点与可访问性基线。

### Cross-Cutting Concerns Identified

- Tenant Isolation & Authorization Consistency
- Session Coherence & Token Security
- Idempotency, Concurrency Control & Transaction Boundaries
- Auditability, Traceability & Error Semantics
- Integration Reliability & Contract Governance
- Operational Readiness (monitoring, alerting, runbook, recovery drill)
- Release Gate Automation & Evidence Management

## Starter Template Evaluation

### Primary Technology Domain

Full-stack Web（治理后台 + API 服务） based on project requirements analysis.

### Starter Options Considered

- `Nx Monorepo (React + Vite + Nest)`：
  - 优势：前后端同仓、共享类型、统一 lint/test/build、适合门禁自动化与跨层一致性治理。
  - 代价：学习曲线略高于纯分仓脚手架。
- `Turborepo + pnpm workspaces`：
  - 优势：轻量灵活、缓存能力强。
  - 代价：React+Nest 组合的“开箱生成与工程约束”需要更多手工搭建。
- `前后端分离仓（create-vite + nest new）`：
  - 优势：结构直观、团队分工清晰。
  - 代价：共享契约与类型同步成本更高，不利于当前“强一致门禁”目标。

### Selected Starter: Nx Monorepo (TypeScript Full-stack)

**Rationale for Selection:**
结合你已确认的偏好（Vite + React + Ant Design 6、NestJS + JWT、MySQL、MVP 先 Web），Nx Monorepo 最匹配本项目的架构诉求：
- 便于前后端共享 DTO/权限码/错误码协议，降低契约漂移风险。
- 更容易把发布门禁（权限负测、契约测试、回归）做成统一流水线。
- 支持从本地优先开发平滑迁移到阿里云/腾讯云部署。

**Initialization Command:**

```bash
npx create-nx-workspace@latest neweast --preset=apps --pm=pnpm --nxCloud=skip --formatter=prettier
cd neweast

# Add plugins
pnpm add -D @nx/react @nx/nest

# Generate apps
pnpm nx g @nx/react:app web --bundler=vite --e2eTestRunner=playwright --style=css
pnpm nx g @nx/nest:app api --frontendProject=web --strict

# Frontend UI stack (MVP Web first)
pnpm add antd @ant-design/icons dayjs echarts

# Backend auth + DB stack
pnpm add @nestjs/jwt @nestjs/passport passport passport-jwt
pnpm add @nestjs/typeorm typeorm mysql2
pnpm add -D @types/passport-jwt
```

**Architectural Decisions Provided by Starter:**

**Language & Runtime:**
- TypeScript 全栈统一（前后端同语言、同类型系统）。
- Node.js 采用 LTS 线（当前建议 Node 24 LTS）。

**Styling Solution:**
- Web 端 UI 基线：Ant Design 6。
- `antd-mobile` 仅作为后续移动端阶段预留，不进入 MVP 交付范围。

**Build Tooling:**
- 前端：Vite。
- 后端：Nest + Nx executor。
- 工作区：Nx task graph + cache，支持后续 CI/CD 门禁扩展。

**Testing Framework:**
- 前端 E2E：Playwright（Chrome 为发布前验证主浏览器）。
- 后端与共享层测试可沿 Nx 统一测试入口扩展。

**Code Organization:**
- `apps/web`（管理端）
- `apps/api`（鉴权/治理 API）
- `libs/*`（后续共享协议、权限模型、错误码、基础设施）

**Development Experience:**
- 单仓统一命令、统一规范、统一质量门禁。
- 更适合你的“本地优先 + 后续云上部署”演进路径。

**Security/Session Baseline to implement in first stories:**
- JWT `access + refresh`；
- refresh rotation + replay detection；
- `session_version` 联动权限/身份变更失效历史会话。

**Note:** Project initialization using this command should be the first implementation story.

## Core Architectural Decisions

### Decision Priority Analysis

**Critical Decisions (Block Implementation):**
- Runtime baseline: Node.js 24 LTS（当前官方 LTS 线，22 为维护期 LTS）。
- Workspace: Nx Monorepo + pnpm。
- Data layer: MySQL 8.4 LTS + TypeORM + mysql2 + migrations。
- API style: REST + OpenAPI（契约优先）+ Problem Details 错误结构。
- Security/session baseline: JWT（RS256）+ refresh rotation + replay detection + session_version。
- Cache/control plane: Redis（用于限流、会话/权限收敛加速、热点授权路径）。

**Important Decisions (Shape Architecture):**
- Frontend state management: TanStack Query（服务端状态）+ Zustand（本地 UI 状态）。
- MVP scope: Web only（移动端延后，`antd-mobile` 暂不进入 MVP）。
- Deployment path: Local-first with Docker Compose, then containerized deployment on Alibaba Cloud / Tencent Cloud.

**Deferred Decisions (Post-MVP):**
- 移动端（H5/小程序）信息架构与组件策略落地细则。
- K8s 编排与多集群扩展时机。
- 多地域容灾与高级数据复制策略。

### Data Architecture

- Database engine: MySQL 8.4 LTS（按官方 8.4.x LTS 线推进）。
- ORM strategy: TypeORM（与 Nest 集成成熟，适配复杂关系建模与事务边界控制）。
- Driver: mysql2。
- Migration strategy: 版本化迁移脚本纳入 CI 门禁；禁止直接手工改线上 schema。
- Caching strategy: Redis 作为限流、会话与热点授权缓存层，DB 作为最终一致事实源。

### Authentication & Security

- Auth method: JWT access token + refresh token。
- JWT algorithm: RS256（为后续多服务验签与密钥轮换预留能力）。
- Refresh policy: rotation + replay detection（与 PRD 的 replay 防护要求一致）。
- Session consistency: 关键身份/权限状态变化后递增 session_version，旧会话即时失效。
- Authorization model: 双域 RBAC（`platform.*` / `tenant.*`）强隔离，组织域仅信任服务端有效租户上下文。
- API security baseline: 统一权限声明、漏声明阻断发布；统一错误码与 retryable 语义分层。

### API & Communication Patterns

- External API: REST-first，OpenAPI 为契约单一事实源。
- Error handling: Problem Details + 统一业务错误码映射。
- Rate limiting: 按 PRD 规则对认证链路执行手机号维度限流。
- Integration pattern: 同步 API + 异步事件/Webhook 双通道，幂等键 + 指数退避重试 + DLQ + 人工重放 Runbook。
- Observability fields: request_id / traceparent 全链路贯穿。

### Frontend Architecture

- Framework: React + Vite + TypeScript。
- UI system: Ant Design 6（MVP Web 一致体验基线）。
- Component strategy: 优先复用现有 `Custom*`，不足时补 AntD 原生组件。
- State model: TanStack Query + Zustand；避免把服务端状态与本地交互状态混杂。
- UX consistency constraints: Modal/Drawer/message/loading 防重与 PRD/UX 规范保持一致。

### Time Semantics Enforcement (NFR33)

- Source of truth:
  - Database time fields MUST remain UTC。
  - API time fields MUST return UTC values。
- Display rule:
  - Frontend display MUST convert UTC time to `Asia/Shanghai` before rendering。
  - Time format must remain consistent with UX baseline (`yyyy-mm-dd hh:mm`)。
- Implementation constraint:
  - Use centralized time-conversion utilities/hooks.
  - Do not implement page-local ad-hoc timezone conversions.
- Verification gates:
  - Unit tests: conversion edge cases (cross-day boundaries) must pass.
  - E2E tests: key pages must verify displayed `Asia/Shanghai` values against UTC API sources.
  - Release gate: `NFR33` check is mandatory; failure blocks release.

### Infrastructure & Deployment

- Local development baseline: Docker Compose（应用 + MySQL + Redis）。
- Cloud path (post-local): 阿里云或腾讯云容器化部署（先非 K8s 路径，降低运维复杂度）。
- CI/CD baseline: 类型检查、单测、契约测试、权限负向测试、门禁报告统一流水线。
- Monitoring/logging baseline: 审计事件、安全告警、SLO 指标（MTTD/MTTR）与发布证据归档。

### Decision Impact Analysis

**Implementation Sequence:**
1. 初始化 Nx 工作区与 `web/api` 应用骨架。
2. 建立认证与会话安全基线（JWT/refresh/session_version）。
3. 落地双域 RBAC、租户边界与权限声明门禁。
4. 固化 OpenAPI 契约、错误码体系与集成接口规范。
5. 引入 Redis 支撑限流、缓存与一致性收敛。
6. 建立审计、可观测、发布门禁与恢复演练闭环。

**Cross-Component Dependencies:**
- JWT 刷新链路与 session_version 直接耦合认证、授权、成员/组织生命周期。
- OpenAPI 契约与共享 DTO 会影响前后端并行开发节奏与回归策略。
- Redis 决策同时影响性能、风控（限流）与会话一致性实现路径。

## Implementation Patterns & Consistency Rules

### Pattern Categories Defined

**Critical Conflict Points Identified:**
5 大类（命名、结构、格式、通信、流程）共 18 个潜在分歧点。

### Naming Patterns

**Database Naming Conventions:**
- 表名：`snake_case` + 复数（`users`, `refresh_tokens`）
- 字段：`snake_case`（`user_id`, `created_at`）
- 索引：`idx_<table>_<cols>`；唯一约束：`uk_<table>_<cols>`

**API Naming Conventions:**
- REST 资源路径：复数（`/api/v1/users`）
- 路径参数：`/api/v1/users/{id}`
- Query 参数：`snake_case`（`page_size`）
- 写接口统一支持 `Idempotency-Key`

**Code Naming Conventions:**
- TS 变量/函数：`camelCase`
- 类/组件/类型：`PascalCase`
- 后端文件：`kebab-case.ts`；前端组件：`PascalCase.tsx`
- 权限码：`scope.resource.action`（如 `tenant.user.create`）

### Structure Patterns

**Project Organization:**
- `apps/web`（前端）、`apps/api`（后端）
- `libs/shared/contracts/*` 仅放 DTO/错误码/权限码/常量
- `libs/server/*` 仅后端可依赖
- 禁止 `apps/web` 依赖 `apps/api` 或 `libs/server/*`

**File Structure Patterns:**
- 后端按领域分模块：`auth/`, `platform/`, `tenant/`, `audit/`, `integration/`
- 模块内固定层：`controller`, `service`, `repository`, `dto`, `entities`
- 单测同目录：`*.spec.ts`
- E2E 独立：`apps/web-e2e`, `apps/api-e2e`

### Format Patterns

**API Response Formats:**
- 成功：`{ data, meta? }`
- 失败：Problem Details 扩展
- 错误结构固定：`{ type, title, status, detail, code, retryable, request_id }`

**Data Exchange Formats:**
- 外部 API 字段：统一 `snake_case`
- 内部 TS 字段：统一 `camelCase`
- 必须通过显式映射层转换，禁止跨层混用
- 时间字段：UTC ISO8601（如 `2026-02-11T06:30:00Z`）

### Communication Patterns

**Event System Patterns:**
- 事件命名：`domain.entity.action.v1`
- 事件最小字段：`event_id`, `request_id`, `occurred_at`, `schema_version`, `data`
- 破坏性变更必须升主版本（`v2`）

**State Management Patterns:**
- 服务端状态：TanStack Query
- 本地 UI 状态：Zustand
- Query key 必须使用统一 key factory，禁止散落字符串
- 禁止将 Query 数据冗余复制到 Zustand 形成双源

### Process Patterns

**Error Handling Patterns:**
- Controller 不吞错，统一异常过滤器输出 Problem Details
- 用户提示与日志语义分离
- 所有错误日志带 `request_id`

**Loading/Retry Patterns:**
- 所有提交按钮必须 `loading` + 防重复提交
- 自动重试仅限 `408/429/5xx`
- 所有写接口必须幂等保护
- 幂等冲突必须记录审计事件

**Frontend Testing Patterns (Mandatory):**
- 所有涉及前端页面的变更，必须使用真实 Chrome 浏览器进行测试。
- 允许并推荐使用 Playwright，且必须配置为 Chrome 项目（如 `--project=chrome` 或 `channel: "chrome"`）。
- 仅组件单测或非真实 Chrome 运行结果，不可作为页面功能验收依据。

### Enforcement Guidelines

**All AI Agents MUST:**
- 遵循统一命名/目录/响应格式，不得引入第二套风格
- 新增受保护接口必须声明权限码，否则阻断 CI
- 身份/权限关键变更必须联动 `session_version`
- 变更接口契约必须同步更新 OpenAPI 与共享 DTO
- 前端页面改动必须通过真实 Chrome + Playwright 门禁

**Pattern Enforcement:**
- Contract lint：校验字段命名、Problem Details、错误码完整性
- Security gate：校验受保护接口权限声明覆盖率
- Session gate：关键写操作触发 `session_version` 测试
- Replay gate：refresh rotation/replay detection 并发用例必须通过
- Frontend gate：执行 Playwright Chrome 项目测试，未通过即阻断合并/发布
- 违规记录：在架构文档变更附录登记并给出修复 PR

### Pattern Examples

**Good Examples:**
- `POST /api/v1/tenant-members` + `Idempotency-Key`
- `platform.org.owner_changed.v1`
- 错误返回含 `code/retryable/request_id`
- 页面功能改动附带 Playwright Chrome 通过记录

**Anti-Patterns:**
- `userId` 与 `user_id` 在同层混用
- 接口返回结构不统一（有的 `{data}`，有的裸对象）
- Query 数据复制到 Zustand 导致状态漂移
- 仅跑组件单测或默认浏览器仿真，不跑真实 Chrome 页面测试

## Project Structure & Boundaries

### Complete Project Directory Structure

```text
neweast/
├── README.md
├── package.json
├── pnpm-workspace.yaml
├── nx.json
├── tsconfig.base.json
├── .gitignore
├── .editorconfig
├── .env.example
├── .github/
│   └── workflows/
│       ├── ci.yml
│       ├── contract-gate.yml
│       ├── security-gate.yml
│       └── frontend-chrome-gate.yml
├── docker/
│   ├── docker-compose.local.yml
│   ├── mysql/
│   │   └── init.sql
│   └── redis/
│       └── redis.conf
├── tools/
│   ├── scripts/
│   │   ├── verify-openapi.ts
│   │   ├── verify-permission-declarations.ts
│   │   └── verify-session-version-tests.ts
│   └── generators/
├── apps/
│   ├── web/
│   │   ├── project.json
│   │   ├── tsconfig.json
│   │   ├── vite.config.ts
│   │   ├── index.html
│   │   ├── src/
│   │   │   ├── main.tsx
│   │   │   ├── App.tsx
│   │   │   ├── app/
│   │   │   │   ├── router/
│   │   │   │   ├── providers/
│   │   │   │   └── store/
│   │   │   ├── pages/
│   │   │   │   ├── auth/
│   │   │   │   ├── platform/
│   │   │   │   │   ├── orgs/
│   │   │   │   │   ├── users/
│   │   │   │   │   └── roles/
│   │   │   │   ├── tenant/
│   │   │   │   │   ├── members/
│   │   │   │   │   └── roles/
│   │   │   │   └── audit/
│   │   │   ├── components/
│   │   │   │   ├── CustomCard.tsx
│   │   │   │   ├── CustomCardTable.tsx
│   │   │   │   ├── CustomFilter.tsx
│   │   │   │   ├── CustomForm.tsx
│   │   │   │   ├── CustomLayout.tsx
│   │   │   │   ├── CustomPage.tsx
│   │   │   │   ├── CustomPanel.tsx
│   │   │   │   └── CustomPanelTable.tsx
│   │   │   ├── features/
│   │   │   │   ├── auth/{api.ts,hooks.ts,types.ts,components/}
│   │   │   │   ├── platform-governance/{api.ts,hooks.ts,types.ts,components/}
│   │   │   │   ├── tenant-governance/{api.ts,hooks.ts,types.ts,components/}
│   │   │   │   ├── permission/{api.ts,hooks.ts,types.ts,components/}
│   │   │   │   └── integration/{api.ts,hooks.ts,types.ts,components/}
│   │   │   ├── api/
│   │   │   │   ├── client.ts
│   │   │   │   ├── interceptors.ts
│   │   │   │   └── mappers/
│   │   │   ├── query/
│   │   │   │   ├── queryKeys.ts
│   │   │   │   └── hooks/
│   │   │   ├── state/
│   │   │   │   └── zustand/
│   │   │   ├── utils/
│   │   │   └── styles/
│   │   └── public/
│   ├── api/
│   │   ├── project.json
│   │   ├── tsconfig.app.json
│   │   ├── nest-cli.json
│   │   └── src/
│   │       ├── main.ts
│   │       ├── app.module.ts
│   │       ├── config/
│   │       │   ├── env.schema.ts
│   │       │   ├── app.config.ts
│   │       │   ├── db.config.ts
│   │       │   └── redis.config.ts
│   │       ├── common/
│   │       │   ├── decorators/
│   │       │   ├── guards/
│   │       │   ├── interceptors/
│   │       │   ├── filters/
│   │       │   ├── pipes/
│   │       │   └── middleware/
│   │       ├── modules/
│   │       │   ├── auth/
│   │       │   │   ├── index.ts
│   │       │   │   ├── controllers/
│   │       │   │   ├── services/
│   │       │   │   ├── dto/
│   │       │   │   └── entities/
│   │       │   ├── platform/
│   │       │   │   ├── index.ts
│   │       │   │   ├── orgs/
│   │       │   │   ├── users/
│   │       │   │   └── roles/
│   │       │   ├── tenant/
│   │       │   │   ├── index.ts
│   │       │   │   ├── members/
│   │       │   │   └── roles/
│   │       │   ├── permission/
│   │       │   │   └── index.ts
│   │       │   ├── audit/
│   │       │   │   └── index.ts
│   │       │   ├── integration/
│   │       │   │   └── index.ts
│   │       │   └── health/
│   │       ├── persistence/
│   │       │   ├── typeorm/
│   │       │   │   ├── data-source.ts
│   │       │   │   ├── migrations/
│   │       │   │   └── subscribers/
│   │       │   ├── repositories/
│   │       │   └── seeds/
│   │       └── events/
│   │           ├── publishers/
│   │           ├── consumers/
│   │           └── schemas/
│   ├── web-e2e/
│   │   ├── project.json
│   │   ├── playwright.config.ts
│   │   ├── tests/
│   │   │   ├── auth/
│   │   │   ├── platform/
│   │   │   ├── tenant/
│   │   │   └── regression/
│   │   ├── fixtures/
│   │   └── artifacts/
│   │       ├── screenshots/
│   │       ├── traces/
│   │       └── videos/
│   └── api-e2e/
│       ├── project.json
│       ├── jest.config.ts
│       └── tests/
│           ├── security/
│           ├── idempotency/
│           └── session-version/
├── libs/
│   ├── shared/
│   │   ├── contracts/
│   │   │   ├── dto/
│   │   │   ├── errors/
│   │   │   ├── permissions/
│   │   │   └── openapi/
│   │   │       └── v1/
│   │   ├── types/
│   │   └── utils/
│   ├── server/
│   │   ├── infra/
│   │   │   ├── db/
│   │   │   ├── redis/
│   │   │   └── queue/
│   │   └── domain/
│   │       ├── auth/
│   │       ├── rbac/
│   │       ├── tenant-context/
│   │       ├── idempotency/
│   │       ├── auditing/
│   │       └── observability/
│   └── testing/
│       ├── fixtures/
│       ├── testcontainers/
│       └── helpers/
└── docs/
    ├── architecture/
    │   └── adr/
    ├── api/
    │   └── changelog/
    └── runbooks/
        ├── security/
        ├── recovery/
        └── integration/
```

### Architectural Boundaries

**API Boundaries:**
- `apps/api` 仅通过 REST 暴露外部契约，契约定义在 `libs/shared/contracts/openapi/v1`。
- 鉴权/授权边界在 `common/guards` + `modules/permission`，禁止分散在 controller 私有逻辑。
- Problem Details 输出仅允许 `common/filters` 统一实现。

**Component Boundaries:**
- `apps/web/pages` 负责页面路由与编排。
- `apps/web/features` 负责业务能力，且遵循固定目录模板。
- `apps/web/components` 负责可复用 UI 组件。
- `apps/web` 禁止依赖 `apps/api` 或 `libs/server/*`。
- `apps/web/src/api/mappers` 是前后端字段转换唯一入口。

**Service Boundaries:**
- `modules/auth` 只负责认证与 token 生命周期。
- `modules/platform` / `modules/tenant` 负责各自域业务。
- `modules/permission` 提供统一权限判断与声明校验。
- 模块间仅允许通过 service 或 domain event 通信，禁止跨模块 repository 互调。

**Data Boundaries:**
- 数据事实源：MySQL（TypeORM）。
- 缓存/控制面：Redis（限流、会话收敛、热点权限）。
- 迁移唯一入口：`persistence/typeorm/migrations`。
- 审计记录统一落 `modules/audit`。

### Requirements to Structure Mapping

**Feature/Epic Mapping (按 FR 类别):**
- 认证与会话（FR1-FR9, FR53, FR62-63, FR67）→ `modules/auth`, `pages/auth`, `web-e2e/tests/auth`
- 平台治理（FR10-FR18）→ `modules/platform/*`, `pages/platform/*`
- 组织治理（FR19-FR25, FR32-35）→ `modules/tenant/*`, `pages/tenant/*`
- 权限执行（FR26-FR31, FR49-52, FR72-75）→ `modules/permission`, `libs/server/domain/rbac`
- 集成互操作（FR36-FR41, FR55-58）→ `modules/integration`, `events/*`, `docs/runbooks/integration`
- 审计与可追踪（FR42-FR45, FR80）→ `modules/audit`, `libs/server/domain/observability`

**Cross-Cutting Concerns:**
- `session_version` 一致性：`libs/server/domain/auth` + `modules/auth` + 相关写操作服务
- 错误码与契约：`libs/shared/contracts/errors` + `openapi/v1`
- 幂等：`libs/server/domain/idempotency` + 写接口中间件/拦截器

### Integration Points

**Internal Communication:**
- web → api: REST + OpenAPI client
- api 内部：service orchestration + domain events
- shared contract：前后端统一引用 `libs/shared/contracts`

**External Integrations:**
- 同步：`modules/integration` outbound clients
- 异步：`events/publishers|consumers` + DLQ/replay runbook

**Data Flow:**
- 请求进入 → auth guard → permission check → domain service → repository
- 写操作同时触发审计与必要事件
- 关键身份/权限写操作后触发 `session_version` 收敛

### File Organization Patterns

**Configuration Files:**
- 根目录集中基础配置。
- 应用专属配置留在各 app 目录。
- 环境变量统一 schema 校验。

**Source Organization:**
- 按领域模块化，不按技术层平铺。
- 共用契约进入 `shared`，后端专用能力进入 `server/domain|infra`。

**Test Organization:**
- 单测同目录。
- API E2E 独立并按安全关键能力分组。
- 前端页面测试统一 `apps/web-e2e` 且必须真实 Chrome（Playwright）。

**Asset Organization:**
- 静态资源仅在 `apps/web/public`。
- 测试产物统一归档到 `apps/web-e2e/artifacts`。
- 文档与运行手册放 `docs/*`。

### Development Workflow Integration

**Branch & Environment Mapping:**
- `feature/*`：功能开发与本地联调分支。
- `develop`：测试环境发布分支。
- `main`：生产环境发布分支。

**Development Server Structure:**
- `pnpm nx serve web`
- `pnpm nx serve api`
- 本地依赖服务通过 `docker/docker-compose.local.yml`

**PR Quality Gates (Required Checks):**
- 基础门禁：`lint`、`typecheck`、`unit test`、`build`（建议 `nx affected` 驱动）。
- 契约门禁：OpenAPI 一致性校验。
- 安全门禁：受保护接口权限声明覆盖校验。
- API 关键 E2E：`security`、`idempotency`、`session-version`。
- 前端页面门禁（强制）：Playwright 真实 Chrome（`project=chrome` 或 `channel: "chrome"`）。
- 产物归档：测试报告、Playwright `screenshot/trace/video`、门禁摘要。

**Test Environment Deployment (develop):**
- 触发：`develop` 分支合并/推送。
- 流程：构建镜像并推送制品库 → 部署测试环境 → 执行 smoke + 契约回归子集。
- 失败策略：自动回滚到上一稳定镜像并触发告警。

**Production Deployment (main):**
- 触发：`main` 分支合并/推送（建议保留人工审批）。
- 流程：migration dry-run → migration apply → 灰度发布 → 生产 smoke → 全量发布。
- 失败策略：自动回滚并记录发布/回滚审计日志。

**Post-Release Verification:**
- 核心指标：鉴权失败率、越权拒绝率、负责人变更失败率。
- 追踪要求：`request_id/traceparent` 全链路可追踪。
- 审计要求：关键安全与治理操作可检索可追溯。

**Branch Protection & Merge Policy:**
- 受保护分支：`develop`、`main`。
- 禁止直推，必须 PR 合并。
- 必须全部 Required Checks 通过后才能合并。
- 建议合并策略：`feature/* -> develop` 使用 squash（历史更清晰）；`develop -> main` 使用 merge commit（保留发布上下文）。

**Repository Noise Control (.gitignore):**
- 忽略：`node_modules/`、`dist/`、`coverage/`、`playwright-report/`、`test-results/`、`*.log`、`.DS_Store`、`.env*`。
- 保留：`.env.example`。
- 个人临时忽略放 `.git/info/exclude`，避免污染团队规则。

## Architecture Validation Results

### Coherence Validation ✅

**Decision Compatibility:**
- 技术选型组合兼容：Node 24 LTS、Nx、pnpm、TypeScript 全栈、React/Vite/AntD6、Nest/TypeORM/MySQL/Redis。
- 安全链路闭环：JWT（RS256）+ refresh rotation + replay detection + `session_version`。
- 契约与错误模型一致：REST + OpenAPI + Problem Details + 统一错误码。
- CI/CD 与开发流程约束与上述决策一致。

**Pattern Consistency:**
- 命名、结构、格式、通信、流程规则覆盖关键冲突点并可执行。
- 外部 `snake_case` / 内部 `camelCase` 与映射层边界清晰。
- 真实 Chrome + Playwright 页面测试已纳入强制门禁。
- 事件命名、幂等、审计与错误格式规则一致且可验证。

**Structure Alignment:**
- `apps/web|api` 与 `libs/shared|server|testing` 边界清晰，契约共享与版本化路径明确。
- 模块通信禁止项（跨模块 repository 互调）已定义。
- 测试资产、ADR、runbook、API changelog 均有目录落点。

### Requirements Coverage Validation ✅

**Feature Coverage:**
- 按 FR 分类映射到认证、平台治理、组织治理、权限执行、集成、审计六大能力域，均有明确模块归属。

**Functional Requirements Coverage:**
- FR1-FR80 均被当前架构能力覆盖，特别是高风险项（租户隔离、幂等、并发冲突、权限声明防漏、会话收敛）已有落地边界。

**Non-Functional Requirements Coverage:**
- 性能：缓存层、边界分层、可扩展结构支持后续压测优化。
- 安全：鉴权算法、会话一致性、权限门禁、错误语义完整。
- 可靠性：审计、可观测、DLQ/replay、回滚与 runbook 支撑。
- 质量：前端页面真实 Chrome 测试与 CI 门禁机制已定义。

### Implementation Readiness Validation ✅

**Decision Completeness:**
- 关键决策、版本线、约束与执行命令已文档化，可直接指导多 Agent 一致实现。

**Structure Completeness:**
- 项目树、边界、映射、测试与部署支持文件路径完整且具体。

**Pattern Completeness:**
- 冲突高发区域规则齐备，包含 Good/Anti-Pattern 与门禁执行点。

### Gap Analysis Results

**Critical Gaps:** 无阻断项。

**Important Gaps（后续建议）:**
- JWT 密钥轮换与密钥托管（KMS）操作细则可进一步固化为安全 runbook。
- OpenAPI 发布流程可补充自动化生成与变更审阅流水线细节。
- 可观测告警阈值模板可进一步参数化，减少环境差异。

**Nice-to-Have Gaps:**
- Query key 静态规则检查工具化增强。
- 事件 schema CI 校验链路进一步自动化。

### Validation Issues Addressed

- 已补充前端页面真实 Chrome 测试为强制门禁项。
- 已补充模块边界、防腐映射层、契约版本化与测试资产归档规则。

### Architecture Completeness Checklist

**✅ Requirements Analysis**
- [x] Project context thoroughly analyzed
- [x] Scale and complexity assessed
- [x] Technical constraints identified
- [x] Cross-cutting concerns mapped

**✅ Architectural Decisions**
- [x] Critical decisions documented with versions
- [x] Technology stack fully specified
- [x] Integration patterns defined
- [x] Performance considerations addressed

**✅ Implementation Patterns**
- [x] Naming conventions established
- [x] Structure patterns defined
- [x] Communication patterns specified
- [x] Process patterns documented

**✅ Project Structure**
- [x] Complete directory structure defined
- [x] Component boundaries established
- [x] Integration points mapped
- [x] Requirements to structure mapping complete

### Architecture Readiness Assessment

**Overall Status:** READY FOR IMPLEMENTATION  
**Confidence Level:** High

**Key Strengths:**
- 架构决策、实现约束、结构边界与门禁命令形成闭环。
- 多 Agent 并行开发冲突点已有系统性规避策略。
- CI/CD 与质量门禁规则可执行、可追溯。

**Areas for Future Enhancement:**
- 密钥管理与告警模板可进一步产品化与自动化。

### Implementation Handoff

**AI Agent Guidelines:**
- 严格按本架构文档执行，不引入第二套规范。
- 页面相关变更必须通过真实 Chrome + Playwright。
- 关键身份/权限变更必须联动 `session_version`。

**First Implementation Priority:**
- 启动首个故事并建立最小可运行骨架，优先打通认证会话、契约门禁与前端真实 Chrome 测试链路。
