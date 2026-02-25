---
title: 'Auth 大文件领域化能力切分与语义命名重构（无行为变更）'
slug: 'auth-domain-capability-splitting-refactor'
created: '2026-02-25T22:01:00+08:00'
status: 'ready-for-dev'
stepsCompleted: [1, 2, 3, 4]
tech_stack:
  - 'Node.js 24 (CommonJS)'
  - 'pnpm + Nx monorepo'
  - 'NestJS host + custom Express route dispatcher'
  - 'MySQL (mysql2) + Redis (ioredis)'
  - 'Node built-in test runner (node:test + assert/strict)'
  - 'Babel parser codemod tooling (@babel/parser)'
files_to_modify:
  - '/Users/helloworld/dev/neweast/tools/domain-contract/capability-map.json'
  - '/Users/helloworld/dev/neweast/tools/domain-contract/naming-rules.json'
  - '/Users/helloworld/dev/neweast/apps/api/src/modules/auth/auth.service.js'
  - '/Users/helloworld/dev/neweast/apps/api/src/modules/auth/auth.store.memory.js'
  - '/Users/helloworld/dev/neweast/apps/api/src/modules/auth/auth.store.mysql.js'
  - '/Users/helloworld/dev/neweast/apps/api/src/modules/auth/store-methods/auth-store-memory-capabilities.js'
  - '/Users/helloworld/dev/neweast/apps/api/src/modules/auth/store-methods/auth-store-mysql-capabilities.js'
  - '/Users/helloworld/dev/neweast/apps/api/src/modules/auth/auth.routes.js'
  - '/Users/helloworld/dev/neweast/apps/api/src/modules/auth/auth.handlers.js'
  - '/Users/helloworld/dev/neweast/apps/api/src/modules/auth/login-service.js'
  - '/Users/helloworld/dev/neweast/apps/api/src/modules/auth/session-service.js'
  - '/Users/helloworld/dev/neweast/apps/api/src/modules/auth/tenant-context-service.js'
  - '/Users/helloworld/dev/neweast/apps/api/src/modules/auth/entry-policy-service.js'
  - '/Users/helloworld/dev/neweast/apps/api/src/modules/auth/route-preauthorization.js'
  - '/Users/helloworld/dev/neweast/apps/api/src/modules/auth/permission-context-builder.js'
  - '/Users/helloworld/dev/neweast/apps/api/src/modules/auth/permission-catalog.js'
  - '/Users/helloworld/dev/neweast/apps/api/src/modules/auth/repositories/index.js'
  - '/Users/helloworld/dev/neweast/apps/api/src/modules/auth/repositories/repository-helpers.js'
  - '/Users/helloworld/dev/neweast/apps/api/src/modules/auth/repositories/domain-access-repository.js'
  - '/Users/helloworld/dev/neweast/apps/api/src/modules/auth/repositories/session-repository.js'
  - '/Users/helloworld/dev/neweast/apps/api/src/modules/auth/repositories/permission-repository.js'
  - '/Users/helloworld/dev/neweast/apps/api/src/modules/auth/repositories/user-repository.js'
  - '/Users/helloworld/dev/neweast/apps/api/src/modules/auth/repositories/tenant-membership-repository.js'
  - '/Users/helloworld/dev/neweast/apps/api/src/shared-kernel/auth/auth-capabilities.js'
  - '/Users/helloworld/dev/neweast/apps/api/src/shared-kernel/auth/auth-problem-error.js'
  - '/Users/helloworld/dev/neweast/apps/api/src/shared-kernel/auth/auth-route-handlers.js'
  - '/Users/helloworld/dev/neweast/apps/api/src/shared-kernel/auth/route-authz.js'
  - '/Users/helloworld/dev/neweast/apps/api/src/shared-kernel/auth/core/auth-problem-error.js'
  - '/Users/helloworld/dev/neweast/apps/api/src/shared-kernel/auth/core/auth-constants.js'
  - '/Users/helloworld/dev/neweast/apps/api/src/shared-kernel/auth/core/auth-normalizers.js'
  - '/Users/helloworld/dev/neweast/apps/api/src/shared-kernel/auth/core/auth-audit-idempotency.service.js'
  - '/Users/helloworld/dev/neweast/apps/api/src/bootstrap/create-shared-kernel.js'
  - '/Users/helloworld/dev/neweast/apps/api/src/bootstrap/create-route-runtime.js'
  - '/Users/helloworld/dev/neweast/apps/api/src/http-routes.js'
  - '/Users/helloworld/dev/neweast/apps/api/src/app.js'
  - '/Users/helloworld/dev/neweast/apps/api/src/domains/platform/auth/session/index.js'
  - '/Users/helloworld/dev/neweast/apps/api/src/domains/platform/auth/session/session.service.js'
  - '/Users/helloworld/dev/neweast/apps/api/src/domains/platform/auth/session/session.store.memory.js'
  - '/Users/helloworld/dev/neweast/apps/api/src/domains/platform/auth/session/session.store.mysql.js'
  - '/Users/helloworld/dev/neweast/apps/api/src/domains/platform/auth/context/index.js'
  - '/Users/helloworld/dev/neweast/apps/api/src/domains/platform/auth/context/context.service.js'
  - '/Users/helloworld/dev/neweast/apps/api/src/domains/platform/auth/context/context.store.memory.js'
  - '/Users/helloworld/dev/neweast/apps/api/src/domains/platform/auth/context/context.store.mysql.js'
  - '/Users/helloworld/dev/neweast/apps/api/src/domains/platform/auth/provisioning/index.js'
  - '/Users/helloworld/dev/neweast/apps/api/src/domains/platform/auth/provisioning/provisioning.service.js'
  - '/Users/helloworld/dev/neweast/apps/api/src/domains/platform/auth/provisioning/provisioning.store.memory.js'
  - '/Users/helloworld/dev/neweast/apps/api/src/domains/platform/auth/provisioning/provisioning.store.mysql.js'
  - '/Users/helloworld/dev/neweast/apps/api/src/domains/platform/auth/governance/index.js'
  - '/Users/helloworld/dev/neweast/apps/api/src/domains/platform/auth/governance/governance.service.js'
  - '/Users/helloworld/dev/neweast/apps/api/src/domains/platform/auth/governance/governance.store.memory.js'
  - '/Users/helloworld/dev/neweast/apps/api/src/domains/platform/auth/governance/governance.store.mysql.js'
  - '/Users/helloworld/dev/neweast/apps/api/src/domains/platform/auth/system-config/index.js'
  - '/Users/helloworld/dev/neweast/apps/api/src/domains/platform/auth/system-config/system-config.service.js'
  - '/Users/helloworld/dev/neweast/apps/api/src/domains/platform/auth/system-config/system-config.store.memory.js'
  - '/Users/helloworld/dev/neweast/apps/api/src/domains/platform/auth/system-config/system-config.store.mysql.js'
  - '/Users/helloworld/dev/neweast/apps/api/src/domains/platform/auth/integration/index.js'
  - '/Users/helloworld/dev/neweast/apps/api/src/domains/platform/auth/integration/integration.service.js'
  - '/Users/helloworld/dev/neweast/apps/api/src/domains/platform/auth/integration/integration.store.memory.js'
  - '/Users/helloworld/dev/neweast/apps/api/src/domains/platform/auth/integration/integration.store.mysql.js'
  - '/Users/helloworld/dev/neweast/apps/api/src/domains/tenant/auth/session/index.js'
  - '/Users/helloworld/dev/neweast/apps/api/src/domains/tenant/auth/session/session.service.js'
  - '/Users/helloworld/dev/neweast/apps/api/src/domains/tenant/auth/session/session.store.memory.js'
  - '/Users/helloworld/dev/neweast/apps/api/src/domains/tenant/auth/session/session.store.mysql.js'
  - '/Users/helloworld/dev/neweast/apps/api/src/domains/tenant/auth/context/index.js'
  - '/Users/helloworld/dev/neweast/apps/api/src/domains/tenant/auth/context/context.service.js'
  - '/Users/helloworld/dev/neweast/apps/api/src/domains/tenant/auth/context/context.store.memory.js'
  - '/Users/helloworld/dev/neweast/apps/api/src/domains/tenant/auth/context/context.store.mysql.js'
  - '/Users/helloworld/dev/neweast/apps/api/src/domains/tenant/auth/provisioning/index.js'
  - '/Users/helloworld/dev/neweast/apps/api/src/domains/tenant/auth/provisioning/provisioning.service.js'
  - '/Users/helloworld/dev/neweast/apps/api/src/domains/tenant/auth/provisioning/provisioning.store.memory.js'
  - '/Users/helloworld/dev/neweast/apps/api/src/domains/tenant/auth/provisioning/provisioning.store.mysql.js'
  - '/Users/helloworld/dev/neweast/apps/api/src/domains/tenant/auth/governance/index.js'
  - '/Users/helloworld/dev/neweast/apps/api/src/domains/tenant/auth/governance/governance.service.js'
  - '/Users/helloworld/dev/neweast/apps/api/src/domains/tenant/auth/governance/governance.store.memory.js'
  - '/Users/helloworld/dev/neweast/apps/api/src/domains/tenant/auth/governance/governance.store.mysql.js'
  - '/Users/helloworld/dev/neweast/tools/lint-rules/file-granularity-thresholds.js'
  - '/Users/helloworld/dev/neweast/apps/api/test/contracts/auth.service.public-contract.test.js'
  - '/Users/helloworld/dev/neweast/apps/api/test/contracts/auth.store.contract.test.js'
  - '/Users/helloworld/dev/neweast/apps/api/test/auth.service.test.js'
  - '/Users/helloworld/dev/neweast/apps/api/test/auth.store.mysql.test.js'
  - '/Users/helloworld/dev/neweast/apps/api/test/auth.store.memory.platform-user-read.test.js'
  - '/Users/helloworld/dev/neweast/apps/api/test/auth.api.test.js'
  - '/Users/helloworld/dev/neweast/apps/api/test/auth.domain.api.test.js'
  - '/Users/helloworld/dev/neweast/apps/api/test/domain-contract.guards.test.js'
  - '/Users/helloworld/dev/neweast/apps/api/test/domain.symmetry.test.js'
  - '/Users/helloworld/dev/neweast/apps/api/src/shared-kernel/auth/create-auth-service.js'
  - '/Users/helloworld/dev/neweast/apps/api/src/shared-kernel/auth/store/create-in-memory-auth-store.js'
  - '/Users/helloworld/dev/neweast/apps/api/src/shared-kernel/auth/store/create-mysql-auth-store.js'
  - '/Users/helloworld/dev/neweast/apps/api/src/modules/auth/refactor-migration-map.md'
  - '/Users/helloworld/dev/neweast/apps/api/scripts/refactor-auth-import-paths.js'
  - '/Users/helloworld/dev/neweast/apps/api/test/contracts/auth.incremental-contract.guard.test.js'
  - '/Users/helloworld/dev/neweast/apps/api/test/contracts/auth.facade-structure.test.js'
  - '/Users/helloworld/dev/neweast/apps/api/test/domain-contract.no-cycle-auth.test.js'
  - '/Users/helloworld/dev/neweast/tools/domain-contract/check-auth-import-cycles.js'
  - '/Users/helloworld/dev/neweast/tools/domain-contract/capability-boundary-rules.json'
  - '/Users/helloworld/dev/neweast/tools/domain-contract/capability-decision-log.json'
  - '/Users/helloworld/dev/neweast/tools/domain-contract/check-domain-symmetry.js'
  - '/Users/helloworld/dev/neweast/tools/domain-contract/check-capability-boundaries.js'
  - '/Users/helloworld/dev/neweast/tools/domain-contract/check-layer-responsibilities.js'
  - '/Users/helloworld/dev/neweast/apps/api/test/domain-contract.capability-boundary.test.js'
  - '/Users/helloworld/dev/neweast/apps/api/test/domain-contract.layer-responsibility.test.js'
  - '/Users/helloworld/dev/neweast/apps/api/src/modules/auth/refactor-rollback-checklist.md'
  - '/Users/helloworld/dev/neweast/apps/api/package.json'
  - '/Users/helloworld/dev/neweast/package.json'
code_patterns:
  - 'Factory-first: createXxx() 返回 capability object，调用端组合装配'
  - 'AuthService monolith facade：单服务暴露 50 个能力入口'
  - 'Store port contract：memory/mysql 保持同名方法镜像（核心 34 项）'
  - 'Repository adapter：通过 createRequiredDelegate/createOptionalDelegate 解耦 authStore'
  - 'Shared-kernel wrappers：迁移期可桥接，最终实现应沉淀在 domains/*/auth/{capability} 下'
  - 'Domain runtime composition：createRouteRuntime -> platform/tenant runtime handlers 聚合'
test_patterns:
  - 'node:test + assert/strict'
  - 'API 集成测试经 handleApiRoute 驱动，依赖 createAuthService 注入'
  - 'Store 测试通过 mock dbClient.query/inTransaction 验证 SQL 语义与事务行为'
  - '领域治理测试通过 runDomainSymmetryCheck 与 lint rule 模块断言门禁'
  - 'auth.service.test.js 体量极大，覆盖认证核心行为与错误码语义'
---

# Tech-Spec: Auth 大文件领域化能力切分与语义命名重构（无行为变更）

**Created:** 2026-02-25T22:01:00+08:00

## Overview

### Problem Statement

当前 `apps/api/src/modules/auth` 中存在多个超大文件（`auth.service.js`、`auth.store.memory.js`、`auth.store.mysql.js` 以及 `store-methods/*capabilities.js`），并混合 platform/tenant/公共能力，导致边界不清、定位成本高、变更风险高；同时部分命名过于宽泛（如 `*-capabilities.js`），难以从文件名判断职责。

### Solution

采用“领域优先 + 能力切分 + 语义命名”的重构方案：将认证相关实现按 `domains/{platform|tenant|shared}/auth/*` 与 capability 颗粒拆分，统一 memory/mysql 在 port/contract 层的接口语义，清理宽泛命名，保持 API 行为与权限/审计语义不变。

### Scope

**In Scope:**
- 纳入并重构 `auth.service.js`、`auth.store.memory.js`、`auth.store.mysql.js`、`store-methods/auth-store-memory-capabilities.js`、`store-methods/auth-store-mysql-capabilities.js`，以及其直接关联的 auth 能力文件。
- 按“领域边界(platform/tenant/shared) > 能力(capability) > 实现适配(memory/mysql)”拆分目录与文件职责。
- 覆盖并迁移 `auth.service`/`auth.store.*` 中剩余治理能力（platform/tenant user-role governance、system-config、integration、audit/idempotency）以闭合旧聚合文件删除前置条件。
- 用语义化动作命名替代宽泛命名（禁止继续新增 `*-capabilities.js`）。
- 在“只重构不改行为”前提下，对过小且语义可合并文件做适度收敛。
- 补充门禁：大文件阈值、命名规则、跨域 import、capability contract 一致性检查。

**Out of Scope:**
- 新增业务能力或产品需求。
- 对外 API 契约、权限策略语义、审计事件语义的行为变更。
- 非 auth 相关模块的结构性重写（除必要依赖适配外）。

## Context for Development

### Codebase Patterns

- 目录治理基线已经存在并启用：`domains/{domain}/{module}/{capability}`，`platform/tenant` 对称性由 `check-domain-symmetry` 约束。
- `modules/auth` 当前仍是核心聚合层，`auth.service.js`（8511 行）暴露 50 个 public 能力，跨越 session/context/provisioning + settings/config + audit/idempotency。
- `auth.store.memory.js`（8259 行）与 `auth.store.mysql.js`（10649 行）同时承载 auth 核心 + platform integration/config 相关能力，领域职责混杂明显。
- `store-methods/auth-store-*-capabilities.js` 已抽出一部分通用 capability（各 34 项），但命名过泛且仍是大聚合，未形成稳定 capability 文件边界。
- 认证支撑层已具备可复用分层：`login-service` / `session-service` / `tenant-context-service` / `entry-policy-service` / `permission-context-builder` / `repositories/*`。
- shared-kernel 已存在（`apps/api/src/shared-kernel/auth/*`），目前主要做转发；具备承接薄公共层的结构条件。
- 目标域目录已经就绪但为空：`apps/api/src/domains/{platform|tenant}/auth/{session|context|provisioning}` 仅 `.gitkeep`，可直接承接迁移。
- 现有门禁已覆盖跨域导入与领域对称，但大文件阈值当前为 `MAX_PRODUCTION_LOC=800`、碎片下限 `MIN_CAPABILITY_LOC=120`，需要按本次标准收紧。
- 用户约束确认：只重构不改行为；过小文件可按语义合并。

### Files to Reference

| File | Purpose |
| ---- | ------- |
| `/Users/helloworld/dev/neweast/apps/api/src/modules/auth/auth.service.js` | 当前认证主服务超大聚合实现 |
| `/Users/helloworld/dev/neweast/apps/api/src/modules/auth/auth.store.memory.js` | 当前内存存储实现，混合多能力 |
| `/Users/helloworld/dev/neweast/apps/api/src/modules/auth/auth.store.mysql.js` | 当前 MySQL 存储实现，混合多能力 |
| `/Users/helloworld/dev/neweast/apps/api/src/modules/auth/store-methods/auth-store-memory-capabilities.js` | memory capabilities 聚合文件（宽泛命名） |
| `/Users/helloworld/dev/neweast/apps/api/src/modules/auth/store-methods/auth-store-mysql-capabilities.js` | mysql capabilities 聚合文件（宽泛命名） |
| `/Users/helloworld/dev/neweast/apps/api/src/modules/auth/login-service.js` | 登录与 OTP 登录流程编排 |
| `/Users/helloworld/dev/neweast/apps/api/src/modules/auth/session-service.js` | access/refresh token 与会话校验 |
| `/Users/helloworld/dev/neweast/apps/api/src/modules/auth/tenant-context-service.js` | tenant 上下文收敛与 session 修复 |
| `/Users/helloworld/dev/neweast/apps/api/src/modules/auth/entry-policy-service.js` | 入口域策略与域访问断言 |
| `/Users/helloworld/dev/neweast/apps/api/src/modules/auth/permission-context-builder.js` | tenant/platform 权限上下文生成 |
| `/Users/helloworld/dev/neweast/apps/api/src/modules/auth/permission-catalog.js` | 路由权限码与 scope 规则 |
| `/Users/helloworld/dev/neweast/apps/api/src/modules/auth/repositories/index.js` | auth store 端口适配器聚合 |
| `/Users/helloworld/dev/neweast/apps/api/src/bootstrap/create-shared-kernel.js` | shared auth service/runtime 组合根 |
| `/Users/helloworld/dev/neweast/apps/api/src/shared-kernel/auth/auth-capabilities.js` | shared-kernel auth 能力导出面 |
| `/Users/helloworld/dev/neweast/apps/api/src/domains/platform/runtime/platform.runtime.js` | 平台域运行时装配模式 |
| `/Users/helloworld/dev/neweast/apps/api/src/domains/tenant/runtime/tenant.runtime.js` | 租户域运行时装配模式 |
| `/Users/helloworld/dev/neweast/apps/api/src/domains/platform/auth/session/.gitkeep` | 平台 auth.session 目标目录锚点 |
| `/Users/helloworld/dev/neweast/apps/api/src/domains/tenant/auth/session/.gitkeep` | 租户 auth.session 目标目录锚点 |
| `/Users/helloworld/dev/neweast/tools/lint-rules/file-granularity-thresholds.js` | 现有大文件/过碎文件门禁阈值 |
| `/Users/helloworld/dev/neweast/tools/domain-contract/naming-rules.json` | 语义命名与模块语义契约 |
| `/Users/helloworld/dev/neweast/tools/domain-contract/capability-map.json` | domain/module/capability 对称契约 |
| `/Users/helloworld/dev/neweast/apps/api/test/auth.service.test.js` | 认证核心回归主测试集 |
| `/Users/helloworld/dev/neweast/apps/api/test/auth.store.mysql.test.js` | MySQL store 合同行为测试 |
| `/Users/helloworld/dev/neweast/apps/api/test/domain-contract.guards.test.js` | 领域结构与门禁规则测试 |
| `/Users/helloworld/dev/neweast/_bmad-output/implementation-artifacts/tech-spec-platform-tenant-domain-structure-refactor.md` | 已有领域化重构规范与治理约束 |

### Technical Decisions

- 目录落位采用 B 方案（最佳实践）：核心认证能力落位 `domains/{platform|tenant}/auth/{session|context|provisioning}`；为闭合旧大文件删除，治理/配置/集成能力补齐到 `domains/{platform|tenant}/auth/governance` 与 `domains/platform/auth/{system-config|integration}`；跨能力稳定复用逻辑落位 `shared-kernel/auth/*`。
- 切分优先级固定：`领域边界 > capability 语义 > 实现适配(memory/mysql)`。
- 能力目录内采用同层共置：每个 capability 目录优先放置 `*.service.js`、`*.store.memory.js`、`*.store.mysql.js`，避免 service/store 跨层分散。
- 对外兼容策略：保持行为和错误码语义不变；迁移阶段允许旧路径临时桥接，收口阶段（Task 18）统一删除旧聚合文件并完成全量改引用。
- store 合同策略：保留 memory/mysql 的 capability port 镜像一致（方法名/入参/返回语义），实现细节与内部 helper 可差异化。
- 命名策略：采用 `<verb>-<entity>(-<qualifier>).js`；禁用新增 `*-capabilities.js`；`index.js` 仅做导出聚合。
- 体量策略：目标 150-350 LOC，硬上限 500 LOC；低于 80 LOC 且无独立语义时合并（工具文件可按 40 LOC 例外）。
- 边界策略：禁止将同一能力的 service/store 分散到多个模块层级；跨能力共享逻辑仅沉淀到 `shared-kernel/auth/core`。
- 装配策略：沿用现有 `createRouteRuntime -> create{Platform|Tenant}DomainRuntime` 组合链，避免一次性改动路由层行为。
- 门禁策略：在现有对称性/跨域导入基础上补强并收紧文件粒度规则（大文件阈值与过碎提示）并纳入 CI。
- 验证策略：优先复用现有高覆盖回归集（`auth.service.test.js`、`auth.api.test.js`、`auth.store.mysql.test.js` + domain-contract guards）。

### Explicit Constraints (Mandatory)

- 适用范围: C1-C10 仅适用于本次 auth 重构范围（`apps/api/src/domains/*/auth`、`apps/api/src/modules/auth`、`apps/api/src/shared-kernel/auth`）。
- C1（能力划分标准）: capability 必须按业务边界、权限边界、事务边界聚合，禁止按单个 API/页面动作直接建 capability。
- C2（新增 capability 触发条件）: 新增 capability 必须在 `tools/domain-contract/capability-decision-log.json` 声明，并以布尔字段记录四项判据（独立权限码集合、独立事务边界、独立审计事件模型、独立状态机）；满足任意两项方可通过校验。
- C3（目录契约）: 业务实现必须落在 `domains/{platform|tenant}/{module}/{capability}`，禁止跨层落到 `modules/*` 作为长期实现位置。
- C4（同层共置契约）: 同一 capability 下必须优先共置 `*.service.js`、`*.store.memory.js`、`*.store.mysql.js`，禁止 service/store 分散在不同 capability 或 module。
- C5（文件粒度阈值）: 目标 150-350 LOC，硬上限 500 LOC，低于 80 LOC 且语义相邻应合并（工具文件可按 40 LOC 例外）。
- C6（命名契约）: 文件命名必须语义化；禁止 `*-capabilities.js`、`common.js`、`misc.js` 等宽泛命名承载业务实现。
- C7（分层职责契约）: `routes` 仅做参数解析与转发；`service` 负责编排与业务规则；`store` 负责持久化与查询；通过 `check-layer-responsibilities.js` 做静态检查。
- C8（shared-kernel 准入）: 仅跨 capability 且稳定复用的逻辑允许进入 `shared-kernel/auth/core`；默认需至少两个 capability 引用。若仅一个 capability 复用，必须在 `capability-decision-log.json` 标注 `shared_kernel_exception` 并附理由。
- C9（迁移阶段契约）: 迁移期允许旧文件桥接但不得承载业务逻辑；收口期必须删除旧文件并清零旧路径引用。
- C10（CI 门禁契约）: 必须通过结构校验、命名校验、循环依赖校验、layer 责任校验、旧路径残留扫描、contract 测试，且这些检查需接入 `apps/api/package.json` 与根 `package.json` 脚本链路，任一失败即阻断合并。

## Implementation Plan

### Tasks

- [ ] Task 1: 冻结重构前公共契约基线（导出面与关键方法集合）
  - File: `apps/api/test/contracts/auth.service.public-contract.test.js`（new）
  - Action: 新增 `createAuthService` 导出方法集合快照测试，锁定行为与能力集合语义。
  - Notes: 重构期间允许导入路径迁移，但不得变更公共能力名称与参数语义。
  - File: `apps/api/test/contracts/auth.store.contract.test.js`（new）
  - Action: 新增 memory/mysql store 能力端口集合一致性测试（核心 34 项 + 扩展能力）。
  - Notes: 该测试作为“只重构不改行为”第一道护栏。
  - File: `apps/api/test/contracts/auth.incremental-contract.guard.test.js`（new）
  - Action: 每完成一组 capability 迁移即执行增量导出面/端口集合比对，确保拆分过程不引入隐式回归。
  - Notes: 任一增量检查失败立即阻断继续迁移。

- [ ] Task 2: 将 auth 细分能力纳入 domain-contract 真源
  - File: `tools/domain-contract/capability-map.json`
  - Action: 为 `platform/tenant/auth/{session,context,provisioning,governance}` 与 `platform/auth/{system-config,integration}` 补齐 capability 记录，并为 platform-only capability 声明 `domain_scoped_exception`。
  - Notes: capability-map 与 capability-decision-log 必须保持一一对应。
  - File: `tools/domain-contract/naming-rules.json`
  - Action: 增补 auth 能力命名规则，明确禁用宽泛后缀（如 `*-capabilities`）与语义命名模板。
  - Notes: 保持已有 forbidden terms 与 module_semantics 兼容。
  - File: `tools/domain-contract/capability-boundary-rules.json`（new）
  - Action: 固化 C1-C10 约束（能力划分、目录契约、同层共置、shared-kernel 准入、迁移收口、CI 门禁）为机器可校验规则。
  - Notes: 规则版本化并与 CI 同步执行。
  - File: `tools/domain-contract/capability-decision-log.json`（new）
  - Action: 记录 capability 新增/拆分决策输入（四项判据、shared-kernel 豁免、审批备注），供 `check-capability-boundaries.js` 读取。
  - Notes: 所有新增 capability 必须先登记再实现。

- [ ] Task 3: 建立 auth 目标目录与导出面骨架（不迁移业务逻辑）
  - File: `apps/api/src/domains/platform/auth/session/index.js`（new）
  - Action: 创建平台域 auth.session capability 导出入口。
  - Notes: 仅导出面，不引入业务分歧。
  - File: `apps/api/src/domains/platform/auth/context/index.js`（new）
  - Action: 创建平台域 auth.context capability 导出入口。
  - Notes: 与 tenant 对称。
  - File: `apps/api/src/domains/platform/auth/provisioning/index.js`（new）
  - Action: 创建平台域 auth.provisioning capability 导出入口。
  - Notes: 与 tenant 对称。
  - File: `apps/api/src/domains/tenant/auth/session/index.js`（new）
  - Action: 创建租户域 auth.session capability 导出入口。
  - Notes: 与 platform 对称。
  - File: `apps/api/src/domains/tenant/auth/context/index.js`（new）
  - Action: 创建租户域 auth.context capability 导出入口。
  - Notes: 与 platform 对称。
  - File: `apps/api/src/domains/tenant/auth/provisioning/index.js`（new）
  - Action: 创建租户域 auth.provisioning capability 导出入口。
  - Notes: 与 platform 对称。

- [ ] Task 4: 抽离 `AuthProblemError` 与公共常量/归一化工具
  - File: `apps/api/src/modules/auth/auth.service.js`
  - Action: 将错误类、通用常量、通用 normalize/helper 从单体文件迁出并改为导入。
  - Notes: `AuthProblemError` 外部行为与 error_code 映射保持不变。
  - File: `apps/api/src/shared-kernel/auth/auth-problem-error.js`
  - Action: 改为从新公共实现导出，保证兼容。
  - Notes: 保持现有 import 路径可用。
  - File: `apps/api/src/shared-kernel/auth/core/auth-problem-error.js`（new）
  - Action: 承载 `AuthProblemError` 主实现。
  - Notes: 仅重定位，不改结构。
  - File: `apps/api/src/shared-kernel/auth/core/auth-constants.js`（new）
  - Action: 承载认证公共常量（TTL、限制、正则、枚举）。
  - Notes: 常量值必须逐项一致。
  - File: `apps/api/src/shared-kernel/auth/core/auth-normalizers.js`（new）
  - Action: 承载可复用的 normalize/parse 工具。
  - Notes: 作为后续 capability 文件共用基础。

- [ ] Task 5: 按能力重组认证路由适配层（handler/router）
  - File: `apps/api/src/modules/auth/auth.routes.js`
  - Action: 仅保留路由入参解析与向能力 facade 转发，删除冗余业务判断。
  - Notes: `AuthProblemError` 映射语义保持一致。
  - File: `apps/api/src/modules/auth/auth.handlers.js`
  - Action: 将 handlers 组织为 session/context/provisioning 分组并保持现有 handler 名称不变。
  - Notes: `http-routes.js` 调用面不变。
  - File: `apps/api/src/shared-kernel/auth/auth-route-handlers.js`
  - Action: 更新为指向新分组导出面。
  - Notes: 继续提供兼容包装层。

- [ ] Task 6: 抽离 `session` 能力实现（登录/OTP/refresh/logout/change-password）
  - File: `apps/api/src/modules/auth/login-service.js`
  - Action: 将会话登录主流程提炼为可复用函数，迁移到 capability 同层文件。
  - Notes: 审计事件类型与字段保持一致。
  - File: `apps/api/src/modules/auth/session-service.js`
  - Action: 将 token 颁发、session 校验、cache 逻辑迁移到 capability 同层文件。
  - Notes: token claims（sub/sid/sv/jti/typ）不得变化。
  - File: `apps/api/src/domains/platform/auth/session/session.service.js`（new）
  - Action: 承载平台 session 编排能力（login/loginWithOtp/refresh/logout/changePassword）。
  - Notes: 能力聚合在单文件，避免过度碎片化。
  - File: `apps/api/src/domains/platform/auth/session/session.store.memory.js`（new）
  - Action: 承载平台 session 的 memory 持久化能力。
  - Notes: 与 mysql 端口对齐。
  - File: `apps/api/src/domains/platform/auth/session/session.store.mysql.js`（new）
  - Action: 承载平台 session 的 MySQL 持久化能力。
  - Notes: 事务/重试语义不变。
  - File: `apps/api/src/domains/tenant/auth/session/session.service.js`（new）
  - Action: 承载租户 session 编排能力（含 tenant 上下文初始化）。
  - Notes: 与 platform 同构命名。
  - File: `apps/api/src/domains/tenant/auth/session/session.store.memory.js`（new）
  - Action: 承载租户 session 的 memory 持久化能力。
  - Notes: 与 mysql 端口对齐。
  - File: `apps/api/src/domains/tenant/auth/session/session.store.mysql.js`（new）
  - Action: 承载租户 session 的 MySQL 持久化能力。
  - Notes: 与 platform 同构命名。
  - File: `apps/api/src/modules/auth/auth.service.js`
  - Action: 将 `login/sendOtp/loginWithOtp/refresh/logout/changePassword` 改为委托新能力模块。
  - Notes: 返回 payload 字段与错误码严格一致。

- [ ] Task 7: 抽离 `context` 能力实现（authorizeRoute/options/select/switch）
  - File: `apps/api/src/modules/auth/tenant-context-service.js`
  - Action: 提炼 tenant options 与 session context 修复逻辑并迁移到 capability 同层文件。
  - Notes: `tenant_selection_required` 判定规则保持一致。
  - File: `apps/api/src/modules/auth/entry-policy-service.js`
  - Action: 提炼 domain access 断言与默认授权策略并迁移到 capability 同层文件。
  - Notes: `AUTH-403-NO-DOMAIN` 行为不变。
  - File: `apps/api/src/modules/auth/permission-context-builder.js`
  - Action: 提炼 platform/tenant 权限上下文构建与系统配置授权补丁逻辑并迁移到 capability 同层文件。
  - Notes: `AUTH-503-PLATFORM-SNAPSHOT-DEGRADED` 语义不变。
  - File: `apps/api/src/modules/auth/route-preauthorization.js`
  - Action: 保持 symbol 标记机制，迁移为 context capability 公共工具。
  - Notes: 与现有 preauthorized pipeline 完全兼容。
  - File: `apps/api/src/domains/platform/auth/context/context.service.js`（new）
  - Action: 承载平台 context 能力（authorizeRoute/platformOptions 等）。
  - Notes: 保持返回字段不变。
  - File: `apps/api/src/domains/platform/auth/context/context.store.memory.js`（new）
  - Action: 承载平台 context 的 memory 存储与上下文读取能力。
  - Notes: 与 mysql 端口一致。
  - File: `apps/api/src/domains/platform/auth/context/context.store.mysql.js`（new）
  - Action: 承载平台 context 的 MySQL 存储与上下文读取能力。
  - Notes: 与 memory 端口一致。
  - File: `apps/api/src/domains/tenant/auth/context/context.service.js`（new）
  - Action: 承载租户 context 能力（tenantOptions/selectTenant/switchTenant）。
  - Notes: 与 platform 同构命名。
  - File: `apps/api/src/domains/tenant/auth/context/context.store.memory.js`（new）
  - Action: 承载租户 context 的 memory 存储能力。
  - Notes: 与 mysql 端口一致。
  - File: `apps/api/src/domains/tenant/auth/context/context.store.mysql.js`（new）
  - Action: 承载租户 context 的 MySQL 存储能力。
  - Notes: 与 platform 同构命名。
  - File: `apps/api/src/modules/auth/auth.service.js`
  - Action: 将 `platformOptions/tenantOptions/authorizeRoute/selectTenant/switchTenant` 委托新模块。
  - Notes: 入参与返回字段保持不变。

- [ ] Task 8: 抽离 `provisioning` 能力实现（平台/租户用户开通与回滚）
  - File: `apps/api/src/modules/auth/auth.service.js`
  - Action: 将 `provisionPlatformUserByPhone/provisionTenantUserByPhone/getOrCreateUserIdentityByPhone/rollbackProvisionedUserIdentity` 提取为 capability 模块。
  - Notes: 默认密码配置读取与失败回滚策略保持不变。
  - File: `apps/api/src/domains/platform/auth/provisioning/provisioning.service.js`（new）
  - Action: 承载平台 provisioning 能力（开通、回滚、身份复用）。
  - Notes: 审计事件与错误码语义不变。
  - File: `apps/api/src/domains/platform/auth/provisioning/provisioning.store.memory.js`（new）
  - Action: 承载平台 provisioning 的 memory 持久化能力。
  - Notes: 与 mysql 端口一致。
  - File: `apps/api/src/domains/platform/auth/provisioning/provisioning.store.mysql.js`（new）
  - Action: 承载平台 provisioning 的 MySQL 持久化能力。
  - Notes: 事务/回滚语义不变。
  - File: `apps/api/src/domains/tenant/auth/provisioning/provisioning.service.js`（new）
  - Action: 承载租户 provisioning 能力（开通、回滚、usership/profile 同步）。
  - Notes: 与 platform 同构命名。
  - File: `apps/api/src/domains/tenant/auth/provisioning/provisioning.store.memory.js`（new）
  - Action: 承载租户 provisioning 的 memory 持久化能力。
  - Notes: 与 mysql 端口一致。
  - File: `apps/api/src/domains/tenant/auth/provisioning/provisioning.store.mysql.js`（new）
  - Action: 承载租户 provisioning 的 MySQL 持久化能力。
  - Notes: 与 platform 同构命名。

- [ ] Task 8A: 抽离剩余治理/配置/集成/审计能力，闭合旧聚合删除前置条件
  - File: `apps/api/src/modules/auth/auth.service.js`
  - Action: 将 `createOrganizationWithOwner/acquireOwnerTransferLock/releaseOwnerTransferLock/validateOwnerTransferRequest/executeOwnerTransferTakeover`、平台/租户角色权限治理、`getSystemSensitiveConfig/upsertSystemSensitiveConfig/recordSystemSensitiveConfigAuditEvent`、integration、`listAuditEvents/recordIdempotencyEvent` 迁移为 capability 委托。
  - Notes: Task 18 前禁止在 `auth.service.js` 保留以上能力的业务内联实现。
  - File: `apps/api/src/domains/platform/auth/governance/index.js`（new）
  - Action: 创建平台治理能力导出入口。
  - Notes: 承载 organization/user/role 治理编排入口。
  - File: `apps/api/src/domains/platform/auth/governance/governance.service.js`（new）
  - Action: 承载平台治理能力编排（组织、角色目录、角色权限与用户状态）。
  - Notes: 保持错误码与审计语义不变。
  - File: `apps/api/src/domains/platform/auth/governance/governance.store.memory.js`（new）
  - Action: 承载平台治理 memory 存储能力。
  - Notes: 与 mysql 端口一致。
  - File: `apps/api/src/domains/platform/auth/governance/governance.store.mysql.js`（new）
  - Action: 承载平台治理 mysql 存储能力。
  - Notes: deadlock retry 与事务边界不变。
  - File: `apps/api/src/domains/tenant/auth/governance/index.js`（new）
  - Action: 创建租户治理能力导出入口。
  - Notes: 与 platform governance 同构。
  - File: `apps/api/src/domains/tenant/auth/governance/governance.service.js`（new）
  - Action: 承载租户治理能力编排（tenant user/role 绑定与状态机）。
  - Notes: usership 状态机语义不变。
  - File: `apps/api/src/domains/tenant/auth/governance/governance.store.memory.js`（new）
  - Action: 承载租户治理 memory 存储能力。
  - Notes: 与 mysql 端口一致。
  - File: `apps/api/src/domains/tenant/auth/governance/governance.store.mysql.js`（new）
  - Action: 承载租户治理 mysql 存储能力。
  - Notes: 与 platform 同构命名。
  - File: `apps/api/src/domains/platform/auth/system-config/index.js`（new）
  - Action: 创建平台 system-config capability 导出入口。
  - Notes: 该能力为 platform-only，需 capability-map 标注例外。
  - File: `apps/api/src/domains/platform/auth/system-config/system-config.service.js`（new）
  - Action: 承载敏感配置读写、版本冲突与审计编排能力。
  - Notes: 白名单与错误码保持一致。
  - File: `apps/api/src/domains/platform/auth/system-config/system-config.store.memory.js`（new）
  - Action: 承载 system-config memory 存储能力。
  - Notes: 与 mysql 端口一致。
  - File: `apps/api/src/domains/platform/auth/system-config/system-config.store.mysql.js`（new）
  - Action: 承载 system-config mysql 存储能力。
  - Notes: 事务语义保持一致。
  - File: `apps/api/src/domains/platform/auth/integration/index.js`（new）
  - Action: 创建平台 integration capability 导出入口。
  - Notes: 该能力为 platform-only，需 capability-map 标注例外。
  - File: `apps/api/src/domains/platform/auth/integration/integration.service.js`（new）
  - Action: 承载 integration 目录/契约/恢复/冻结能力编排。
  - Notes: freeze blocked 语义保持一致。
  - File: `apps/api/src/domains/platform/auth/integration/integration.store.memory.js`（new）
  - Action: 承载 integration memory 存储能力。
  - Notes: 与 mysql 端口一致。
  - File: `apps/api/src/domains/platform/auth/integration/integration.store.mysql.js`（new）
  - Action: 承载 integration mysql 存储能力。
  - Notes: 与 memory 端口一致。
  - File: `apps/api/src/shared-kernel/auth/core/auth-audit-idempotency.service.js`（new）
  - Action: 抽离跨 capability 复用的审计/幂等编排逻辑并供各 capability 调用。
  - Notes: 仅承载跨能力稳定复用逻辑，符合 C8 准入规则。

- [ ] Task 9: 拆分 memory `store-methods` 聚合文件为语义能力文件
  - File: `apps/api/src/modules/auth/store-methods/auth-store-memory-capabilities.js`
  - Action: 将 memory 方法实现迁移到 capability 同层 store 文件，并将该文件临时收敛为“仅导出映射表”。
  - Notes: 本任务仅负责方法迁移，不负责 createInMemoryAuthStore 组合逻辑。
  - File: `apps/api/src/modules/auth/refactor-migration-map.md`
  - Action: 列出 memory 方法迁移的完整“旧函数 -> 新文件”路径映射（禁止通配路径占位）。
  - Notes: 该清单是评审与回归的唯一真源，必须覆盖 `session/context/provisioning/governance/system-config/integration` 全能力族。
  - File: `apps/api/src/domains/platform/auth/session/session.store.memory.js`（new）
  - Action: 收拢原 memory 会话方法（issue/rotate/validate 等）到 capability 同层文件。
  - Notes: 同能力内聚，避免跨目录跳转。
  - File: `apps/api/src/domains/tenant/auth/context/context.store.memory.js`（new）
  - Action: 收拢原 memory 上下文方法（tenant option/select/switch 相关）到 capability 同层文件。
  - Notes: 与 service 并置。
  - File: `apps/api/src/domains/platform/auth/governance/governance.store.memory.js`（new）
  - Action: 收拢平台治理 memory 方法（组织/角色目录/角色权限/平台用户状态）到 capability 同层文件。
  - Notes: 与 service 并置。
  - File: `apps/api/src/domains/tenant/auth/governance/governance.store.memory.js`（new）
  - Action: 收拢租户治理 memory 方法（tenant user/role 绑定与状态）到 capability 同层文件。
  - Notes: 与 service 并置。
  - File: `apps/api/src/domains/platform/auth/system-config/system-config.store.memory.js`（new）
  - Action: 收拢平台系统配置 memory 方法到 capability 同层文件。
  - Notes: 与 mysql 端口保持镜像。
  - File: `apps/api/src/domains/platform/auth/integration/integration.store.memory.js`（new）
  - Action: 收拢平台 integration memory 方法到 capability 同层文件。
  - Notes: 与 mysql 端口保持镜像。

- [ ] Task 10: 拆分 mysql `store-methods` 聚合文件为语义能力文件
  - File: `apps/api/src/modules/auth/store-methods/auth-store-mysql-capabilities.js`
  - Action: 将 mysql 方法实现迁移到 capability 同层 store 文件，并将该文件临时收敛为“仅导出映射表”。
  - Notes: 本任务仅负责方法迁移，不负责 createMySqlAuthStore 组合逻辑。
  - File: `apps/api/src/modules/auth/refactor-migration-map.md`
  - Action: 列出 mysql 方法迁移的完整“旧函数 -> 新文件”路径映射（禁止通配路径占位）。
  - Notes: 与 memory 映射保持一一对应，并覆盖 `session/context/provisioning/governance/system-config/integration` 全能力族。
  - File: `apps/api/src/domains/platform/auth/session/session.store.mysql.js`（new）
  - Action: 收拢原 mysql 会话方法（issue/rotate/validate 等）到 capability 同层文件。
  - Notes: 保持冲突错误与 deadlock retry 语义。
  - File: `apps/api/src/domains/tenant/auth/context/context.store.mysql.js`（new）
  - Action: 收拢原 mysql 上下文方法（tenant option/select/switch 相关）到 capability 同层文件。
  - Notes: 与 service 并置。
  - File: `apps/api/src/domains/platform/auth/governance/governance.store.mysql.js`（new）
  - Action: 收拢平台治理 mysql 方法（组织/角色目录/角色权限/平台用户状态）到 capability 同层文件。
  - Notes: 保持冲突错误与 deadlock retry 语义。
  - File: `apps/api/src/domains/tenant/auth/governance/governance.store.mysql.js`（new）
  - Action: 收拢租户治理 mysql 方法（tenant user/role 绑定与状态）到 capability 同层文件。
  - Notes: 与 service 并置。
  - File: `apps/api/src/domains/platform/auth/system-config/system-config.store.mysql.js`（new）
  - Action: 收拢平台系统配置 mysql 方法到 capability 同层文件。
  - Notes: 与 memory 端口保持镜像。
  - File: `apps/api/src/domains/platform/auth/integration/integration.store.mysql.js`（new）
  - Action: 收拢平台 integration mysql 方法到 capability 同层文件。
  - Notes: 与 memory 端口保持镜像。

- [ ] Task 11: 将 `auth.store.memory.js` 按领域-能力拆分并保留临时桥接入口
  - File: `apps/api/src/modules/auth/auth.store.memory.js`
  - Action: 基于 Task 9 迁移结果，仅负责组合 `createInMemoryAuthStore` 与桥接导出（无业务内联逻辑）。
  - Notes: 最终在 Task 18 删除该旧文件。
  - File: `apps/api/src/shared-kernel/auth/store/create-in-memory-auth-store.js`（new）
  - Action: 提供新的内存 store 组合入口并对外统一暴露 factory。
  - Notes: 构造参数与返回 contract 语义保持一致。
  - File: `apps/api/src/domains/platform/auth/session/session.store.memory.js`（new）
  - Action: 作为平台 session memory 能力组合导出入口。
  - Notes: 不再使用通配路径。
  - File: `apps/api/src/domains/platform/auth/context/context.store.memory.js`（new）
  - Action: 作为平台 context memory 能力组合导出入口。
  - Notes: 不再使用通配路径。
  - File: `apps/api/src/domains/platform/auth/provisioning/provisioning.store.memory.js`（new）
  - Action: 作为平台 provisioning memory 能力组合导出入口。
  - Notes: 不再使用通配路径。
  - File: `apps/api/src/domains/tenant/auth/session/session.store.memory.js`（new）
  - Action: 作为租户 session memory 能力组合导出入口。
  - Notes: 与 platform 同构。
  - File: `apps/api/src/domains/tenant/auth/context/context.store.memory.js`（new）
  - Action: 作为租户 context memory 能力组合导出入口。
  - Notes: 与 platform 同构。
  - File: `apps/api/src/domains/tenant/auth/provisioning/provisioning.store.memory.js`（new）
  - Action: 作为租户 provisioning memory 能力组合导出入口。
  - Notes: 与 platform 同构。

- [ ] Task 12: 将 `auth.store.mysql.js` 按领域-能力拆分并保留临时桥接入口
  - File: `apps/api/src/modules/auth/auth.store.mysql.js`
  - Action: 基于 Task 10 迁移结果，仅负责组合 `createMySqlAuthStore` 与桥接导出（无业务内联 SQL）。
  - Notes: 最终在 Task 18 删除该旧文件。
  - File: `apps/api/src/shared-kernel/auth/store/create-mysql-auth-store.js`（new）
  - Action: 提供新的 MySQL store 组合入口并统一暴露 factory。
  - Notes: 构造参数、事务语义与返回 contract 保持一致。
  - File: `apps/api/src/domains/platform/auth/session/session.store.mysql.js`（new）
  - Action: 作为平台 session mysql 能力组合导出入口。
  - Notes: 不再使用通配路径。
  - File: `apps/api/src/domains/platform/auth/context/context.store.mysql.js`（new）
  - Action: 作为平台 context mysql 能力组合导出入口。
  - Notes: 不再使用通配路径。
  - File: `apps/api/src/domains/platform/auth/provisioning/provisioning.store.mysql.js`（new）
  - Action: 作为平台 provisioning mysql 能力组合导出入口。
  - Notes: 不再使用通配路径。
  - File: `apps/api/src/domains/tenant/auth/session/session.store.mysql.js`（new）
  - Action: 作为租户 session mysql 能力组合导出入口。
  - Notes: 与 platform 同构。
  - File: `apps/api/src/domains/tenant/auth/context/context.store.mysql.js`（new）
  - Action: 作为租户 context mysql 能力组合导出入口。
  - Notes: 与 platform 同构。
  - File: `apps/api/src/domains/tenant/auth/provisioning/provisioning.store.mysql.js`（new）
  - Action: 作为租户 provisioning mysql 能力组合导出入口。
  - Notes: 与 platform 同构。

- [ ] Task 13: 统一 auth store 组合与 repository 适配
  - File: `apps/api/src/modules/auth/repositories/index.js`
  - Action: 保持 repository 接口不变，改为消费新的组合式 auth store。
  - Notes: 上层 service 无感迁移。
  - File: `apps/api/src/modules/auth/repositories/repository-helpers.js`
  - Action: 增强必选/可选 delegate 断言错误信息以定位缺失能力。
  - Notes: 仅增强可观测性，不改变调用语义。
  - File: `apps/api/src/modules/auth/repositories/domain-access-repository.js`
  - Action: 保持接口稳定，校准到新 store 组合端口。
  - Notes: 兼容现有调用点。
  - File: `apps/api/src/modules/auth/repositories/session-repository.js`
  - Action: 保持接口稳定，校准到新 store 组合端口。
  - Notes: 兼容现有调用点。
  - File: `apps/api/src/modules/auth/repositories/permission-repository.js`
  - Action: 保持接口稳定，校准到新 store 组合端口。
  - Notes: 兼容现有调用点。
  - File: `apps/api/src/modules/auth/repositories/user-repository.js`
  - Action: 保持接口稳定，校准到新 store 组合端口。
  - Notes: 兼容现有调用点。
  - File: `apps/api/src/modules/auth/repositories/tenant-membership-repository.js`
  - Action: 保持接口稳定，校准到新 store 组合端口。
  - Notes: 兼容现有调用点。

- [ ] Task 14: 收敛 `auth.service.js` 为薄 facade（目标 <= 500 LOC）
  - File: `apps/api/src/modules/auth/auth.service.js`
  - Action: 将内联重逻辑迁移后收敛为临时薄 facade，仅做委托与导出。
  - Notes: 最终在 Task 18 删除该旧文件。
  - File: `apps/api/src/shared-kernel/auth/create-auth-service.js`（new）
  - Action: 提供新的 `createAuthService` 入口并承载组合装配逻辑。
  - Notes: 行为与错误码语义保持一致。
  - File: `apps/api/src/shared-kernel/auth/auth-capabilities.js`
  - Action: 对接新的 facade 导出面。
  - Notes: 统一导出入口到新路径。

- [ ] Task 15: 更新 bootstrap/runtime 装配，确保单实例 authService 对齐
  - File: `apps/api/src/bootstrap/create-shared-kernel.js`
  - Action: 维持实例对齐断言，适配新的 capability 组合结构。
  - Notes: 保持现有类型与错误消息语义。
  - File: `apps/api/src/bootstrap/create-route-runtime.js`
  - Action: 继续以 shared-kernel + domain runtime 装配，不引入行为变更。
  - Notes: handler 名称与注入结构不变。
  - File: `apps/api/src/http-routes.js`
  - Action: 验证 auth/platform/tenant/audit handlers 组合面保持一致。
  - Notes: 不改路由声明。
  - File: `apps/api/src/app.js`
  - Action: 将 `createAuthService`、`createMySqlAuthStore` 的导入切换到新 shared-kernel 入口。
  - Notes: 删除旧路径引用。

- [ ] Task 16: 收紧大文件与命名门禁，阻断回归
  - File: `tools/lint-rules/file-granularity-thresholds.js`
  - Action: 将生产文件硬上限收紧到 `500 LOC`，并将过碎建议阈值调整到与本次策略一致（`<80 LOC` 建议合并，工具文件可 `40 LOC` 例外）。
  - Notes: route adapter 文件维持例外策略。
  - File: `tools/domain-contract/check-domain-symmetry.js`
  - Action: 增补 auth capability 命名/层级检查，阻断 `*-capabilities.js` 回归。
  - Notes: 不影响已有 capability map 校验逻辑。
  - File: `tools/domain-contract/check-auth-import-cycles.js`（new）
  - Action: 新增 auth 相关目录循环依赖检查（`modules/auth`、`shared-kernel/auth`、`domains/*/auth`）。
  - Notes: CI 阶段强制执行。
  - File: `tools/domain-contract/check-capability-boundaries.js`（new）
  - Action: 基于 `capability-boundary-rules.json` 校验 capability 划分、同层共置、shared-kernel 准入与旧路径收口。
  - Notes: 任一规则不满足即返回非 0 退出码。
  - File: `tools/domain-contract/check-layer-responsibilities.js`（new）
  - Action: 静态校验 route/service/store 职责边界（路由层禁止业务分支与持久化逻辑，store 禁止鉴权编排逻辑）。
  - Notes: 作为 C7 的自动化执行器。
  - File: `apps/api/test/domain-contract.guards.test.js`
  - Action: 添加新门禁测试用例。
  - Notes: 保证 CI 可复现。
  - File: `apps/api/test/domain-contract.no-cycle-auth.test.js`（new）
  - Action: 增加 no-cycle 回归测试并固定失败样例提示。
  - Notes: 作为循环依赖门禁的测试层兜底。
  - File: `apps/api/test/domain-contract.capability-boundary.test.js`（new）
  - Action: 增加 capability 边界契约测试（验证 C1-C10 的关键断言）。
  - Notes: 与 `check-capability-boundaries.js` 双重兜底。
  - File: `apps/api/test/domain-contract.layer-responsibility.test.js`（new）
  - Action: 增加 layer 职责契约测试（验证 C7）。
  - Notes: 与 `check-layer-responsibilities.js` 双重兜底。
  - File: `apps/api/package.json`
  - Action: 新增 `check:capability-boundaries`、`check:layer-responsibilities`、`check:auth-refactor-guards` 脚本，并将其接入 `lint`。
  - Notes: 确保应用级门禁自动执行。
  - File: `package.json`
  - Action: 将 `pnpm --dir apps/api run check:auth-refactor-guards` 同时接入根级 `check:refactor-governance` 与 `lint` 链路（两条链路均为强制）。
  - Notes: 任一链路失败均阻断合并。

- [ ] Task 17: 扩展/校准回归测试覆盖，验证“只重构不改行为”
  - File: `apps/api/test/auth.service.test.js`
  - Action: 保持现有行为断言，补充公共导出面与错误码回归断言。
  - Notes: 不削减现有覆盖。
  - File: `apps/api/test/auth.store.mysql.test.js`
  - Action: 补充拆分后 SQL 能力组合与事务一致性断言。
  - Notes: deadlock 与冲突路径重点覆盖。
  - File: `apps/api/test/auth.store.memory.platform-user-read.test.js`
  - Action: 覆盖 memory 分层后的读取行为一致性。
  - Notes: 避免轻量分层导致字段漂移。
  - File: `apps/api/test/auth.api.test.js`
  - Action: 保证登录/刷新/登出/改密主链路输出字段、错误码、headers 不变。
  - Notes: 作为接口回归主集。
  - File: `apps/api/test/auth.domain.api.test.js`
  - Action: 保证跨域登录、租户选择/切换、域拒绝语义不变。
  - Notes: 覆盖 domain 边界行为。
  - File: `apps/api/test/domain.symmetry.test.js`
  - Action: 保证重构后目录结构与对称性门禁通过。
  - Notes: 必须纳入最终验收。
  - File: `apps/api/test/contracts/auth.facade-structure.test.js`（new）
  - Action: 静态断言迁移阶段旧聚合文件仅承担桥接委托职责，不承载业务分支与 SQL 内联逻辑。
  - Notes: 收口删除验证由 AC 18 与 Task 18 联合完成。

- [ ] Task 18: 直接删除旧聚合文件并完成全量改引用收口
  - File: `apps/api/scripts/refactor-auth-import-paths.js`（new）
  - Action: 提供旧路径到新路径的批量改写与 `--check` 校验能力，并支持 `--restore-bridge` 回滚模式。
  - Notes: 删除旧文件前必须通过 `--check` 且旧路径扫描结果为空。
  - File: `apps/api/src/modules/auth/refactor-rollback-checklist.md`（new）
  - Action: 提供收口失败回滚步骤（恢复桥接入口、恢复导入、恢复映射清单、回归验证命令）。
  - Notes: 回滚步骤必须可在单次提交内执行完成。
  - File: `apps/api/src/modules/auth/store-methods/auth-store-memory-capabilities.js`
  - Action: 直接删除该旧聚合文件并将全部引用替换为新能力文件导出面。
  - Notes: 不允许保留占位兼容文件。
  - File: `apps/api/src/modules/auth/store-methods/auth-store-mysql-capabilities.js`
  - Action: 直接删除该旧聚合文件并将全部引用替换为新能力文件导出面。
  - Notes: 不允许保留占位兼容文件。
  - File: `apps/api/src/modules/auth/auth.store.memory.js`
  - Action: 直接删除旧文件并迁移全部调用点到 `shared-kernel/auth/store/create-in-memory-auth-store.js`。
  - Notes: 引用替换必须一次性完成。
  - File: `apps/api/src/modules/auth/auth.store.mysql.js`
  - Action: 直接删除旧文件并迁移全部调用点到 `shared-kernel/auth/store/create-mysql-auth-store.js`。
  - Notes: 引用替换必须一次性完成。
  - File: `apps/api/src/modules/auth/auth.service.js`
  - Action: 直接删除旧文件并迁移全部调用点到 `shared-kernel/auth/create-auth-service.js`。
  - Notes: 仅在完整回归通过后执行删除；全量更新后仓库内不得残留旧路径 import/require。

- [ ] Task 0（Pre-Gate）: 建立并维护旧->新文件迁移映射清单（强制执行）
  - File: `apps/api/src/modules/auth/refactor-migration-map.md`（new）
  - Action: 维护旧文件到新文件的一一映射（含“已迁移/待迁移/删除”状态）并作为迁移主清单。
  - Notes: 至少覆盖 Task 6-12/18 涉及的全部旧路径与新路径。
  - File: `apps/api/src/modules/auth/refactor-migration-map.md`
  - Action: 每次删除旧文件前先更新映射，再执行引用替换与删除。
  - Notes: 映射与代码变更必须同一 PR 提交。

### Acceptance Criteria

- [ ] AC 1: Given 认证模块完成重构, when 全仓执行导入扫描, then 不再存在对 `modules/auth/auth.service`、`modules/auth/auth.store.memory`、`modules/auth/auth.store.mysql` 的引用，且新入口行为与旧行为一致。
- [ ] AC 2: Given memory/mysql 双实现, when 执行 store 合同测试, then 两者在 `capability-map + contract snapshot` 定义的全量端口上方法名与输入输出语义一致（非“至少 N 项”）。
- [ ] AC 3: Given 登录主链路（密码登录与 OTP 登录）, when 调用 `/auth/login` 与 `/auth/otp/login`, then token/session 字段、权限上下文字段和错误码行为与重构前一致。
- [ ] AC 4: Given tenant 多组织场景, when 登录并执行 tenant select/switch, then `tenant_selection_required`、`active_tenant_id` 与拒绝语义（`AUTH-403-NO-DOMAIN`）保持一致。
- [ ] AC 5: Given refresh token 轮换与重放路径, when 触发重复 refresh, then 仍按原语义返回 `AUTH-401-INVALID-REFRESH` 并执行对应会话收敛策略。
- [ ] AC 6: Given change-password 场景, when 修改密码后使用旧凭据/旧会话, then 仍按原策略强制重新登录并保持原错误码语义。
- [ ] AC 7: Given platform 用户/角色/组织治理接口, when 执行增删改查与状态变更, then 返回结构、审计事件语义与权限检查行为不变。
- [ ] AC 8: Given platform system-config 能力, when 读取/更新敏感配置, then 白名单、版本冲突、审计落库与错误码语义不变。
- [ ] AC 9: Given platform integration 目录/契约/恢复/冻结能力, when 执行 CRUD、激活、回放与冻结操作, then 事务与门禁行为（含 freeze blocked）与现状一致。
- [ ] AC 10: Given tenant user/role 治理能力, when 执行成员状态变更、资料更新、角色绑定, then usership 状态机与返回字段语义不变。
- [ ] AC 11: Given route preauthorization 机制, when 使用预授权上下文调用 platform/tenant 服务层, then symbol 标记校验逻辑与拒绝行为保持一致。
- [ ] AC 12: Given shared-kernel 与 domain runtime 装配链路, when 启动应用创建 handlers, then auth/platform/tenant/audit handler 装配结果与现有路由分发兼容。
- [ ] AC 13: Given 大文件拆分完成, when 执行 lint granularity 与目录结构校验, then 目标业务文件不超过 500 LOC、无新增 `*-capabilities.js`，且 capability 默认满足 `service + store.memory + store.mysql` 同层共置；任何豁免必须登记到 `capability-decision-log.json` 并通过边界校验。
- [ ] AC 14: Given 对称性与边界门禁, when 执行 `check-domain-symmetry` 与相关 guard tests, then 平台/租户共享 capability（session/context/provisioning/governance）的目录层级、命名与跨域导入规则全部通过，且 platform-only capability（system-config/integration）已在 capability-map 声明 `domain_scoped_exception` 并通过校验。
- [ ] AC 15: Given 完整回归矩阵, when 执行 auth/service/store/api/domain-contract 相关测试集, then 全部通过且无行为回归。
- [ ] AC 16: Given 迁移中间态, when 扫描旧聚合实现残留, then `auth.service`/`auth.store.*` 仅允许薄 facade/桥接职责，不得承载业务内联逻辑。
- [ ] AC 17: Given auth 领域拆分完成, when 执行 no-cycle 检查与对应测试, then `modules/auth`、`shared-kernel/auth`、`domains/*/auth` 之间不存在循环依赖。
- [ ] AC 18: Given 旧聚合文件删除策略, when 执行静态结构断言与契约测试, then 旧聚合文件已被删除且新入口文件仅承载组合/导出职责。
- [ ] AC 19: Given 执行 Task 18 收口删除, when 运行 `node scripts/refactor-auth-import-paths.js --check` 与旧路径 `rg` 扫描, then `auth.service/auth.store.memory/auth.store.mysql/auth-store-memory-capabilities/auth-store-mysql-capabilities` 残留引用结果为 0。
- [ ] AC 20: Given Task 14-17 的迁移中间态验收, when 运行 facade 结构静态断言, then 旧聚合文件仅含委托/导出逻辑且不含业务分支与 SQL 内联实现，且同一 capability 的 service/store 不跨目录分散；该项为 Task 18 的前置门禁而非终态验收。
- [ ] AC 21: Given capability 结构完成, when 执行 capability boundary 检查, then 所有能力均满足 C1-C7（能力划分、目录契约、同层共置、命名与分层职责）。
- [ ] AC 22: Given shared-kernel/auth/core 引入新逻辑, when 执行 boundary 与契约测试, then 仅允许满足 C8 准入条件的跨能力稳定复用逻辑进入 shared-kernel。
- [ ] AC 23: Given CI 执行 auth 范围门禁, when 运行结构/命名/循环依赖/layer 责任/旧路径扫描/contract 套件, then 必须全部通过才允许合并（C10）。
- [ ] AC 24: Given 执行 Task 18 收口删除失败, when 按回滚清单执行恢复, then 能在一个提交内恢复到桥接可运行状态并重新通过核心回归。

## Additional Context

### Dependencies

- 运行时依赖：MySQL、Redis（本地或测试环境可达）。
- 语言与工具链：Node.js 24、pnpm、Nx、`node:test`、`@babel/parser`。
- 现有契约依赖：`tools/domain-contract/capability-map.json`、`tools/domain-contract/naming-rules.json`、`tools/domain-contract/check-domain-symmetry.js`、`tools/domain-contract/capability-boundary-rules.json`。
- 任务依赖顺序：
  - 执行顺序以依赖为准，任务编号仅用于追踪，不代表时间顺序。
  - Task 0（迁移映射清单）必须先初始化，并在 Task 6-12 与 Task 8A 过程中持续更新，在 Task 18 前完成最终核对。
  - 先完成 Task 1（契约基线）再进行任意能力迁移。
  - Task 2-3 必须先于 Task 6-12 与 Task 8A（先定规则与目录，再迁移实现）。
  - Task 8A 必须先于 Task 14（确保旧大文件删除前全部能力已迁出）。
  - Task 9-12（store 拆分）与 Task 8A（剩余能力拆分）必须先于 Task 13-15（组合与装配收口）。
  - Task 16（门禁）需在主要迁移后开启强校验，避免中途阻塞迭代。
  - Task 17-18 作为最终回归与收口，Task 0 贯穿迁移全程并在收口前完成核对。

### Testing Strategy

- 单元/服务级回归：
  - `pnpm --dir apps/api exec node --test test/auth.service.test.js`
  - `pnpm --dir apps/api exec node --test test/auth.store.mysql.test.js`
  - `pnpm --dir apps/api exec node --test test/auth.store.memory.platform-user-read.test.js`
  - `pnpm --dir apps/api exec node --test test/contracts/auth.incremental-contract.guard.test.js`
  - `pnpm --dir apps/api exec node --test test/contracts/auth.facade-structure.test.js`
- API 集成回归：
  - `pnpm --dir apps/api exec node --test test/auth.api.test.js`
  - `pnpm --dir apps/api exec node --test test/auth.domain.api.test.js`
- 领域契约与门禁回归：
  - `pnpm --dir apps/api run check:auth-refactor-guards`
  - `pnpm --dir apps/api run check:domain-symmetry`
  - `pnpm --dir apps/api exec node --test test/domain-contract.guards.test.js`
  - `pnpm --dir apps/api exec node --test test/domain.symmetry.test.js`
  - `pnpm --dir apps/api exec node --test test/domain-contract.no-cycle-auth.test.js`
  - `pnpm --dir apps/api exec node --test test/domain-contract.capability-boundary.test.js`
  - `pnpm --dir apps/api exec node --test test/domain-contract.layer-responsibility.test.js`
  - `node tools/domain-contract/check-capability-boundaries.js`
  - `node tools/domain-contract/check-layer-responsibilities.js`
  - `pnpm --dir apps/api exec node scripts/refactor-auth-import-paths.js --check`
  - `rg -n "modules/auth/auth\\.service|modules/auth/auth\\.store\\.memory|modules/auth/auth\\.store\\.mysql|store-methods/auth-store-memory-capabilities|store-methods/auth-store-mysql-capabilities" apps tools`（期望无输出）
- 工作区级串联验证：
  - `pnpm run check:refactor-governance`
  - `pnpm run lint`
  - `pnpm run test`
- 手工核验要点：
  - 验证 `/auth/login`、`/auth/refresh`、`/auth/logout`、`/auth/change-password` 返回体字段不变。
  - 验证 platform/tenant 管理端关键接口在 preauthorized 上下文下行为一致。
  - 验证集成冻结窗口下写操作阻断语义与审计事件一致。

### Notes

- 高风险点：
  - `auth.service.js` 拆分时最容易出现错误码/错误类型漂移（必须靠契约测试兜底）。
  - mysql store 迁移时容易破坏事务边界和 deadlock retry 语义。
  - route preauthorization 符号上下文若处理不当会导致隐性权限穿透或误拒绝。
  - `create-shared-kernel.js` 的实例一致性约束不可破坏，否则会出现跨域服务实例漂移。
- 已知限制：
  - 本次不引入新业务能力，不处理产品需求扩展。
  - 迁移阶段允许短期桥接，但最终状态必须删除旧聚合大文件且不残留旧路径引用。
- 后续考虑（超出本次范围）：
  - 将治理能力进一步细化（如 owner-transfer、role-catalog、role-grants）并评估是否拆为独立子 capability。
  - 将 codemod 自动拆分能力用于后续模块（例如 inventory）接入流程。
