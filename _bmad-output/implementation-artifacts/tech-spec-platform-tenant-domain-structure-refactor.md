---
title: '平台与租户双域目录树彻底重构与一致性治理'
slug: 'platform-tenant-domain-structure-refactor'
created: '2026-02-24T23:12:18+0800'
status: 'done'
stepsCompleted: [1, 2, 3, 4]
tech_stack:
  - 'Node.js 24 (CommonJS)'
  - 'React 19 + Vite 7 + Ant Design 6'
  - 'pnpm workspace + custom Nx wrapper (tools/nx.js)'
  - 'MySQL (mysql2) + TypeORM dependency set'
  - 'Redis (ioredis) for OTP/限流/幂等'
  - 'Node built-in test runner (node:test) + assert + supertest'
files_to_modify:
  - '/Users/helloworld/dev/neweast/apps/api/src/http-routes.js'
  - '/Users/helloworld/dev/neweast/apps/api/src/route-manifests/index.js'
  - '/Users/helloworld/dev/neweast/apps/api/src/route-manifests/platform.route-manifest.js'
  - '/Users/helloworld/dev/neweast/apps/api/src/route-manifests/tenant.route-manifest.js'
  - '/Users/helloworld/dev/neweast/apps/api/src/route-permissions.js'
  - '/Users/helloworld/dev/neweast/apps/api/src/modules/auth'
  - '/Users/helloworld/dev/neweast/apps/api/src/modules/audit'
  - '/Users/helloworld/dev/neweast/apps/api/src/server.js'
  - '/Users/helloworld/dev/neweast/apps/api/src/app.js'
  - '/Users/helloworld/dev/neweast/apps/api/test/platform.org.api.test.js'
  - '/Users/helloworld/dev/neweast/apps/api/test/platform.user.api.test.js'
  - '/Users/helloworld/dev/neweast/apps/api/test/platform.role.api.test.js'
  - '/Users/helloworld/dev/neweast/apps/api/test/tenant.user.api.test.js'
  - '/Users/helloworld/dev/neweast/apps/api/test/tenant.role.api.test.js'
  - '/Users/helloworld/dev/neweast/apps/api/test/http-routes.test.js'
  - '/Users/helloworld/dev/neweast/apps/web/src/App.jsx'
  - '/Users/helloworld/dev/neweast/apps/web/src/api/platform-management.mjs'
  - '/Users/helloworld/dev/neweast/apps/web/src/api/tenant-management.mjs'
  - '/Users/helloworld/dev/neweast/apps/web/scripts/sync-permission-catalog.cjs'
  - '/Users/helloworld/dev/neweast/package.json'
  - '/Users/helloworld/dev/neweast/tools/domain-contract/naming-rules.json'
  - '/Users/helloworld/dev/neweast/tools/domain-contract/check-domain-symmetry.js'
  - '/Users/helloworld/dev/neweast/tools/domain-contract/check-refactor-governance.js'
  - '/Users/helloworld/dev/neweast/tools/domain-contract/domain-extension-registry.json'
  - '/Users/helloworld/dev/neweast/tools/lint-rules/no-cross-domain-imports.js'
  - '/Users/helloworld/dev/neweast/tools/scaffold/check-domain-module-scaffold-smoke.js'
  - '/Users/helloworld/dev/neweast/apps/api/test/domain.symmetry.test.js'
  - '/Users/helloworld/dev/neweast/apps/api/test/domain-contract.guards.test.js'
  - '/Users/helloworld/dev/neweast/_bmad-output/implementation-artifacts/refactor-review-record.json'
  - '/Users/helloworld/dev/neweast/docs/templates/spec-diff-justification.md'
  - '/Users/helloworld/dev/neweast/apps/web/test/server.test.js'
  - '/Users/helloworld/dev/neweast/apps/web/test/chrome.playwright.test.js'
  - '/Users/helloworld/dev/neweast/tools/domain-contract/capability-map.schema.json'
  - '/Users/helloworld/dev/neweast/apps/api/test/contracts'
  - '/Users/helloworld/dev/neweast/apps/api/test/invariants'
  - '/Users/helloworld/dev/neweast/tools/scaffold/create-domain-module.mjs'
  - '/Users/helloworld/dev/neweast/tools/scaffold/templates/domain-module'
  - '/Users/helloworld/dev/neweast/tools/lint-rules/file-granularity-thresholds.js'
  - '/Users/helloworld/dev/neweast/apps/api/src/domains'
  - '/Users/helloworld/dev/neweast/apps/api/src/domains/platform/settings'
  - '/Users/helloworld/dev/neweast/apps/api/src/domains/platform/config'
  - '/Users/helloworld/dev/neweast/apps/api/src/domains/platform/auth'
  - '/Users/helloworld/dev/neweast/apps/api/src/domains/tenant/settings'
  - '/Users/helloworld/dev/neweast/apps/api/src/domains/tenant/config'
  - '/Users/helloworld/dev/neweast/apps/api/src/domains/tenant/auth'
  - '/Users/helloworld/dev/neweast/apps/api/src/domains/platform/auth/session'
  - '/Users/helloworld/dev/neweast/apps/api/src/domains/tenant/auth/session'
  - '/Users/helloworld/dev/neweast/apps/api/src/modules'
  - '/Users/helloworld/dev/neweast/apps/web/src/domains'
  - '/Users/helloworld/dev/neweast/apps/web/src/domains/platform/settings'
  - '/Users/helloworld/dev/neweast/apps/web/src/domains/platform/config'
  - '/Users/helloworld/dev/neweast/apps/web/src/domains/platform/auth'
  - '/Users/helloworld/dev/neweast/apps/web/src/domains/tenant/settings'
  - '/Users/helloworld/dev/neweast/apps/web/src/domains/tenant/config'
  - '/Users/helloworld/dev/neweast/apps/web/src/domains/tenant/auth'
  - '/Users/helloworld/dev/neweast/apps/web/src/domains/platform/auth/session'
  - '/Users/helloworld/dev/neweast/apps/web/src/domains/tenant/auth/session'
  - '/Users/helloworld/dev/neweast/apps/web/src/features'
  - '/Users/helloworld/dev/neweast/tools/codemods/migrate-domain-imports.mjs'
  - '/Users/helloworld/dev/neweast/tools/lint-rules/no-domain-deep-imports.js'
  - '/Users/helloworld/dev/neweast/apps/api/test/helpers/deterministic-clock.js'
  - '/Users/helloworld/dev/neweast/apps/api/test/helpers/deterministic-random.js'
  - '/Users/helloworld/dev/neweast/apps/api/test/helpers/fixture-loader.js'
  - '/Users/helloworld/dev/neweast/apps/web/test/helpers/deterministic-env.mjs'
code_patterns:
  - 'API 以 constants/routes/service + runtime/handlers 作为能力单元模板。'
  - 'http-routes.js 是组合根，当前通过 shared authService 对 platform/tenant/audit 形成强耦合。'
  - '路由权限声明以 route-manifests 为源，并由 route-permissions 校验一致性。'
  - '路由层统一采用 resolveRoutePreauthorizedContext 做预授权短路与 entry_domain/scope 校验。'
  - 'Web 侧采用 DomainShell + ManagementLayout + menu config registry + lazy page 组合模式。'
  - 'platform/tenant API 客户端存在 requestJson/toSearch/idempotency 逻辑重复。'
  - 'platform 与 tenant 在命名与语义上目前仅部分对齐（role 对齐，user/org/member 语义分歧）。'
test_patterns:
  - 'API 以 node:test + assert/strict 编写，dispatchApiRoute/createRouteHandlers 为核心 harness。'
  - '测试命名常见模式为 <domain>.<feature>.(api|service).test.js。'
  - '平台域与租户域均有独立 API 测试，另有 http-routes 聚合层测试。'
  - 'Web 使用 node:test，包含 server 路由测试与 Chrome/CDP 端到端测试。'
---

# Tech-Spec: 平台与租户双域目录树彻底重构与一致性治理

**Created:** 2026-02-24T23:12:18+0800

## Overview

### Problem Statement

当前代码目录树在双域治理上存在系统性问题：
1. `platform` 与 `tenant` 在代码组织与装配链路上尚未实现彻底隔离。
2. 存在职责过载的大文件，影响可维护性与演进效率。
3. 存在过度细碎拆分，导致定位成本与理解成本偏高。
4. `platform` 与 `tenant` 同类功能在实现路径上存在不一致或缺失。
5. 项目当前仅有设置模块，但即将快速扩展多业务模块，现结构难以支撑规模化演进。

### Solution

采用领域优先（Domain-first）与边界上下文（Bounded Context）重构方案：以 `platform` 与 `tenant` 为一级业务边界进行最大隔离（C 级），仅保留极薄 shared kernel；统一双域能力蓝图与实现路径；按最佳实践重新定义“拆分与聚合”规则，在保持用户侧与数据侧结果一致的前提下完成 API/Web 目录树与模块装配重建。

### Scope

**In Scope:**
- API 与 Web 的目录树、模块边界、运行时装配路径重构
- `platform` / `tenant` 同类能力对齐与缺口补齐
- 大文件按职责拆分、过碎文件按能力聚合
- 导入依赖关系与测试结构重排
- 为后续多模块扩展建立统一目录模板、约束与检查点

**Out of Scope:**
- 新业务需求交付（仅做结构重构与一致性治理）
- 用户侧体验语义与数据语义变更
- 非重构必需的数据模型语义调整

## Context for Development

### Codebase Patterns

- 单仓多应用结构：`apps/api` + `apps/web`，由 workspace 脚本统一调度。
- API 领域结构已具雏形：`modules/auth|platform|tenant|audit|integration`，但组合根仍集中在 `http-routes.js`。
- `platform` 与 `tenant` 能力层多采用 `*.constants.js` + `*.routes.js` + `*.service.js` 三段式，外层由 `*.runtime.js` 和 `*.handlers.js` 聚合。
- 预授权模式统一：路由层通过 `resolveRoutePreauthorizedContext` 和 `expectedScope/expectedEntryDomain` 校验后可短路 token 解析。
- 路由声明链统一：`route-manifests/*` -> `route-permissions.js` -> 检查脚本/测试；重构必须保持该链条可追踪。
- Web 双域具备独立壳层：`PlatformDomainShell` / `TenantDomainShell`；但 tenant 额外承载组织切换状态流，当前与 platform 对称性不足。
- Web 双域 API 客户端结构高度相似，但存在重复实现，可抽取 shared kernel。
- 大文件集中在 `auth.*`、`openapi.js` 与部分高复杂度页面/测试，属于重构首批拆分对象。
- 未发现 `project-context.md`（已确认）。

### Files to Reference

| File | Purpose |
| ---- | ------- |
| `/Users/helloworld/dev/neweast/apps/api/src/http-routes.js` | API 组合根与跨域耦合热点 |
| `/Users/helloworld/dev/neweast/apps/api/src/modules/platform/platform.runtime.js` | 平台域运行时装配模式 |
| `/Users/helloworld/dev/neweast/apps/api/src/modules/tenant/tenant.runtime.js` | 租户域运行时装配模式 |
| `/Users/helloworld/dev/neweast/apps/api/src/modules/platform/platform.handlers.js` | 平台域 handler 聚合接口 |
| `/Users/helloworld/dev/neweast/apps/api/src/modules/tenant/tenant.handlers.js` | 租户域 handler 聚合接口 |
| `/Users/helloworld/dev/neweast/apps/api/src/route-manifests/platform.route-manifest.js` | 平台域路由权限声明 |
| `/Users/helloworld/dev/neweast/apps/api/src/route-manifests/tenant.route-manifest.js` | 租户域路由权限声明 |
| `/Users/helloworld/dev/neweast/apps/api/src/route-permissions.js` | 路由声明校验与门禁规则 |
| `/Users/helloworld/dev/neweast/apps/web/src/App.jsx` | Web 入口壳层与双域切换主流程 |
| `/Users/helloworld/dev/neweast/apps/web/src/features/platform-management/platform-management.config.jsx` | 平台菜单与权限规则 |
| `/Users/helloworld/dev/neweast/apps/web/src/features/tenant-management/tenant-management.config.jsx` | 租户菜单与权限规则 |
| `/Users/helloworld/dev/neweast/apps/web/src/api/platform-management.mjs` | 平台域 API 客户端模式 |
| `/Users/helloworld/dev/neweast/apps/web/src/api/tenant-management.mjs` | 租户域 API 客户端模式 |
| `/Users/helloworld/dev/neweast/apps/web/scripts/sync-permission-catalog.cjs` | 前后端权限目录同步机制 |

### Target Directory Blueprint

目标目录树采用镜像模板（示例）：

```text
apps/api/src/
  shared-kernel/
    auth/
      auth-problem-error.js
      route-authz.js
    http/
    observability/
  domains/
    platform/
      settings/
        user/{controller,service,repository,constants}
        role/{controller,service,repository,constants}
        org/{controller,service,repository,constants}
      config/
        password-policy/{controller,service,repository,constants}
        system-config/{controller,service,repository,constants}
        integration/
          catalog/{controller,service,repository,constants}
          contract/{controller,service,repository,constants}
          recovery/{controller,service,repository,constants}
          freeze/{controller,service,repository,constants}
      auth/
        session/{login,logout,otp-send,otp-login,refresh,change-password}
        context/{platform-options}
        provisioning/{user-management-probe,provision-user}
    tenant/
      settings/
        user/{controller,service,repository,constants}
        role/{controller,service,repository,constants}
      config/
        domain-extension/{registry}
      auth/
        session/{login,logout,otp-send,otp-login,refresh,change-password,switch-org}
        context/{tenant-options,tenant-select}
        provisioning/{user-management-probe,provision-user}
```

```text
apps/web/src/
  shared-kernel/
    http/{request-json.mjs,idempotency-key.mjs}
    permission/
  domains/
    platform/
      settings/
        user/{api,mappers,hooks,views}
        role/{api,mappers,hooks,views}
        org/{api,mappers,hooks,views}
      config/
        password-policy/{api,mappers,hooks,views}
        system-config/{api,mappers,hooks,views}
        integration/
          catalog/{api,mappers,hooks,views}
          contract/{api,mappers,hooks,views}
          recovery/{api,mappers,hooks,views}
          freeze/{api,mappers,hooks,views}
      auth/
        session/{api,mappers,hooks,views}
        context/{api,mappers,hooks}
        provisioning/{api,mappers,hooks}
      shell/{layout,menu,routes}
    tenant/
      settings/
        user/{api,mappers,hooks,views}
        role/{api,mappers,hooks,views}
      config/
        domain-extension/{registry}
      auth/
        session/{api,mappers,hooks,views}
        context/{api,mappers,hooks}
        provisioning/{api,mappers,hooks}
      shell/{layout,menu,routes}
```

目录层级强制采用：`domains/{domain}/{module}/{capability}`。  
当前阶段基础模块集合为：`settings`、`config`、`auth`。  
归属规则强制为：`用户管理/角色管理/组织管理` 归 `settings`；`默认密码策略/系统配置/集成治理` 归 `config`；`登录/退出登录/OTP/刷新会话/改密/组织切换` 与 `context/provisioning` 归 `auth`（`组织切换` 归 `auth/session/switch-org`）。
`tenant/config` 在无可见能力时仅允许保留 `domain-extension/registry` 占位；该状态下前端不得展示 `config` 菜单与路由入口。

### Technical Decisions

- 硬约束：
  - 用户侧行为保持一致
  - 数据侧结果保持一致
  - 所有改动必须符合当前最佳实践，禁止以“最小化改动兜底”作为方案或验收标准
- 可调整项：
  - API 契约与内部调用链
  - 目录树、模块边界、文件拆分与聚合
- 隔离策略：`platform` / `tenant` 采用 C 级最大隔离，仅保留极薄共享内核
- 命名约束：`platform` 与 `tenant` 的文件命名格式、目录层级命名、语义命名必须成对一致（同能力同命名规则）
- 决策输入约束：本轮重构不引入或扩展“历史架构文档”作为方案约束，完全基于当前代码事实与最佳实践
- 重构策略：目标态一次定版，分波次实施并以全量回归门禁收敛风险
- 实施原则：先建立 `platform/tenant` 镜像目录契约，再迁移代码，最后抽取 shared kernel（mirror-first）
- 结构原则：`platform` 与 `tenant` 同能力必须同层级、同命名语法、同文件职责粒度
- 目录原则：能力目录不得直接挂在 `platform/tenant` 下，必须挂在 `module` 下（`{domain}/{module}/{capability}`）
- module 命名原则：使用业务语义名（如 `settings`/`inventory`），禁止 `tenant-xxx` 或 `platform-xxx` 这类域名拼接前缀
- 当前基线模块：`settings`、`config`、`auth`（按前台展示与交互流归属放置）
- 归属规则：`用户管理/角色管理/组织管理` 归 `settings`；`默认密码策略/系统配置/集成治理` 归 `config`；`登录/退出登录/OTP/刷新会话/改密/组织切换` 与 `context/provisioning` 归 `auth`
- 覆盖原则：模块划分必须完整覆盖当前行为能力，至少包含 `settings.management`、`config.governance`、`auth.session`、`auth.context`、`auth.provisioning` 能力簇
- 语义原则：对 `org/member/user` 等历史语义差异直接统一命名并一次性迁移，不保留映射层或别名层
- shared-kernel 白名单（允许）：错误模型、鉴权适配器、HTTP 客户端基础层、日志追踪工具、纯函数映射器
- shared-kernel 黑名单（禁止）：任一 domain 专属 repository、domain 状态机、domain 业务规则
- shared-kernel 边界原则：`session/context/provisioning` 业务能力目录必须落在 `domains/{domain}/auth/*`，shared-kernel 仅提供通用适配器与基础设施能力
- domain-extension 规则：非对称能力必须登记在 `domain-extension-registry.json`，包含 owner、理由、退出条件、复审日期；常规复审由技术 owner 执行，仅在范围扩展或影响用户侧/数据侧一致性时升级产品确认
- 过渡原则：名称与目录直接调整到目标态，不引入额外映射适配层
- 拆分与聚合基线：
  - 生产代码文件 > 800 LOC 默认进入拆分候选（按职责而非按语句机械切片）
  - 同能力文件组若出现过细碎片（大量 < 120 LOC 且单一导出）默认进入聚合候选
  - 共享逻辑仅允许落在 shared kernel，不允许跨域互引具体业务实现
- Task DoD 标准（适用于每个任务）：
  - 代码变更通过 lint/test/对称性检查
  - 无跨域非法 import
  - 变更可追溯到至少 1 条 AC
  - 如存在可接受差异，必须附 `spec-diff-justification` 记录

## Implementation Plan

### Tasks

- [x] Task 1: 建立双域镜像契约与语义命名规范源
  - File: `/Users/helloworld/dev/neweast/tools/domain-contract/capability-map.json`
  - File: `/Users/helloworld/dev/neweast/tools/domain-contract/naming-rules.json`
  - File: `/Users/helloworld/dev/neweast/tools/domain-contract/domain-extension-registry.json`
  - Action: 定义 `platform` 与 `tenant` 的能力清单、目录层级、文件命名语法与语义对齐规则（含 `user/member/org` 历史命名直接统一）、模块集合（`settings/config/auth`）以及非对称能力登记
  - Notes: 该契约作为后续脚本检查与代码迁移唯一真源，不依赖历史架构文档；domain-extension 按 owner 周期复审

- [x] Task 2: 增加镜像一致性自动检查门禁
  - File: `/Users/helloworld/dev/neweast/apps/api/scripts/check-domain-symmetry.js`
  - File: `/Users/helloworld/dev/neweast/apps/web/scripts/check-domain-symmetry.cjs`
  - File: `/Users/helloworld/dev/neweast/package.json`
  - File: `/Users/helloworld/dev/neweast/apps/api/package.json`
  - File: `/Users/helloworld/dev/neweast/apps/web/package.json`
  - Action: 新增并接入镜像检查命令，校验成对目录、成对文件、命名格式、能力语义命名完整性
  - Notes: 失败即阻断提交链路

- [x] Task 3: 拆分 API 组合根并建立域级装配入口
  - File: `/Users/helloworld/dev/neweast/apps/api/src/http-routes.js`
  - File: `/Users/helloworld/dev/neweast/apps/api/src/bootstrap/create-route-runtime.js`
  - File: `/Users/helloworld/dev/neweast/apps/api/src/domains/platform/runtime/create-platform-domain-runtime.js`
  - File: `/Users/helloworld/dev/neweast/apps/api/src/domains/tenant/runtime/create-tenant-domain-runtime.js`
  - File: `/Users/helloworld/dev/neweast/apps/api/src/bootstrap/create-shared-kernel.js`
  - Action: 将当前集中装配拆分为 shared-kernel + platform runtime + tenant runtime，减少跨域耦合
  - Notes: 子步骤顺序固定为 3.1 抽组合根 -> 3.2 建平台 runtime -> 3.3 建租户 runtime -> 3.4 合并 shared-kernel 注入；`http-routes.js` 仅保留路由绑定与组合逻辑

- [x] Task 4: 建立 API shared-kernel 并替换跨域硬依赖
  - File: `/Users/helloworld/dev/neweast/apps/api/src/shared-kernel/auth/auth-problem-error.js`
  - File: `/Users/helloworld/dev/neweast/apps/api/src/shared-kernel/auth/route-authz.js`
  - File: `/Users/helloworld/dev/neweast/apps/api/src/modules/auth/auth.service.js`
  - File: `/Users/helloworld/dev/neweast/apps/api/src/modules/auth/route-preauthorization.js`
  - Action: 抽取跨域共享的错误模型与预授权能力，替代 platform/tenant 对 `auth.service` 内部实现的直接耦合
  - Notes: 子步骤顺序固定为 4.1 错误模型抽取 -> 4.2 预授权抽取 -> 4.3 domain 适配替换 -> 4.4 删除旧跨域依赖；同时覆盖 auth 关键能力簇（`session`: login/logout/otp-send/otp-login/refresh/change-password/switch-org，`context`: platform-options/tenant-options/select，`provisioning`: probe/provision-user）。`session/context/provisioning` 的业务代码必须落位到 `domains/{domain}/auth/*`，不得继续放在 shared-kernel。

- [x] Task 5: 平台域按镜像模板重排目录（治理能力组）
  - File: `/Users/helloworld/dev/neweast/apps/api/src/domains/platform/settings/org/*`
  - File: `/Users/helloworld/dev/neweast/apps/api/src/domains/platform/settings/role/*`
  - File: `/Users/helloworld/dev/neweast/apps/api/src/domains/platform/settings/user/*`
  - File: `/Users/helloworld/dev/neweast/apps/api/src/domains/platform/runtime/platform.runtime.js`
  - File: `/Users/helloworld/dev/neweast/apps/api/src/domains/platform/index.js`
  - Action: 按能力分层整理并对齐命名语法，消除同类功能路径漂移
  - Notes: 大于阈值文件先按职责拆分再迁移；`用户管理/角色管理/组织管理` 统一归 `settings/*`

- [x] Task 6: 平台域按镜像模板重排目录（config 治理能力组）
  - File: `/Users/helloworld/dev/neweast/apps/api/src/domains/platform/config/system-config/{constants,service}/*`
  - File: `/Users/helloworld/dev/neweast/apps/api/src/domains/platform/config/system-config/system-config.routes.js`
  - File: `/Users/helloworld/dev/neweast/apps/api/src/domains/platform/config/integration/{constants,service}/*`
  - File: `/Users/helloworld/dev/neweast/apps/api/src/domains/platform/config/integration/integration.routes.js`
  - File: `/Users/helloworld/dev/neweast/apps/api/src/domains/platform/config/integration-contract/{constants,service}/*`
  - File: `/Users/helloworld/dev/neweast/apps/api/src/domains/platform/config/integration-contract/integration-contract.routes.js`
  - File: `/Users/helloworld/dev/neweast/apps/api/src/domains/platform/config/integration-recovery/{constants,service}/*`
  - File: `/Users/helloworld/dev/neweast/apps/api/src/domains/platform/config/integration-recovery/integration-recovery.routes.js`
  - File: `/Users/helloworld/dev/neweast/apps/api/src/domains/platform/config/integration-freeze/{constants,service}/*`
  - File: `/Users/helloworld/dev/neweast/apps/api/src/domains/platform/config/integration-freeze/integration-freeze.routes.js`
  - File: `/Users/helloworld/dev/neweast/apps/api/src/domains/platform/runtime/platform.runtime.js`
  - File: `/Users/helloworld/dev/neweast/apps/api/src/domains/platform/index.js`
  - Action: 将平台治理扩展能力统一收敛到 `config/*` 分层模板（password-policy/system-config/integration）
  - Notes: 治理扩展能力默认落到 `config/*`（`password-policy`、`system-config`、`integration/*`）；`password-policy` 当前仍以 `domain-extension-registry` 记录为平台单边能力，未引入运行时代码路径

- [x] Task 7: 租户域按镜像模板重排目录并完成语义对齐
  - File: `/Users/helloworld/dev/neweast/apps/api/src/domains/tenant/settings/user/constants/index.js`
  - File: `/Users/helloworld/dev/neweast/apps/api/src/domains/tenant/settings/user/user.routes.js`
  - File: `/Users/helloworld/dev/neweast/apps/api/src/domains/tenant/settings/user/service/index.js`
  - File: `/Users/helloworld/dev/neweast/apps/api/src/domains/tenant/settings/role/constants/index.js`
  - File: `/Users/helloworld/dev/neweast/apps/api/src/domains/tenant/settings/role/role.routes.js`
  - File: `/Users/helloworld/dev/neweast/apps/api/src/domains/tenant/settings/role/service/index.js`
  - File: `/Users/helloworld/dev/neweast/apps/api/src/domains/tenant/runtime/tenant.runtime.js`
  - File: `/Users/helloworld/dev/neweast/apps/api/src/domains/tenant/runtime/tenant.handlers.js`
  - File: `/Users/helloworld/dev/neweast/apps/api/test/tenant.user.api.test.js`
  - File: `/Users/helloworld/dev/neweast/apps/api/test/tenant.role.api.test.js`
  - Action: 与 platform 完成命名/层级对齐，`member` 直接统一命名为 `user` 并沉淀单一术语
  - Notes: 不允许临时兼容别名或中间映射；`user/role` 归 `settings/*`，`组织切换` 归 `auth/session/*`

- [x] Task 8: 重建路由声明链并保持权限门禁可验证
  - File: `/Users/helloworld/dev/neweast/apps/api/src/route-manifests/platform.route-manifest.js`
  - File: `/Users/helloworld/dev/neweast/apps/api/src/route-manifests/tenant.route-manifest.js`
  - File: `/Users/helloworld/dev/neweast/apps/api/src/route-manifests/index.js`
  - File: `/Users/helloworld/dev/neweast/apps/api/src/route-permissions.js`
  - Action: 迁移后同步更新 route manifest 来源与 scope/permission 对齐规则
  - Notes: 保持 `check:route-permissions` 可直接阻断不一致声明

- [x] Task 9: Web 抽取 shared-kernel 并统一双域 API 客户端模板
  - File: `/Users/helloworld/dev/neweast/apps/web/src/shared-kernel/http/request-json.mjs`
  - File: `/Users/helloworld/dev/neweast/apps/web/src/shared-kernel/http/idempotency-key.mjs`
  - File: `/Users/helloworld/dev/neweast/apps/web/src/api/platform-management.mjs`
  - File: `/Users/helloworld/dev/neweast/apps/web/src/api/tenant-management.mjs`
  - Action: 抽取重复的请求、错误处理、幂等 key 生成逻辑，保留域特定 payload 字段处理
  - Notes: 保证用户侧反馈语义完全一致

- [x] Task 10: Web 平台域迁移至镜像目录模板
  - File: `/Users/helloworld/dev/neweast/apps/web/src/App.jsx`
  - File: `/Users/helloworld/dev/neweast/apps/web/src/domains/platform/PlatformApp.jsx`
  - File: `/Users/helloworld/dev/neweast/apps/web/src/domains/platform/auth/context/PlatformDomainShell.jsx`
  - File: `/Users/helloworld/dev/neweast/apps/web/src/domains/platform/settings/workbench/PlatformManagementLayoutPage.jsx`
  - File: `/Users/helloworld/dev/neweast/apps/web/src/domains/platform/settings/workbench/platform-management.config.jsx`
  - File: `/Users/helloworld/dev/neweast/apps/web/src/domains/platform/settings/{user,role,org}/*`
  - Action: 以能力层级重排平台域页面、菜单与状态边界，沉淀可复用模板供后续新模块扩展
  - Notes: 保留现有页面行为与交互语义；`用户管理/角色管理/组织管理` 归 `settings/*`，不得分散到其它模块

- [x] Task 11: Web 租户域迁移至镜像目录模板并对齐命名语义
  - File: `/Users/helloworld/dev/neweast/apps/web/src/domains/tenant/TenantApp.jsx`
  - File: `/Users/helloworld/dev/neweast/apps/web/src/domains/tenant/auth/context/TenantDomainShell.jsx`
  - File: `/Users/helloworld/dev/neweast/apps/web/src/domains/tenant/settings/workbench/TenantManagementLayoutPage.jsx`
  - File: `/Users/helloworld/dev/neweast/apps/web/src/domains/tenant/settings/workbench/tenant-management.config.jsx`
  - File: `/Users/helloworld/dev/neweast/apps/web/src/domains/tenant/auth/session/useTenantSessionFlow.js`
  - File: `/Users/helloworld/dev/neweast/apps/web/src/domains/tenant/settings/{user,role}/*`
  - Action: 将 tenant 域特有组织切换流收敛为标准能力层，确保与 platform 结构镜像并可持续扩展
  - Notes: 语义命名规范由 Task 1 契约驱动，不允许局部命名漂移；`登录/退出` 与 `组织切换` 均归 `auth/session/*`；当租户域无 `config` 可见能力时，必须隐藏 `config` 菜单与路由入口，仅保留 `domain-extension/registry` 契约记录

- [x] Task 12: 补齐并重构测试基线（对称性 + 用户侧 + 数据侧）
  - File: `/Users/helloworld/dev/neweast/apps/api/test/http-routes.test.js`
  - File: `/Users/helloworld/dev/neweast/apps/api/test/platform.org.api.test.js`
  - File: `/Users/helloworld/dev/neweast/apps/api/test/platform.user.api.test.js`
  - File: `/Users/helloworld/dev/neweast/apps/api/test/platform.role.api.test.js`
  - File: `/Users/helloworld/dev/neweast/apps/api/test/tenant.user.api.test.js`
  - File: `/Users/helloworld/dev/neweast/apps/api/test/tenant.role.api.test.js`
  - File: `/Users/helloworld/dev/neweast/apps/api/test/domain.symmetry.test.js`
  - File: `/Users/helloworld/dev/neweast/apps/api/test/domain-contract.guards.test.js`
  - File: `/Users/helloworld/dev/neweast/apps/api/test/contracts/*.test.js`
  - File: `/Users/helloworld/dev/neweast/apps/api/test/invariants/*.test.js`
  - File: `/Users/helloworld/dev/neweast/apps/web/test/server.test.js`
  - File: `/Users/helloworld/dev/neweast/apps/web/test/chrome.playwright.test.js`
  - Action: 新增镜像检查测试、用户侧黄金流程回归、数据侧语义回归，并更新既有测试路径
  - Notes: 黄金用例需覆盖登录、权限、用户/角色治理、组织切换

- [x] Task 13: 清理旧路径并收口到目标结构
  - File: `/Users/helloworld/dev/neweast/apps/api/src/domains/platform/runtime/*`
  - File: `/Users/helloworld/dev/neweast/apps/api/src/domains/tenant/runtime/*`
  - File: `/Users/helloworld/dev/neweast/apps/api/src/modules`（已移除 `platform`、`tenant` 子目录）
  - File: `/Users/helloworld/dev/neweast/apps/web/src/features/platform-management`
  - File: `/Users/helloworld/dev/neweast/apps/web/src/features/tenant-management`
  - Action: 在新路径稳定后移除迁移期间临时目录与旧目录，统一 import 到目标结构
  - Notes: 清理前必须完成全量测试与门禁验证；禁止引入运行时兼容层、路径别名桥接层或映射适配层作为“过渡方案”

- [x] Task 14: 建立跨域 import 静态门禁
  - File: `/Users/helloworld/dev/neweast/tools/lint-rules/no-cross-domain-imports.js`
  - File: `/Users/helloworld/dev/neweast/tools/lint.js`
  - File: `/Users/helloworld/dev/neweast/apps/api/package.json`
  - File: `/Users/helloworld/dev/neweast/apps/web/package.json`
  - Action: 增加 `platform <-> tenant` 跨域 import 禁止规则，仅允许通过 shared-kernel 边界访问共享能力
  - Notes: 规则应支持 allowlist（仅限基础设施级例外），默认 deny

- [x] Task 15: 固化黄金基线与差异说明模板
  - File: `/Users/helloworld/dev/neweast/apps/api/test/fixtures/golden-user-side.json`
  - File: `/Users/helloworld/dev/neweast/apps/api/test/fixtures/golden-data-side.json`
  - File: `/Users/helloworld/dev/neweast/docs/templates/spec-diff-justification.md`
  - File: `/Users/helloworld/dev/neweast/_bmad-output/implementation-artifacts/spec-diff-register.json`
  - Action: 固化用户侧/数据侧可比较基线，并提供“可接受差异”记录模板
  - Notes: 任一差异若未登记模板记录，则默认视为回归缺陷

- [x] Task 16: 建立阶段里程碑与 scope 冻结机制
  - File: `/Users/helloworld/dev/neweast/_bmad-output/implementation-artifacts/refactor-milestones.yaml`
  - File: `/Users/helloworld/dev/neweast/_bmad-output/implementation-artifacts/refactor-review-record.json`
  - File: `/Users/helloworld/dev/neweast/tools/domain-contract/check-refactor-governance.js`
  - File: `/Users/helloworld/dev/neweast/package.json`
  - Action: 定义 M1-M4 里程碑、每阶段入场与出场条件、scope freeze 规则（禁止顺便功能重构）
  - Notes: 若新增需求超出本 spec，必须进入新 spec 或变更审批，不得并入当前任务

- [x] Task 17: 升级 capability 契约为 schema v2 并强制引用
  - File: `/Users/helloworld/dev/neweast/tools/domain-contract/capability-map.schema.json`
  - File: `/Users/helloworld/dev/neweast/tools/domain-contract/capability-map.json`
  - File: `/Users/helloworld/dev/neweast/apps/api/scripts/check-domain-symmetry.js`
  - File: `/Users/helloworld/dev/neweast/apps/web/scripts/check-domain-symmetry.cjs`
  - Action: 为能力契约增加 `capability_id`、`canonical_term`、`module`、`domain`、`owner`、`review_at` 字段并在检查脚本中强制校验
  - Notes: 禁止 alias 字段与映射适配字段进入主干，统一使用单一 canonical 命名

- [x] Task 18: 建立 API 契约快照与数据不变量门禁
  - File: `/Users/helloworld/dev/neweast/apps/api/test/contracts/platform.contract.snapshot.test.js`
  - File: `/Users/helloworld/dev/neweast/apps/api/test/contracts/tenant.contract.snapshot.test.js`
  - File: `/Users/helloworld/dev/neweast/apps/api/test/invariants/data-side.invariant.test.js`
  - File: `/Users/helloworld/dev/neweast/apps/api/test/invariants/audit-chain.invariant.test.js`
  - File: `/Users/helloworld/dev/neweast/apps/api/package.json`
  - Action: 为关键接口建立响应契约快照，并对关键写链路建立唯一性/状态迁移/审计链不变量断言
  - Notes: 快照更新必须通过评审并附差异说明，禁止静默更新基线

- [x] Task 19: 建立双域脚手架与文件粒度 CI 门禁
  - File: `/Users/helloworld/dev/neweast/tools/scaffold/create-domain-module.mjs`
  - File: `/Users/helloworld/dev/neweast/tools/scaffold/templates/domain-module/*`
  - File: `/Users/helloworld/dev/neweast/tools/lint-rules/file-granularity-thresholds.js`
  - File: `/Users/helloworld/dev/neweast/package.json`
  - Action: 新增 `create:domain-module` 脚手架命令按镜像模板生成 platform/tenant 能力目录，并在 CI 中校验大文件/过碎文件阈值
  - Notes: 默认阈值沿用本 spec（>800 LOC 拆分候选；大量 <120 LOC 单导出文件进入聚合候选）

- [x] Task 20: 完成 `modules/features -> domains` 命名空间终态迁移
  - File: `/Users/helloworld/dev/neweast/apps/api/src/domains`
  - File: `/Users/helloworld/dev/neweast/apps/api/src/modules`
  - File: `/Users/helloworld/dev/neweast/apps/web/src/domains`
  - File: `/Users/helloworld/dev/neweast/apps/web/src/features`
  - File: `/Users/helloworld/dev/neweast/apps/api/src/http-routes.js`
  - File: `/Users/helloworld/dev/neweast/apps/web/src/App.jsx`
  - File: `/Users/helloworld/dev/neweast/tools/domain-contract/check-domain-symmetry.js`
  - File: `/Users/helloworld/dev/neweast/apps/api/test/domain-contract.guards.test.js`
  - Action: 将 API/Web 业务能力统一收敛到 `domains/{domain}/{module}/{capability}` 命名空间，并按前台展示归属到 `settings/config/auth`，完成旧命名空间迁出与最终清理
  - Notes: 迁移后必须由自动化检查证明 `modules/features` 业务引用为 0，且禁止 `domains/{domain}/{capability}` 直挂能力目录

- [x] Task 21: 建立导入迁移 codemod 与 domain public API 门禁
  - File: `/Users/helloworld/dev/neweast/tools/codemods/migrate-domain-imports.mjs`
  - File: `/Users/helloworld/dev/neweast/tools/lint-rules/no-domain-deep-imports.js`
  - File: `/Users/helloworld/dev/neweast/apps/api/package.json`
  - File: `/Users/helloworld/dev/neweast/apps/web/package.json`
  - File: `/Users/helloworld/dev/neweast/package.json`
  - Action: 用 codemod 批量改写 import 到 domain public API 入口，并用 lint 阻断 deep import 回归
  - Notes: `platform` 与 `tenant` 只能通过各自 `index` 导出面消费能力，禁止绕过边界直接引子路径

- [x] Task 22: 建立可重复执行的 deterministic test harness
  - File: `/Users/helloworld/dev/neweast/apps/api/test/helpers/deterministic-clock.js`
  - File: `/Users/helloworld/dev/neweast/apps/api/test/helpers/deterministic-random.js`
  - File: `/Users/helloworld/dev/neweast/apps/api/test/helpers/fixture-loader.js`
  - File: `/Users/helloworld/dev/neweast/apps/web/test/helpers/deterministic-env.mjs`
  - File: `/Users/helloworld/dev/neweast/apps/api/package.json`
  - File: `/Users/helloworld/dev/neweast/apps/web/package.json`
  - Action: 统一测试时钟、随机种子、ID 生成与 fixture 装载顺序，确保快照与数据侧断言可重复
  - Notes: 同一基线在连续两次执行结果必须一致，差异默认判为测试基建缺陷

### Acceptance Criteria

- [x] AC 1: Given 已定义镜像契约文件, when 执行 `check-domain-symmetry`, then platform/tenant 成对目录、命名格式、语义命名全部通过且无遗漏。
- [x] AC 2: Given 完成 API 装配重构, when 创建路由处理器, then 不再依赖单文件集中耦合并且 platform/tenant/runtime 可独立装配。
- [x] AC 3: Given 重构后的 shared-kernel, when platform/tenant 调用预授权与错误模型, then 不直接依赖 `auth.service` 内部实现且行为语义不变。
- [x] AC 4: Given 平台域治理能力重排完成, when 执行平台用户/角色/组织相关接口回归, then 返回结构与数据语义保持可接受一致。
- [x] AC 5: Given 租户域治理能力重排完成, when 执行租户用户/角色与组织切换相关接口回归, then 返回结构与数据语义保持可接受一致。
- [x] AC 6: Given 路由声明链已重建, when 执行 `pnpm --dir apps/api run check:route-permissions`, then 无缺失声明、无无效 scope、无未知权限码。
- [x] AC 7: Given Web shared-kernel 抽取完成, when 调用 platform/tenant API client, then 通用请求逻辑无重复实现且域特定字段处理正确。
- [x] AC 8: Given Web 双域目录迁移完成, when 用户在 platform/tenant 两域进入 `settings/config/auth` 相关工作台, then 页面导航与权限可见性行为与现有系统一致（tenant 在无 `config` 可见能力时不得展示 `config` 菜单或路由入口）。
- [x] AC 9: Given 命名语义对齐规则生效, when 检查同能力文件, then platform/tenant 文件命名、层级、职责粒度满足镜像一致性要求。
- [x] AC 10: Given 数据侧黄金回归集, when 执行关键写操作（用户、角色授权、状态切换）, then 写库结果与审计事件语义保持一致。
- [x] AC 11: Given 用户侧黄金回归集, when 执行关键流程（登录、权限收敛、组织切换、治理操作）, then 用户可见行为与错误反馈语义保持一致。
- [x] AC 12: Given 大文件拆分策略执行完毕, when 扫描代码行数与模块职责, then 超阈值文件被按职责拆分且无过碎新碎片堆积。
- [x] AC 13: Given 迁移清理阶段结束, when 进行最终收口检查, then 旧路径 import 为 0 且仅保留目标目录树，并且不存在运行时兼容层或映射适配层残留。
- [x] AC 14: Given 全量回归门禁执行, when 运行 `pnpm nx test` 与相关检查脚本, then 所有检查通过后方可合并重构分支。
- [x] AC 15: Given 任一重构任务进入评审, when 检查实现方案与代码结果, then 必须满足最佳实践基线且不得以最小化改动作为兜底通过条件。
- [x] AC 16: Given 目标目录树蓝图, when 对比实际目录结构, then API 与 Web 双域目录均符合镜像层级模板或在 domain-extension 清单中有登记；tenant `config` 若处于占位态仅允许 `domain-extension/registry`，且无前台菜单/路由入口。
- [x] AC 17: Given 静态门禁已启用, when 执行 lint, then 所有跨域 import 违规被阻断且仅 shared-kernel 边界可跨域共享。
- [x] AC 18: Given 用户侧黄金基线, when 执行关键流程回归, then 菜单可见性、交互路径、错误文案对比结果满足一致性阈值（100% 必选项一致）。
- [x] AC 19: Given 数据侧黄金基线, when 执行关键写链路回归, then 关键字段、状态迁移、幂等重复写与审计 event_type 全量一致。
- [x] AC 20: Given 任一差异被标记为“可接受”, when 提交评审, then 必须附带 `spec-diff-justification` 记录并经责任人签署。
- [x] AC 21: Given 重构分阶段执行, when 完成每个里程碑检查, then 未通过不得进入下一阶段且不得扩展本次 scope。
- [x] AC 22: Given capability schema v2 生效, when 执行对称性检查, then 所有能力定义均包含 `capability_id` 且仅使用 canonical 命名（无 alias 字段）。
- [x] AC 23: Given 契约快照与数据不变量门禁启用, when 执行 API 测试链路, then 未经批准的响应结构变化与数据语义漂移会被阻断。
- [x] AC 24: Given 双域脚手架与粒度门禁启用, when 新增模块或执行 CI, then 目录命名镜像规则与文件粒度阈值均被强制校验通过。
- [x] AC 25: Given 命名空间终态迁移完成, when 执行全仓扫描, then 旧 `modules/features` 业务引用数为 0，且无运行时兼容壳/映射适配层残留，并且无 `domains/{domain}/{capability}` 直挂目录。
- [x] AC 26: Given public API 导入门禁生效, when 执行 lint 与 codemod 校验, then 任何 domain deep import 均被阻断并给出修复路径。
- [x] AC 27: Given deterministic test harness 生效, when 在同一环境连续执行两次关键测试链路, then 快照与数据不变量结果完全一致。
- [x] AC 28: Given 新模块接入流程启用, when 新增业务模块（如 `inventory`）, then 必须创建在 `domains/{platform|tenant}/{module}/{capability}` 层级并通过对称性检查。
- [x] AC 29: Given 能力归属规则生效, when 执行模块归属检查, then `用户管理/角色管理/组织管理` 必须落在 `settings`，`默认密码策略/系统配置/集成治理` 必须落在 `config`，`登录/退出登录/OTP/刷新会话/改密/组织切换` 与 `context/provisioning` 必须落在 `auth`（其中 `组织切换` 位于 `auth/session/switch-org`）。

## Additional Context

### Dependencies

- Node.js `>=24` 与 pnpm workspace（现有）
- MySQL 与 Redis 可用测试环境（用于数据侧语义回归）
- 现有权限目录同步链：`apps/web/scripts/sync-permission-catalog.cjs`
- 现有路由权限门禁链：`apps/api/src/route-permissions.js` + `check:route-permissions`
- JSON Schema 校验依赖（建议 `ajv`）用于 capability schema v2 强校验
- 可选 codemod 工具依赖（如 `jscodeshift` 或 `recast`）用于批量 import 迁移
- 可选开发依赖（如需更强依赖边界分析）：`dependency-cruiser` 或等效静态依赖检查工具

### Testing Strategy

- 对称性门禁：新增目录与命名对称性检查（platform/tenant 成对存在、命名规则一致、能力清单完整）
- 用户侧黄金用例：重构前后对比关键用户旅程、权限可见性与错误反馈语义，确保一致
- 数据侧黄金用例：重构前后对比关键写操作结果、状态迁移与审计事件语义，确保一致
- 回归入口：将上述检查接入现有 `pnpm nx test` / `check:route-permissions` 链路，作为重构合并门禁
- 契约快照门禁：关键 API 响应结构与错误语义采用快照测试，任何变更需显式审批
- 数据不变量门禁：关键写链路必须满足唯一性、状态迁移与审计链完整性断言
- 命名空间门禁：增加旧命名空间残留扫描（`modules/features` 引用计数必须为 0），并阻断 `domains/{domain}/{capability}` 直挂目录
- 模块归属门禁：阻断命名漂移，校验 `用户管理/角色管理/组织管理` -> `settings`、`默认密码策略/系统配置/集成治理` -> `config`、`登录/退出登录/OTP/刷新会话/改密/组织切换/context/provisioning` -> `auth`（`switch-org` 位于 `auth/session`）
- tenant config 占位门禁：当仅存在 `domain-extension/registry` 占位时，断言前台无 `config` 菜单与路由入口
- 导入边界门禁：禁止 domain deep import，仅允许 domain public API 导出面
- 单元测试：对 shared-kernel、语义命名规范、路径解析、镜像检查脚本分别补充独立单测
- 集成测试：覆盖 API 装配入口、路由声明链与权限判定链
- E2E/手工验证：覆盖平台与租户在 `settings/config/auth` 三类模块中的关键管理流与组织切换流
- 脚手架校验：新增模块脚手架需有 smoke test，验证产出目录/命名满足镜像契约
- 粒度门禁：CI 校验大文件阈值与过碎文件阈值，不达标即阻断
- 可重复性门禁：冻结时间源、随机种子、ID 生成与 fixture 加载顺序，避免非业务噪声
- 用户侧量化项：
  - 菜单可见性（含禁用态）逐项比对
  - 关键路径跳转与交互动作逐步比对
  - 错误反馈文案与错误码映射逐项比对
- 数据侧量化项：
  - 写入关键字段（主键/外键/状态）逐项比对
  - 状态迁移图前后比对
  - 审计 `event_type`/`request_id`/`traceparent` 语义比对
- 基线版本治理：
  - 黄金基线文件需带版本号
  - 更新基线必须附差异说明模板并在评审记录落档

### Notes

- 用户明确希望“彻底重构并符合当前最佳实践”，不采用最小化兜底方案。
- 2026-02-24：已执行 Advanced Elicitation，用户选择采纳，但本轮未引入额外内容改动。
- 2026-02-24：用户新增硬约束：`platform` 与 `tenant` 相关文件命名格式与语义需保持一致。
- 2026-02-24：已执行 Party Mode 并采纳结论：镜像优先、共享内核最小化、对称性/用户侧/数据侧三类门禁必须并行建立。
- 2026-02-24：二次 Party Mode 评审采纳：加入 capability schema v2、API 契约快照/数据不变量门禁、双域脚手架与文件粒度 CI 门禁。
- 2026-02-24：三次 Party Mode 评审采纳：加入 `domains` 命名空间终态迁移、codemod+public API 导入门禁、deterministic test harness。
- 2026-02-24：用户确认更新：目录采用 `domain/module/capability`，并按前台展示归属 `settings/config/auth`。
- 2026-02-24：用户确认更新：`settings` 仅承载用户管理/角色管理/组织管理；`config` 承载默认密码策略与系统配置/集成治理能力。
- 2026-02-24：用户确认更新：`组织切换` 并入 `auth/session/switch-org`，不再单列 `org-switch` 模块。
- 2026-02-24：用户确认更新：tenant 侧 `config` 在无可见能力时仅保留 `domain-extension/registry` 占位，前台不展示 `config` 菜单与路由入口。
- 2026-02-24：用户新增约束：名称需要直接调整到目标态，不增加映射层、别名层或兼容适配层。
- 2026-02-24：用户新增硬约束：所有改动必须符合最佳实践，不采用“最小化改动兜底”。
- 2026-02-25：F6 收敛：`no-domain-deep-imports` 规则已基于 AST 导入提取执行，仅对仓内 `src/domains` 路径做段级判断；补充误报回归用例（外部包路径含 `domains` 不阻断）。
- 2026-02-25：命名空间收口门禁补齐：`check-domain-symmetry` 新增旧 `modules/features` 引用残留扫描，并阻断 `domains/{domain}/{capability}` 直挂目录。
- 2026-02-25：tenant `config` 占位态门禁补齐：`check-domain-symmetry` 强制 `tenant/config` 仅允许 `domain-extension/registry` 目录与占位文件，并阻断前端 tenant config 菜单/路由标记；Chrome 回归断言同步覆盖。
- 2026-02-25：测试基线收口：contracts/invariants/domain-symmetry 与 Web Chrome 视觉+交互回归链路通过；`pnpm nx test` 全量通过。
- 2026-02-25：AC28/AC29 收口：`check-domain-symmetry` module 校验升级为语义命名 + capability-map 驱动（支持 `inventory` 等新模块接入并通过对称性检查）；同时保留能力归属规则与 `auth/session/switch-org` 位置约束，新增回归用例覆盖。
- 2026-02-25：AC15/AC20/AC21 收口：新增 `check-refactor-governance` 门禁并接入 workspace lint，强制校验里程碑阶段推进顺序、`spec-diff-register` 与 `spec-diff-justification` 记录完整性、以及已完成 Task 的最佳实践评审记录（禁止 minimal-change fallback）。
- 高风险提醒 1：`auth` 共享能力抽取不当会破坏预授权与错误语义一致性。
- 高风险提醒 2：`member/user/org` 语义迁移不完整会导致双域命名再漂移。
- 高风险提醒 3：路由声明链漏改会导致权限门禁与实际路由不一致。
- 高风险提醒 4：若未阻断 deep import，双域边界会在后续模块扩展中快速失效。
- Scope Freeze 规则：本次仅处理目录树与结构一致性重构，禁止夹带新业务功能与产品行为扩展。
- 阶段里程碑：
  - M1：契约与门禁建立（Task 1/2/14/15/17/19/21）
  - M2：API 重构完成并过门禁（Task 3-8/18）
  - M3：Web 重构完成并过门禁（Task 9-11/22）
  - M4：命名空间收口与清理完成（Task 12/13/16/20）
- 后续扩展建议：在本次重构落地后，补充“新模块脚手架”自动生成镜像目录与命名模板，避免人工偏移。
