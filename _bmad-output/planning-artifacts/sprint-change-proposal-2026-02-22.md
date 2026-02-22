# Sprint Change Proposal

- Project: `neweast`
- Date: `2026-02-22`
- Workflow: `Correct Course (CC)`
- Mode: `Incremental`
- Trigger Source: `Story coverage gap between PRD/UX and implemented frontend pages`

## 1. 问题摘要（Issue Summary）

### 1.1 触发问题
当前识别到的关键问题为：
- PRD 已明确平台域与组织域的用户治理、角色治理前端承载目标；
- UX 已明确“列表工作台 + Modal + Drawer + 一致反馈”的页面交互骨架；
- 现有已完成故事（`2.3/2.4/2.5/3.1/3.2/3.3`）主要聚焦 API/服务层与契约，未形成对应前端治理页面的交付闭环。

### 1.2 问题类型
- 分类：`Misunderstanding of original requirements`（需求理解偏差，非产品方向变化）

### 1.3 证据
- PRD：`_bmad-output/planning-artifacts/prd.md`
- Epics：`_bmad-output/planning-artifacts/epics.md`
- UX：`_bmad-output/planning-artifacts/ux-design-specification.md`
- 实现痕迹：`_bmad-output/implementation-artifacts/2-3...`、`2-4...`、`2-5...`、`3-1...`、`3-2...`、`3-3...`
- 前端现状：`apps/web/src/App.jsx` 仅最小登录/组织选择/权限展示，未见完整治理页面模块。

## 2. 影响分析（Impact Analysis）

### 2.1 Epic 影响
- 受影响 Epic：`Epic 2`、`Epic 3`
- 判断：需补齐前端治理页面 Story，才能满足 PRD + UX 交付预期

### 2.2 变更方式
- 采用：在现有 Epic 内补 Story（不新增 Epic）

### 2.3 其他 Epic 影响
- `Epic 1/4/5`：无结构性改动，仅受回归与验收口径联动影响

### 2.4 未来 Epic 有效性
- 不废弃既有 Epic
- 不新增 Epic

### 2.5 优先级调整
- 按用户确认：`不调整优先级`

### 2.6 工件冲突汇总
- PRD：存在能力覆盖冲突（文档要求 > 当前前端交付）
- Architecture：页面分层映射与现状不一致
- UX：治理工作台交互骨架未完整落地
- Testing/CI：需补前端页面门禁覆盖

## 3. 推荐路径（Recommended Approach）

- Selected Path: `Option 1 - Direct Adjustment`
- Rationale:
  - 问题是交付结构缺口，不是方向错误；
  - 以最小改动补齐前端治理闭环，保留既有后端成果；
  - 风险与成本低于回滚或下调 MVP 目标。

- Effort: `Medium`
- Risk: `Low-Medium`
- Timeline Impact: `Minor`

## 4. 详细变更提案（Detailed Change Proposals）

### 4.1 Proposal A（Approved）

Story: `[2.7] 平台治理前端工作台（平台用户管理 + 平台角色管理）`
Section: `epics.md -> Epic 2`

OLD:
- Epic 2 现有故事到 2.6 结束，平台用户/平台角色能力主要以 API 交付为主。

NEW:
- 新增 Story 2.7，覆盖平台用户管理、平台角色管理、权限树配置与角色分配的前端治理工作台。
- AC 明确：列表/筛选/分页；新建编辑 Modal；详情 Drawer；真实 Chrome Playwright 门禁。

Rationale:
- 补齐平台治理前端承载，闭合 FR13-FR18 在 UI 层的可验收路径。

### 4.2 Proposal B（Approved）

Story: `[3.8] 组织治理前端工作台（组织成员管理 + 组织角色管理）`
Section: `epics.md -> Epic 3`

OLD:
- Epic 3 现有故事到 3.7 结束，组织成员/角色能力主要以 API 交付为主。

NEW:
- 新增 Story 3.8，覆盖组织成员管理、组织角色管理、权限树配置与成员角色分配的前端治理工作台。
- AC 明确：Modal/Drawer 交互规范、权限并集即时生效、越权一致拒绝、真实 Chrome 门禁。

Rationale:
- 补齐组织治理前端主路径，匹配 Journey 3 与 UX 工作台策略。

### 4.3 Proposal C（Approved）

Artifact: `sprint-status.yaml`
Section: `development_status`

OLD:
- Epic 2/3 已有故事到 `2.6`、`3.7`。

NEW:
- 新增状态项：
  - `2-7-平台治理前端工作台-平台用户管理-平台角色管理: backlog`
  - `3-8-组织治理前端工作台-组织成员管理-组织角色管理: backlog`

Rationale:
- 将新增故事纳入正式迭代跟踪，不改变当前优先级策略。

### 4.4 Proposal D（Approved）

Artifact: `epics.md`
Section: `Frontend Validation Gate (applies to Story 2.7 and 3.8)`

OLD:
- 前端页面门禁未被显式定义为故事完成条件。

NEW:
- 增加前端门禁：
  - 真实 Chrome Playwright（非仿真）
  - 覆盖列表、Modal、Drawer、状态切换、权限分配与越权拒绝
  - 门禁失败不得标记 done
  - 结果需归档到 implementation artifacts

Rationale:
- 防止“API 已完成但前端未交付”的同类偏差再次出现。

## 5. 实施交接（Implementation Handoff）

### 5.1 变更范围分级
- Scope Classification: `Moderate`

### 5.2 交接对象与职责
- Product Owner / Scrum Master
  - 将 Proposal A/B/D 合并进 `epics.md`
  - 同步 `sprint-status.yaml` 的新 Story 状态（Proposal C）
- Development Team
  - 按新增 Story 2.7/3.8 实现前端治理页面
  - 落实真实 Chrome Playwright 门禁并归档证据
- QA
  - 补齐前端关键路径回归集与越权负向用例

### 5.3 成功标准
- `epics.md` 出现 Story `2.7` 与 `3.8` 及对应 AC
- `sprint-status.yaml` 出现两条新增 backlog 状态
- 前端治理关键路径在真实 Chrome 门禁通过
- 能力闭环与 PRD/UX 对齐

## 6. 执行清单快照（Checklist Snapshot）

- Section 1 Understand Trigger and Context: `[x] Done`
- Section 2 Epic Impact Assessment: `[x] Done`
- Section 3 Artifact Conflict and Impact Analysis: `[x] Done`
- Section 4 Path Forward Evaluation: `[x] Done`（Option 1）
- Section 5 Proposal Components: `[x] Done`
- Section 6 Final Review and Handoff: `[x] Done`

## 7. 审批与路由记录（Approval & Routing Record）

- User approval: `yes`
- Scope classification: `Moderate`
- Routed to:
  - Product Owner / Scrum Master（确认新增 Story 与验收边界）
  - Development Team（实现 Story 2.7/3.8 前端治理页面）
  - QA（补齐前端关键路径与越权负向门禁）
- Tracking updates:
  - `_bmad-output/planning-artifacts/epics.md` 已更新（新增 Story 2.7、3.8 与前端门禁）
  - `_bmad-output/implementation-artifacts/sprint-status.yaml` 已更新（新增 2.7、3.8 为 backlog）
