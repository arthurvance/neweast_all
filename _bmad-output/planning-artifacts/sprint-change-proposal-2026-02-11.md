# Sprint Change Proposal

- Project: `neweast`
- Date: `2026-02-11`
- Source Trigger: `implementation-readiness-report-2026-02-11.md`
- Workflow: `Correct Course (CC)`
- Mode: `Incremental`
- Scope Included: `6 issues (2 Major + 2 Minor + 2 Warning)`

## 1. Issue Summary

IR assessment result is `NEEDS WORK`. The change is triggered by structural delivery risks and cross-artifact alignment gaps, not by product direction changes.

Primary triggers:
- Story coupling risk: `Story 4.6` combines release gate and user soft-delete session revocation.
- Cross-epic boundary risk: `Story 2.6` (owner-transfer entry) depends on closure capabilities in Epic 3 without explicit contract.

Supporting triggers:
- `Story 1.1` needs executable thin-slice acceptance proof.
- `Story 1.10` is too broad for stable single-pass validation.
- UX Journey 6 lacks executable MVP operating mode.
- Architecture lacks explicit `NFR33` timezone enforcement details.

## 2. Impact Analysis

### 2.1 Epic Impact

- Epic 4: Needs story split to restore independent delivery and test focus.
- Epic 2 + Epic 3: Need explicit boundary contract to remove hidden forward dependency risk.
- Epic 1: Needs acceptance decomposition and thin-slice quality safeguards.
- Epic 5: No structural changes required.

### 2.2 Story/Artifact Impact

Affected artifacts:
- `_bmad-output/planning-artifacts/epics.md`
- `_bmad-output/planning-artifacts/ux-design-specification.md`
- `_bmad-output/planning-artifacts/architecture.md`
- `_bmad-output/implementation-artifacts/sprint-status.yaml` (currently missing; must be created/updated after approval)

Technical impact:
- Better isolation of release-governance vs account-lifecycle behaviors.
- Explicit owner-transfer API/error/audit contract across Epic 2 and Epic 3.
- Enforceable timezone conversion and test gates for `NFR33`.
- Clear MVP ops governance execution path without product frontend pages.

## 3. Recommended Approach

Selected path: `Option 1 - Direct Adjustment`

Rationale:
- Problem is implementation-structure and alignment quality, not MVP strategy mismatch.
- Fixes are precise, document-scoped, and low-risk relative to rollback/replan.
- Preserves FR/NFR baseline and current epic architecture.

Estimate:
- Effort: `Medium`
- Risk: `Low-Medium`
- Timeline impact: `Minor` (mainly planning/backlog realignment)

## 4. Detailed Change Proposals

### 4.1 Stories (`epics.md`)

#### Change A (Approved): Split Story 4.6

Story: `4.6`
Section: Story definition + AC

OLD:
- `Story 4.6: 发布前回归门禁与用户软删除会话撤销`
- FRs: `FR48, FR78`
- Mixed AC across two capability domains.

NEW:
- `Story 4.6: 发布前回归门禁分组报告` (FR48)
- `Story 4.7: 用户软删除会话撤销` (FR78)
- Separate AC and DoD/test scope for each story.

Rationale: remove cross-domain coupling and reduce regression blast radius.

#### Change B (Approved): Story 2.6 boundary contract

Story: `2.6`
Section: Acceptance Criteria

OLD:
- Entry and controlled flow are defined, but handoff contract to Epic 3 is implicit.

NEW:
- Define minimum closure boundary: Story 2.6 delivers platform-side initiation and validation only.
- Add explicit cross-epic contract fields:
  - `request_id`, `org_id`, `old_owner_user_id`, `new_owner_user_id`, `result_status`, `error_code`, `retryable`
- Add required audit event minimum set:
  - initiation, validation-failed, conflict, committed
- Explicitly prohibit Story 2.6 from implementing Epic 3 closure capabilities.

Rationale: remove hidden forward dependency and prevent pseudo-completion.

#### Change C (Approved): Story 1.1 thin-slice acceptance

Story: `1.1`
Section: Acceptance Criteria

OLD:
- Infra initialization validated, but no executable business thin-slice proof.

NEW:
- Add end-to-end thin-slice smoke AC (`web -> api -> db/redis`) with archived evidence.
- Add CI baseline AC requiring `lint/build/test/smoke` and merge blocking on failure.

Rationale: ensure foundation story proves runnable value, not only setup completion.

#### Change D (Approved): Story 1.10 layered acceptance

Story: `1.10`
Section: Acceptance Criteria

OLD:
- Broad AC scope without layered completion criteria.

NEW:
- Keep story number unchanged; add layered AC groups:
  - Layer A: Problem Details + error code contract (`FR9`, `FR80`)
  - Layer B: rate-limit feedback mapping (`FR62`, `FR63`)
  - Layer C: idempotent repeated-write semantics (`FR52`, `FR69`)
- Story completion requires all layers green; each layer testable independently.

Rationale: reduce delivery risk while preserving planning stability.

### 4.2 UX (`ux-design-specification.md`)

#### Change E (Approved, revised): Journey 6 MVP as non-frontend operating mode

Section: Journey 6 execution definition

OLD:
- Journey 6 has principle-level statements, but no executable MVP operation model.

NEW:
- Add explicit scope statement: `MVP 不提供运维前端页面`.
- Define executable non-UI flow:
  - alert trigger -> trace/search (`request_id`/`traceparent`) -> gate result verification -> recovery action (retry/rollback/escalate) -> archived closure
- Define minimum observable contract fields for operations:
  - `request_id`, `traceparent`, `error_code`, `retryable`, `runbook_link`, `affected_scope`, `affected_org_id`

Rationale: closes Journey 6 execution gap without adding frontend scope.

### 4.3 Architecture (`architecture.md`)

#### Change F (Approved): NFR33 timezone enforcement

Section: time semantics and release gates

OLD:
- `dayjs` and generic constraints exist; no explicit UTC->`Asia/Shanghai` enforcement spec.

NEW:
- Add explicit rules:
  - DB/API time remains UTC.
  - Frontend display must convert to `Asia/Shanghai`.
  - Use centralized conversion utility (no scattered local conversion logic).
- Add validation gates:
  - unit tests for conversion edge cases
  - E2E verification against UTC source values on key pages
  - release gate item for `NFR33`

Rationale: transform requirement into implementable and testable architecture constraint.

## 5. Implementation Handoff

Scope classification: `Moderate`

Routing:
- Primary: `Product Owner / Scrum Master`
- Secondary: `Architect + UX Designer` (artifact updates)
- Then: `Development Team` (post-document alignment implementation)

Responsibilities:
- PO/SM:
  - re-sequence stories (`4.6/4.7`, `2.6` boundary contract)
  - update sprint plan and backlog acceptance
- Architect:
  - apply timezone enforcement and ops boundary clauses in architecture
- UX:
  - apply Journey 6 non-UI operating mode updates
- Dev Team:
  - implement against revised story boundaries and updated gates

Success criteria:
- `epics.md` reflects approved structure and AC updates.
- `ux-design-specification.md` reflects Journey 6 non-UI MVP mode.
- `architecture.md` includes enforceable `NFR33` implementation + test gates.
- sprint tracking includes explicit change log and new story references.

## 6. Checklist Status Snapshot

- Section 1 Understand Trigger/Context: `[x] Done`
- Section 2 Epic Impact Assessment: `[x] Done` (with action on sequencing constraint)
- Section 3 Artifact Conflict Analysis: `[x] Done`
- Section 4 Path Forward Evaluation: `[x] Done` (Option 1 selected)
- Section 5 Proposal Components: `[x] Done`
- Section 6 Final Review/Handoff: `[x] Done`

## 7. Approval & Handoff Record

- User approval: `yes`
- Scope classification: `Moderate`
- Routed to:
  - Product Owner / Scrum Master (backlog reorganization and sprint sequencing)
  - Architect + UX Designer (artifact alignment updates)
  - Development Team (implementation after artifact updates)
- Tracking updates:
  - `_bmad-output/implementation-artifacts/sprint-status.yaml` created/updated
  - `_bmad-output/implementation-artifacts/workflow-execution-log.md` updated
