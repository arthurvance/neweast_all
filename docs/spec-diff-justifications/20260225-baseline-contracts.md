# Spec Diff Justification

## Summary
- Spec: `platform-tenant-domain-structure-refactor`
- Change ID: `20260225-baseline-contracts`
- Owner: `platform-tenant-refactor`
- Review Date: `2026-02-25`

## Difference Type
- Category: `contract`
- Scope: `api`
- Related Tasks/AC: `Task 15, Task 18, AC 20, AC 23`

## What Changed
- Previous behavior/contract:
  - Contract snapshot and golden baseline files were missing from approved diff coverage.
- Current behavior/contract:
  - Added explicit approved diff entry and justification for current API contract snapshot and golden baseline artifacts.
- Affected files/paths:
  - `apps/api/test/contracts/platform.route-manifest.snapshot.json`
  - `apps/api/test/contracts/tenant.route-manifest.snapshot.json`
  - `apps/api/test/fixtures/golden-data-side.json`
  - `apps/api/test/fixtures/golden-user-side.json`

## Why It Is Acceptable
- Business/technical rationale:
  - These baseline artifacts are the designated governance source for contract/data-side consistency and must be explicitly reviewable.
- Risk assessment:
  - Risk is controlled by requiring explicit review and mapping in `spec-diff-register.json`.
- Rejected alternatives:
  - Silent baseline updates without change register coverage were rejected.

## Guardrails
- Added/updated tests:
  - Governance guard now blocks governed snapshot/baseline changes without accepted diff coverage.
- Added/updated lint/check gates:
  - `check-refactor-governance` now enforces `affected_files` coverage for accepted diff entries.
- Rollback plan:
  - Revert diff register entry and baseline files together if approval is revoked.

## Approval
- Responsible engineer: `platform-tenant-refactor`
- Reviewer: `architecture-reviewer`
- Product/owner confirmation (if required): `not required for structure-only baseline governance update`
- Final decision: `accepted`
