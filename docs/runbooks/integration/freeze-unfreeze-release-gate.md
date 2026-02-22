# Integration Freeze / Unfreeze Release Gate Runbook

## Scope

Use this runbook to operate the platform integration freeze window during high-risk release windows and to verify release gate behavior before and after unfreeze.

## Preconditions

- Operator has `platform.member_admin.operate` permission.
- Platform auth is healthy and route permission checks pass.
- Target environment has API service running with the latest schema migration applied.

## Activate Freeze Window

1. Call `POST /platform/integrations/freeze`.
2. Provide:
   - `freeze_reason` (required, max length 256)
   - `freeze_id` (optional, max length 64; auto-generated if omitted)
3. Record:
   - `freeze_id`
   - `request_id`
   - `frozen_at`

Example:

```json
{
  "freeze_id": "release-window-2026-02-22",
  "freeze_reason": "production release window opened"
}
```

## Verify Freeze Is Active

1. Call `GET /platform/integrations/freeze`.
2. Confirm:
   - `frozen = true`
   - `active_freeze.status = "active"`
   - `active_freeze.freeze_id` matches expected window.

## Verify Write Blocking Behavior

During freeze, the following write routes must return `409` with `error_code = INT-409-INTEGRATION-FREEZE-BLOCKED`:

- `POST /platform/integrations`
- `PATCH /platform/integrations/{integration_id}`
- `POST /platform/integrations/{integration_id}/lifecycle`
- `POST /platform/integrations/{integration_id}/contracts`
- `POST /platform/integrations/{integration_id}/contracts/{contract_version}/activate`

Audit expectation:

- event type `platform.integration.freeze.change_blocked` exists for blocked write requests.

## Release Freeze Window

1. Call `POST /platform/integrations/freeze/release`.
2. Optional payload:
   - `rollback_reason` (max length 256)
3. Confirm response:
   - `status = "released"`
   - `released = true`
   - `previous_status = "active"`
   - `current_status = "released"`

## Verify Release Completed

1. Call `GET /platform/integrations/freeze`.
2. Confirm:
   - `frozen = false`
   - `active_freeze = null`
   - `latest_freeze.status = "released"`.

## Release Gate Checks

Run:

```bash
pnpm --dir apps/api check:integration-release-window
pnpm --dir apps/api check:integration-contract-consistency
node tools/release-gate-report.js
```

Expected:

- `integration-release-window` group is `passed`.
- `integration-contract-consistency` group is `passed`.
- Release gate report returns `blocking=false`.

## Rollback Notes

- If freeze activation conflicts (`INT-409-INTEGRATION-FREEZE-ACTIVE`), inspect active window and avoid creating overlapping windows.
- If release conflicts (`INT-409-INTEGRATION-FREEZE-RELEASE-CONFLICT`), verify current status first; do not retry blindly.
