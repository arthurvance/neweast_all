# Integration Retry Recovery Replay Runbook

## Purpose

Standardize platform integration failure recovery from automatic retry to manual replay with auditable evidence.

## Scope

- Platform integration delivery retry orchestration
- Recovery queue (`pending|retrying|succeeded|failed|dlq|replayed`)
- Manual replay operations for failed and DLQ items

## Preconditions

- Integration exists and is managed in platform catalog.
- Operator has:
  - `platform.member_admin.view` to query recovery queue
  - `platform.member_admin.operate` to trigger replay
- `request_id` and `traceparent` are preserved in operation chain.

## Automatic Retry Policy

- Retryable failures:
  - HTTP `408`, `429`, `5xx`
  - transient network errors in configured retryable code set
- Backoff:
  - exponential backoff + jitter
  - default max attempts: `5`
- On exhaustion:
  - item transitions to `dlq`
  - payload/response snapshots are retained for replay

## Queue Operations

1. List queue items:
   - `GET /platform/integrations/{integration_id}/recovery/queue`
   - Optional filters: `status`, `limit`
2. Review target entry:
   - validate `status`, `attempt_count`, `failure_code`, `failure_detail`
   - confirm upstream dependency has recovered

## Manual Replay

1. Trigger replay:
   - `POST /platform/integrations/{integration_id}/recovery/queue/{recovery_id}/replay`
   - Body: `{ "reason": "manual replay reason" }`
   - Use `Idempotency-Key` to avoid duplicate replay side effects.
2. Expected status transitions:
   - allowed source status: `failed` or `dlq`
   - target status: `replayed`
3. Conflict handling:
   - non-replayable source status returns `INT-409-RECOVERY-REPLAY-CONFLICT`

## Audit and Traceability

Validate events with `request_id`:

- `platform.integration.recovery.retry_scheduled`
- `platform.integration.recovery.reprocess_failed`
- `platform.integration.recovery.retry_exhausted`
- `platform.integration.recovery.reprocess_succeeded`
- `platform.integration.recovery.replayed`

Each key event must include state change evidence (`before_state`/`after_state` or equivalent).

## Failure Handling

- `INT-400-INVALID-PAYLOAD`: invalid path/query/body
- `INT-404-NOT-FOUND`: integration missing
- `INT-404-RECOVERY-NOT-FOUND`: recovery entry missing
- `INT-409-RECOVERY-REPLAY-CONFLICT`: replay state conflict
- `INT-503-DEPENDENCY-UNAVAILABLE`: fail-closed dependency/storage issue

## Rollback / Containment

1. Stop replay attempts for the impacted integration.
2. Keep item in `failed`/`dlq` and capture full dependency evidence.
3. Escalate downstream dependency remediation.
4. Re-attempt replay with a new `request_id` after dependency recovery confirmation.
