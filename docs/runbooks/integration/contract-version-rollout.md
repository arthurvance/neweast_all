# Integration Contract Version Rollout Runbook

## Purpose

Standardize contract version rollout for platform integrations with fail-closed safeguards.

## Scope

- Platform integration contract governance APIs
- OpenAPI/Event contract versions
- Compatibility checks and activation gating

## Preconditions

- Integration exists in platform catalog.
- Integration lifecycle is `active` for production invocation.
- Operator has `platform.member_admin.operate`.

## Rollout Steps

1. Create a candidate contract version.
2. If there is an active baseline version, run compatibility check:
   - Input: `baseline_version`, `candidate_version`, `diff_summary`/`breaking_change_count`
   - Output: `compatible` or `incompatible`
3. Activate the candidate contract version:
   - Activation is blocked when compatibility check is missing (for baseline/candidate pair).
   - Activation is blocked when latest compatibility check result is `incompatible`.
4. Verify activation result and audit events:
   - `platform.integration.contract.created`
   - `platform.integration.contract.compatibility_evaluated`
   - `platform.integration.contract.activated`

## API Sequence (Example)

1. `POST /platform/integrations/{integration_id}/contracts`
2. `POST /platform/integrations/{integration_id}/contracts/compatibility-check`
3. `POST /platform/integrations/{integration_id}/contracts/{contract_version}/activate`
4. `GET /platform/integrations/{integration_id}/contracts`

## Failure Handling

- `integration_contract_not_found`: baseline/candidate/target version missing.
- `integration_contract_incompatible`: compatibility result is incompatible.
- `integration_contract_activation_blocked`: missing compatibility check or retired target version.
- `INT-503-DEPENDENCY-UNAVAILABLE`: fail-closed dependency/storage issue.

## Rollback

1. Identify previous active contract version from list API.
2. Run activation for previous version.
3. Confirm audit trail and request correlation using `request_id` (and `traceparent` if provided).
