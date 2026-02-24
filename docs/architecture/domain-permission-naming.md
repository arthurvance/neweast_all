# Domain Permission Naming Baseline

## Scope

This baseline defines the naming and boundary rules after the platform/tenant refactor.
All new code should follow this document.

## Domain Terms

- Technical domain name: `tenant`
- UI label: `组织`
- Domain split:
  - `platform`: platform-side governance
  - `tenant`: tenant-side governance

## Permission Codes

### Platform

- `platform.user_management.view`
- `platform.user_management.operate`
- `platform.role_management.view`
- `platform.role_management.operate`
- `platform.tenant_management.view`
- `platform.tenant_management.operate`

### Tenant

- `tenant.user_management.view`
- `tenant.user_management.operate`
- `tenant.role_management.view`
- `tenant.role_management.operate`
- `tenant.context.read`
- `tenant.context.switch`

## Frontend Naming

- API client modules:
  - `apps/web/src/api/platform-management.mjs`
  - `apps/web/src/api/tenant-management.mjs`
- Test IDs:
  - use `platform-management-*`
  - use `tenant-management-*`
- Avoid historical names in runtime code:
  - `platform-settings`
  - `tenant-governance`
  - `billing`
  - `member-admin`

## Smoke Script Baseline

- `tools/smoke.js` must bootstrap the platform operator through:
  - `apps/api/scripts/bootstrap-first-platform-admin.js`
- Probe endpoint for platform entry verification:
  - `GET /auth/platform/user-management/probe`
