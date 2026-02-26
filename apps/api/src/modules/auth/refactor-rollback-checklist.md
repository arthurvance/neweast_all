# Auth Refactor Rollback Checklist

## Trigger

执行收口后出现不可接受回归，且需在单次提交内恢复桥接可运行状态。

## Rollback Steps

1. Restore legacy bridge files from git history
- `apps/api/src/modules / auth / auth.service.js`
- `apps/api/src/modules / auth / auth.store.memory.js`
- `apps/api/src/modules / auth / auth.store.mysql.js`
- `apps/api/src/modules / auth / store-methods / auth-store-memory-capabilities.js`
- `apps/api/src/modules / auth / store-methods / auth-store-mysql-capabilities.js`

2. Restore import paths using migration script
- `node apps/api/scripts/refactor-auth-import-paths.js --restore-bridge`

3. Re-run guard checks
- `pnpm --dir apps/api exec node scripts/refactor-auth-import-paths.js --check`
- `pnpm --dir apps/api run check:auth-refactor-guards`

4. Re-run critical auth tests
- `pnpm --dir apps/api exec node --test test/auth.service.test.js`
- `pnpm --dir apps/api exec node --test test/auth.api.test.js`
- `pnpm --dir apps/api exec node --test test/auth.store.mysql.test.js`

5. Update migration map status
- 将 `apps/api/src/modules/auth/refactor-migration-map.md` 的状态更新为 rollback 状态并附原因。
