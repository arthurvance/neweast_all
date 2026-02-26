# Auth Refactor Migration Map

## Status Legend

- `migrated`: 新路径已生效，旧路径已清理
- `pending`: 迁移尚未完成
- `deleted`: 旧文件已删除

## File Mapping

| Old Path | New Path | Status |
| --- | --- | --- |
| `apps/api/src/modules / auth / auth.service.js` | `apps/api/src/shared-kernel/auth/create-auth-service.js` | migrated |
| `apps/api/src/modules / auth / auth.store.memory.js` | `apps/api/src/shared-kernel/auth/store/create-in-memory-auth-store.js` | migrated |
| `apps/api/src/modules / auth / auth.store.mysql.js` | `apps/api/src/shared-kernel/auth/store/create-mysql-auth-store.js` | migrated |
| `apps/api/src/modules / auth / store-methods / auth-store-memory-capabilities.js` | `apps/api/src/shared-kernel/auth/store/methods/memory-method-map.js` | migrated |
| `apps/api/src/modules / auth / store-methods / auth-store-mysql-capabilities.js` | `apps/api/src/shared-kernel/auth/store/methods/mysql-method-map.js` | migrated |

## Capability Surface Mapping

| Capability Family | Service Entry | Store Entry (Memory) | Store Entry (MySQL) |
| --- | --- | --- | --- |
| `platform/auth/session` | `apps/api/src/domains/platform/auth/session/session.service.js` | `apps/api/src/domains/platform/auth/session/session.store.memory.js` | `apps/api/src/domains/platform/auth/session/session.store.mysql.js` |
| `platform/auth/context` | `apps/api/src/domains/platform/auth/context/context.service.js` | `apps/api/src/domains/platform/auth/context/context.store.memory.js` | `apps/api/src/domains/platform/auth/context/context.store.mysql.js` |
| `platform/auth/provisioning` | `apps/api/src/domains/platform/auth/provisioning/provisioning.service.js` | `apps/api/src/domains/platform/auth/provisioning/provisioning.store.memory.js` | `apps/api/src/domains/platform/auth/provisioning/provisioning.store.mysql.js` |
| `platform/auth/governance` | `apps/api/src/domains/platform/auth/governance/governance.service.js` | `apps/api/src/domains/platform/auth/governance/governance.store.memory.js` | `apps/api/src/domains/platform/auth/governance/governance.store.mysql.js` |
| `platform/auth/system-config` | `apps/api/src/domains/platform/auth/system-config/system-config.service.js` | `apps/api/src/domains/platform/auth/system-config/system-config.store.memory.js` | `apps/api/src/domains/platform/auth/system-config/system-config.store.mysql.js` |
| `platform/auth/integration` | `apps/api/src/domains/platform/auth/integration/integration.service.js` | `apps/api/src/domains/platform/auth/integration/integration.store.memory.js` | `apps/api/src/domains/platform/auth/integration/integration.store.mysql.js` |
| `tenant/auth/session` | `apps/api/src/domains/tenant/auth/session/session.service.js` | `apps/api/src/domains/tenant/auth/session/session.store.memory.js` | `apps/api/src/domains/tenant/auth/session/session.store.mysql.js` |
| `tenant/auth/context` | `apps/api/src/domains/tenant/auth/context/context.service.js` | `apps/api/src/domains/tenant/auth/context/context.store.memory.js` | `apps/api/src/domains/tenant/auth/context/context.store.mysql.js` |
| `tenant/auth/provisioning` | `apps/api/src/domains/tenant/auth/provisioning/provisioning.service.js` | `apps/api/src/domains/tenant/auth/provisioning/provisioning.store.memory.js` | `apps/api/src/domains/tenant/auth/provisioning/provisioning.store.mysql.js` |
| `tenant/auth/governance` | `apps/api/src/domains/tenant/auth/governance/governance.service.js` | `apps/api/src/domains/tenant/auth/governance/governance.store.memory.js` | `apps/api/src/domains/tenant/auth/governance/governance.store.mysql.js` |

## Closure Checklist

- [x] Core old->new path map created
- [x] Import rewrite script available
- [x] Legacy path scan integrated into guard scripts
- [x] Old aggregate file deletion completed
