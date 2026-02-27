# Development Guide（API）

## 1. 前置条件

- Node.js `>= 24`
- pnpm `10.x`
- MySQL 8（建议使用仓库内 docker-compose）
- Redis 7（建议使用仓库内 docker-compose）

## 2. 初始化

```bash
pnpm install
docker compose up -d mysql redis
pnpm migrate
```

## 3. 常用命令

### 3.1 启动 API

```bash
pnpm --dir apps/api run start
```

### 3.2 质量门禁

```bash
pnpm --dir apps/api run lint
pnpm --dir apps/api run test
pnpm --dir apps/api run check:route-permissions
pnpm --dir apps/api run check:auth-refactor-guards
```

### 3.3 工作区级别

```bash
pnpm nx lint
pnpm nx build
pnpm nx test
pnpm nx smoke
```

## 4. 本地验证

- 健康检查：`GET http://localhost:3000/health`
- 冒烟检查：`GET http://localhost:3000/smoke`
- OpenAPI：`GET http://localhost:3000/openapi.json`

## 5. 迁移相关

```bash
pnpm --dir apps/api run migrate
pnpm --dir apps/api run migrate:down
```

## 6. 开发注意事项

1. 新增路由必须同步 route manifest 与权限声明。
2. 认证、会话、权限相关改动优先补 contracts/invariants 测试。
3. 任何跨域（platform/tenant）行为需明确 scope 与 permission_code。

