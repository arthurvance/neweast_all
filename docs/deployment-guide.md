# Deployment Guide

## 1. 本地一键编排（推荐）

使用根目录 `docker-compose.yml`：

```bash
docker compose up -d
```

会启动 4 个服务：

- `mysql`（3306）
- `redis`（6379）
- `api`（3000）
- `web`（4173）

## 2. 环境变量

可参考 `.env.example`，关键变量：

- API: `API_HOST`, `API_PORT`, `DB_*`, `REDIS_*`, `API_CORS_ALLOWED_ORIGINS`
- Auth: `AUTH_DEFAULT_PASSWORD_ENCRYPTED`, `AUTH_SENSITIVE_CONFIG_DECRYPTION_KEY`
- Web: `WEB_HOST`, `WEB_PORT`, `API_BASE_URL`

## 3. 健康检查

- `api` health：`/health`
- `web` health：`/health`
- `web` smoke：`/smoke`（会探测 `api/health`）

## 4. CI/CD（当前）

GitHub Actions：`.github/workflows/ci.yml`

- 矩阵门禁：`lint` / `build` / `test` / `smoke`
- 额外作业：`release-gate-report`（上传 `artifacts/release-gates/*`）

## 5. 发布前检查清单

1. `pnpm nx lint`
2. `pnpm nx build`
3. `pnpm nx test`
4. `pnpm nx smoke`
5. 检查 release gate artifact 是否完整

