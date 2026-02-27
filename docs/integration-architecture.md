# Integration Architecture（api + web + infra）

## 1. 部件清单

- `web`：React SPA + Node Web Server
- `api`：业务 API 服务
- `mysql`：关系型存储
- `redis`：缓存/临时存储（OTP、限流、幂等等）

## 2. 请求流

```text
Browser
  -> Web Server (:4173)
    -> /api/* proxy
      -> API (:3000)
        -> MySQL (:3306)
        -> Redis (:6379)
```

## 3. 集成契约点

- Web -> API:
  - 主要通过 `/api/*` 代理通信
  - 前端 API SDK：
    - `src/api/platform-management.mjs`
    - `src/api/tenant-management.mjs`
- API -> Infra:
  - MySQL：业务实体与会话/权限持久化
  - Redis：OTP、限流、幂等 token 协调

## 4. 身份与上下文传播

- 前端保留会话状态并带 `Authorization`
- API 统一注入并回传 `x-request-id` 与 `traceparent`
- 平台/租户入口域由 session 上下文管理（`entry_domain`, `active_tenant_id`）

## 5. 健康链路

- `web:/health`：web 自身可用
- `web:/smoke`：web -> api -> db/redis 依赖链路可用
- `api:/health`：api + 依赖探测

