# API Architecture（apps/api）

## 1. 架构定位

`apps/api` 是权限强约束的业务 API 服务，核心特点：

- 通过 route manifest 声明路由与权限关系
- 统一问题详情（problem details）响应
- 会话、幂等、限流、权限上下文都在服务层集中处理
- MySQL 持久化 + Redis 辅助（OTP、限流、幂等等）

## 2. 请求主链路

1. `main.js` 读取环境变量并启动应用
2. `app.js` 的 `createApiApp` 组装运行时依赖：
   - MySQL 连接与 schema preflight
   - Redis 连接（非 mock）
   - auth service / auth store / otp store / rate-limit store
3. 注册 route definitions（来自 route manifests）
4. 请求进入后统一注入 `request_id`/`traceparent`
5. `dispatchApiRoute` 完成：
   - 路由匹配
   - protected 路由鉴权
   - handler 调用
   - 标准化响应与错误

## 3. 模块划分

- `domains/platform/*`：平台侧组织/用户/角色/集成配置
- `domains/tenant/*`：租户侧用户/角色/权限
- `modules/auth/*`：登录、OTP、session、权限目录与相关仓储
- `modules/audit/*`：审计能力
- `modules/integration/*`：契约/重试/冻结等流程能力
- `shared-kernel/auth/*`：认证共享能力与 store 抽象（memory/mysql）

## 4. 路由与权限模型

- 路由来源：`src/route-manifests/*.route-manifest.js`
- 清单规模：66 routes
  - public: 8
  - protected: 58
- scope 维度：`public` / `session` / `tenant` / `platform`
- 受保护路由通过 `permission_code + scope` 执行预授权

## 5. 数据与基础设施

- ORM/迁移：
  - TypeORM config：`apps/api/typeorm.config.js`
  - 迁移目录：`apps/api/migrations/*.sql`
- 基础设施：
  - MySQL（业务主存储）
  - Redis（OTP、限流、幂等支持）

## 6. 可观测性与契约

- 健康检查：`GET /health`
- 冒烟检查：`GET /smoke`
- OpenAPI：`GET /openapi.json`（由 `src/openapi.js` 生成）
- 错误格式：`application/problem+json`

## 7. 测试策略（现状）

- API/服务测试：`apps/api/test/**/*.test.js`
- 契约测试：`apps/api/test/contracts/*`
- 不变量测试：`apps/api/test/invariants/*`
- 领域约束脚本：domain contract / route permissions / integration freeze gate

