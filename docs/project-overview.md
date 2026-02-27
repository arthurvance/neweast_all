# neweast 项目概览

最后更新：2026-02-26

## 1. 项目定位

`neweast` 是一个基于 `Nx + pnpm` 的 monorepo，包含两类应用：

- `apps/api`：后端 API（Node.js + Nest 运行时 + Express 路由分发）
- `apps/web`：前端应用（React + Vite），并带有 Node Web Server 用于静态资源与 API 反向代理

该项目围绕多租户权限体系构建，核心业务域包含：

- 认证与会话（密码登录、OTP、刷新、登出、切换租户）
- 平台侧管理（组织、用户、角色、系统配置、集成配置）
- 租户侧管理（用户、角色、权限）
- 审计日志与集成恢复/冻结控制

## 2. 仓库结构结论

- 仓库类型：`monorepo`
- 部件数量：`2`
- 部件分类：
  - `api` -> `backend`
  - `web` -> `web`

## 3. 技术栈摘要

| 类别 | 技术 |
| --- | --- |
| Workspace | Nx, pnpm workspace |
| Runtime | Node.js (要求 >= 24) |
| Backend | NestJS core + Express adapter 风格路由、TypeORM、mysql2、ioredis |
| Frontend | React 19、Ant Design 6、Vite 7 |
| Database | MySQL 8.4（docker-compose） |
| Cache/Infra | Redis 7（docker-compose） |
| Testing | Node test runner (`node --test`), Supertest, Playwright（Web smoke） |
| CI | GitHub Actions（lint/build/test/smoke + release gate report） |

## 4. 规模快照（本次扫描）

- API 路由总数：`66`
  - public：`8`
  - protected：`58`
- 数据表（迁移中可识别）：`19`
- 迁移版本：`0001` 到 `0025`
- 测试文件数：
  - `apps/api/test`：`62`
  - `apps/web/test`：`6`

## 5. 推荐阅读顺序

1. [项目文档索引](./index.md)
2. [API 架构](./architecture-api.md)
3. [Web 架构](./architecture-web.md)
4. [集成架构](./integration-architecture.md)
5. [API 合同](./api-contracts-api.md)
6. [数据模型](./data-models-api.md)

