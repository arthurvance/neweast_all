# Project Documentation Index

最后更新：2026-02-26

## 项目概况

- 名称：`neweast`
- 类型：`monorepo`（2 parts）
- 主语言：JavaScript / TypeScript
- 架构：`web + backend` 双部件，Web 通过 `/api` 代理访问 API

## 快速参考

### api（backend）

- 根目录：`apps/api`
- 入口：`src/main.js`, `src/app.js`
- 数据存储：MySQL + Redis

### web（web）

- 根目录：`apps/web`
- 入口：`src/main.jsx`, `server.js`
- UI 栈：React + Ant Design + Vite

## 生成文档

- [项目概览](./project-overview.md)
- [Source Tree Analysis](./source-tree-analysis.md)
- [API 架构](./architecture-api.md)
- [Web 架构](./architecture-web.md)
- [集成架构](./integration-architecture.md)
- [API 合同（API）](./api-contracts-api.md)
- [数据模型（API）](./data-models-api.md)
- [组件清单（Web）](./component-inventory-web.md)
- [API 开发指南](./development-guide-api.md)
- [Web 开发指南](./development-guide-web.md)
- [部署指南](./deployment-guide.md)
- [项目部件元数据](./project-parts.json)
- [扫描状态](./project-scan-report.json)

## 现有项目内文档（扫描到）

- [Auth Refactor Migration Map](../apps/api/src/modules/auth/refactor-migration-map.md)
- [Auth Refactor Rollback Checklist](../apps/api/src/modules/auth/refactor-rollback-checklist.md)

## 使用建议

1. 先看 `project-overview.md`，再按 `api/web` 架构文档进入对应子系统。
2. 改接口前先看 `api-contracts-api.md` 与 `data-models-api.md`。
3. 做跨端功能时同时参考 `integration-architecture.md`。

