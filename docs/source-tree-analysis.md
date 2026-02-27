# Source Tree Analysis

## 1. 根目录（摘要）

```text
neweast/
├── apps/
│   ├── api/                 # 后端服务
│   └── web/                 # 前端与 web server
├── docs/                    # 项目文档（本次扫描产物）
├── tools/                   # workspace 脚本、lint/build/release gate 等
├── _bmad/                   # BMAD 工作流与技能配置
├── _bmad-output/            # BMAD 输出目录
├── artifacts/               # 测试与发布工件
├── docker-compose.yml       # 本地编排：mysql/redis/api/web
├── package.json             # workspace scripts
├── nx.json                  # Nx 项目与 target 依赖
└── pnpm-workspace.yaml
```

## 2. API 目录（关键）

```text
apps/api/
├── src/
│   ├── main.js              # API 入口
│   ├── app.js               # createApiApp，组装 auth/redis/mysql/route dispatch
│   ├── server.js            # HTTP 分发与路由执行核心
│   ├── http-routes.js       # handlers 汇总
│   ├── route-manifests/     # iam/platform/tenant 路由清单
│   ├── domains/             # platform / tenant 业务域
│   ├── modules/             # auth / audit / integration 模块
│   ├── shared-kernel/auth/  # 认证共享内核能力
│   ├── infrastructure/      # mysql/redis 连接
│   └── config/              # env 读取
├── migrations/              # SQL 迁移 0001~0025
├── test/                    # API/契约/不变量测试
└── scripts/                 # migration 与检查脚本
```

## 3. Web 目录（关键）

```text
apps/web/
├── src/
│   ├── main.jsx             # React 入口
│   ├── App.jsx              # 应用主壳，管理登录/平台/租户域切换
│   ├── server.js            # Web server（/api 代理、静态资源、健康检查）
│   ├── features/auth/       # 登录页与会话持久化
│   ├── domains/platform/    # 平台域 UI
│   ├── domains/tenant/      # 租户域 UI
│   ├── api/                 # 平台/租户 API 调用封装
│   ├── shared-kernel/http/  # request-json 与幂等键工具
│   └── components/          # 通用 UI 组件
├── test/                    # server/playwright/工具测试
├── vite.config.js           # dev 代理与构建输出配置
└── server.js                # 生产启动入口
```

## 4. 关键入口点

- API:
  - `apps/api/src/main.js`
  - `apps/api/src/app.js`
- Web:
  - `apps/web/src/main.jsx`
  - `apps/web/server.js`
- Workspace:
  - 根 `package.json` scripts（`lint`/`build`/`test`/`smoke`）
  - `nx.json` target 依赖链

## 5. 集成路径

- 浏览器 -> `apps/web`（4173）
- Web server `/api/*` -> 转发至 `apps/api`（3000）
- API -> MySQL（3306） + Redis（6379）

