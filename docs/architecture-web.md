# Web Architecture（apps/web）

## 1. 架构定位

`apps/web` 同时包含：

- React SPA（Vite 构建）
- Node Web Server（生产托管静态资源、处理 `/api` 代理、健康与冒烟）

## 2. 前端运行链路

1. `src/main.jsx` 启动 React + Ant Design `ConfigProvider(zh_CN)`
2. `src/App.jsx` 作为应用总壳：
   - 处理登录态恢复/清理
   - 维护 `platform` 与 `tenant` 两种入口域
   - 统一消息提示与屏幕路由切换
3. 领域 UI：
   - `domains/platform/*`
   - `domains/tenant/*`
4. API 调用：
   - `src/api/platform-management.mjs`
   - `src/api/tenant-management.mjs`
   - 通过 `shared-kernel/http/request-json.mjs`

## 3. Web Server 责任

- 文件：`src/server.js`
- 能力：
  - `GET /health`
  - `GET /smoke`（探测 API `/health`）
  - `/api/*` 转发到 API 服务
  - 静态资源与 SPA fallback（`dist/apps/web/client`）

## 4. UI 组织与可复用组件

- 页面/流程：
  - `features/auth/*`（密码/OTP 登录流程）
  - `features/app-shell/*`（screen 解析）
- 通用组件：
  - `components/CustomCard.tsx`
  - `components/CustomForm.tsx`
  - `components/CustomLayout.tsx`
  - `components/CustomPage.tsx`
  - `components/CustomPanel*.tsx` 等

## 5. 构建与代理

- `vite.config.js`
  - dev server：`0.0.0.0:4173`
  - `/api` 代理至 `http://127.0.0.1:3000`
  - build 输出：`dist/apps/web/client`

## 6. 测试策略（现状）

- Node test：
  - `test/server.test.js`
  - `test/shared-kernel-http.test.mjs`
  - `test/helpers/*.test.mjs`
- Playwright smoke：
  - `test/chrome.playwright.test.js`

