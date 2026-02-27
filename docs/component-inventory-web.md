# Component Inventory（apps/web）

## 1. 结构视图

Web 端组件分为 4 层：

- `features/*`：流程级页面与交互逻辑
- `domains/*`：业务域容器（platform/tenant）
- `components/*`：可复用通用 UI 组件
- `shared-kernel/*`：HTTP/幂等等底层能力

## 2. 流程与容器组件

### 2.1 应用壳层

- `App.jsx`
  - 会话恢复与持久化
  - screen 路由状态切换
  - PlatformApp / TenantApp 容器挂载

### 2.2 认证流程

- `features/auth/AuthApp.jsx`
- `features/auth/PlatformLoginPage.jsx`
- `features/auth/TenantLoginPage.jsx`
- `features/auth/session-model.js`
- `features/auth/auth-session-storage.js`

### 2.3 业务域容器

- `domains/platform/PlatformApp.jsx`
- `domains/tenant/TenantApp.jsx`

## 3. 通用 UI 组件（`src/components`）

- `CustomCard.tsx`
- `CustomCardTable.tsx`
- `CustomFilter.tsx`
- `CustomForm.tsx`
- `CustomLayout.tsx`
- `CustomPage.tsx`
- `CustomPanel.tsx`
- `CustomPanelTable.tsx`

这些组件主要承担布局、表单、筛选、面板化展示等复用职责。

## 4. API 调用封装（UI 依赖）

- `api/platform-management.mjs`
- `api/tenant-management.mjs`

这两类 SDK 与组件层解耦，减少页面直接拼装请求细节。

## 5. 状态与会话相关辅助

- `features/app-shell/app-screen.js`：屏幕解析与路径映射
- `features/auth/generated-permission-catalog.js`：权限目录
- `shared-kernel/http/request-json.mjs`：统一请求与错误处理
- `shared-kernel/http/idempotency-key.mjs`：幂等键生成

