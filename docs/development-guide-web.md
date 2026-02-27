# Development Guide（Web）

## 1. 前置条件

- Node.js `>= 24`
- pnpm `10.x`
- API 服务可用（默认 `http://127.0.0.1:3000`）

## 2. 初始化

```bash
pnpm install
```

## 3. 本地开发

```bash
pnpm --dir apps/web run dev
```

- 默认端口：`4173`
- `/api` 会代理到 `VITE_PROXY_TARGET`（默认 `http://127.0.0.1:3000`）

## 4. 构建与运行

```bash
pnpm --dir apps/web run build
pnpm --dir apps/web run start
```

## 5. 测试与质量

```bash
pnpm --dir apps/web run lint
pnpm --dir apps/web run test
pnpm --dir apps/web run smoke
pnpm --dir apps/web run test:shared-kernel-http
```

## 6. 开发注意事项

1. API 调用优先集中在 `src/api/*`，不要在页面组件直接散落 fetch 逻辑。
2. 涉及权限的 UI 控制应与后端 permission context 保持一致。
3. 修改认证流程时需同步检查 `auth-session-storage` 与 screen path 解析逻辑。

