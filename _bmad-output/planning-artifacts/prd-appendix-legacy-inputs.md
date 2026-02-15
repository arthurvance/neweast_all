# Consolidated Legacy Inputs (For Cleanup)

### Executive Summary

- 项目定位：企业内部 SaaS 的认证与双域 RBAC 权限底座（SCRM 基础架构阶段）。
- 目标用户：平台管理员、组织负责人/组织管理员、组织成员。
- 核心差异化：平台治理与组织治理双主线并行，权限边界强隔离、会话强一致、可审计可追踪。
- 当前阶段：0-1 构建，优先确保治理闭环可用与至少 1 条真实外部集成链路可落地。

### Scope Baseline (Consolidated)

- 本期覆盖：认证与会话、平台域治理、组织域治理、负责人变更、权限树、审计链路、集成治理基线。
- 本期不做：业务流程模块、组织树层级、自注册与邀请注册、套餐计费分层。
- 项目上下文：greenfield + AI-first 交付，保留人工双签核治理责任。

### API Contract Baseline

- 认证接口：
  - `POST /auth/login/password`
  - `POST /auth/sms/send-code`
  - `POST /auth/login/sms`
  - `POST /auth/refresh`
  - `POST /auth/logout`
  - `POST /auth/change-password`
- 平台域接口能力：组织管理、平台用户管理、平台角色管理、负责人变更。
- 组织域接口能力：成员管理、角色管理、权限分配、组织成员资料维护。
- 组织上下文要求：
  - 客户端可传递 `X-Tenant-Id` 作为上下文信号。
  - 服务端必须基于有效成员关系与组织状态做最终组织域访问判定。
  - 服务端以 `effective_tenant_id` 作为最终可信租户上下文，禁止采信请求体中的租户标识。
- 关键写接口契约要求：
  - 关键写接口声明 `Idempotency-Key` 请求头。
  - 重复请求返回固定幂等语义与标准冲突错误码。
- 认证契约要求：
  - `refresh` 接口定义原子轮换语义与重放错误码。
- 错误契约要求：
  - 错误码必须提供 `retryable` 标记并在 OpenAPI 中给出示例。

### Data Model Baseline

- 核心实体：
  - `users`, `orgs`, `memberships`, `roles`, `permissions`
  - `role_permissions`, `membership_roles`, `user_roles`
  - `refresh_tokens`, `sms_codes`, `sys_configs`, `audit_logs`
- 核心约束：
  - `users.phone` 全局唯一。
  - `memberships(tenant_id,user_id)` 活跃数据唯一。
  - `roles(scope,tenant_id,code)` 活跃数据唯一。
  - `permissions(scope,code)` 活跃数据唯一。
  - `role_permissions(role_id,permission_id)` 活跃数据唯一。
  - `membership_roles(membership_id,role_id)` 活跃数据唯一。
  - `user_roles(user_id,role_id)` 活跃数据唯一。
- 数据治理：
  - 业务实体统一软删除（`deleted_at`）。
  - 关系实体 `role_permissions`、`membership_roles`、`user_roles` 采用软删除并参与活跃唯一性约束。
  - 默认查询不返回已软删除数据。
  - 组织成员重入组创建新关系，不复用历史关系。
  - 关键状态变更触发会话版本收敛。
  - 组织软删除级联软删除成员、组织角色与角色绑定。
  - 用户软删除立即撤销全部 refresh token。
  - 删除状态语义不新增独立字段，统一由 `status` + `deleted_at` 判定：
    - `ACTIVE`: `deleted_at IS NULL` 且 `status='ENABLED'`（适用于有状态业务实体）
    - `DISABLED`: `deleted_at IS NULL` 且 `status='DISABLED'`
    - `SOFT_DELETED`: `deleted_at IS NOT NULL`（此时必须视为不可用，不参与任何权限计算）
  - 本期删除生命周期：`DISABLE -> SOFT_DELETE`；不提供自动/手动硬删除入口，不提供恢复入口（后续迭代）。
  - 约束一致性要求：对存在 `status` 的业务实体，`deleted_at IS NOT NULL` 时 `status` 必须为 `DISABLED`（数据库约束或触发器保证）。

### Default Password Provisioning Rules (Detailed)

- 新用户创建规则：
  - 当手机号不存在时，系统创建用户并应用默认密码策略初始化账号。
  - 默认密码来源于系统配置项（如 `auth.default_password`）。
  - 账号落库仅保存 `password_hash`，不保存明文密码。
- 既有用户复用规则：
  - 当手机号已存在时，仅建立成员关系与角色绑定。
  - 入组或授权流程不得修改该用户现有密码。
- 首次登录规则：
  - MVP 阶段不强制首登改密。
  - 首登策略固定为不强制改密，不提供管理员配置入口。
- 配置安全规则：
  - 默认密码配置值按敏感配置处理，采用密文存储。
  - 解密依赖环境密钥，不允许在代码仓库中保存明文密钥。

### Rate Limiting Rules (Detailed)

- 限流范围：
  - 账号密码登录接口。
  - 手机验证码登录接口。
  - 验证码发送接口。
- 限流维度：
  - 仅按手机号维度计数，不使用 IP 维度限流。
- 限流窗口与阈值：
  - 同一手机号在任一上述接口上 1 分钟最多 10 次请求（按接口类型独立计数）。
- 超限行为：
  - 直接拒绝当前请求，不设置冷却时间。
- 错误反馈与审计：
  - 对外返回统一失败语义。
  - 服务端记录失败类别与时间用于审计和排障。

### Authentication & Session Rules (Detailed)

- 登录方式：
  - 手机号密码登录。
  - 手机号验证码登录（MVP 使用 Mock 短信）。
- Token 策略：
  - Access Token + Refresh Token 双令牌策略。
  - Access Token 有效期 30 分钟。
  - Refresh Token 有效期 14 天。
  - `logout` 仅撤销当前会话，不提供 `logout-all`。
  - `refresh` 采用原子轮换并识别重放请求。
- 会话并发：
  - 允许同一用户无限并发会话。
- 会话强一致策略：
  - `session_version` 用于会话一致性校验。
  - 改密、`users.status` 变更、`memberships.status` 变更、`orgs.status` 变更、角色授权变更后递增 `session_version`。
  - 鉴权时版本不一致返回 `401`。
- 验证码策略：
  - 验证码有效期 15 分钟。
  - 验证码倒计时按服务端剩余时间延续（页面刷新后保持一致）。
- 密码策略：
  - 仅限制长度 >= 6。
  - 仅限制长度 `>= 6`。
  - 密码长度最小为 6。
  - MVP 不强制复杂度、不限制历史密码复用、不要求新旧密码不同。
- 账户保护策略：
  - MVP 不启用失败锁定与二级加固策略。
- 认证失败反馈策略：
  - 验证码错误/过期/已使用对外统一文案。
  - 服务端日志记录具体失败原因并用于审计。

### Tenant Entry & Access Model (Detailed)

- 平台入口与组织入口可并行存在，后端为同一套系统。
- 平台入口仅允许进入平台域；组织入口仅允许进入组织域。
- 对无有效域权限访问返回统一“暂无登录权限”语义。
- 组织域服务端判定始终以 `effective_tenant_id` 为准。
- 组织入口登录后先获取组织列表：单组织直接进入该组织，多组织进入组织选择页。
- 会话内点击“切换组织”时统一进入组织选择页（即使仅有一个组织）。

### Organization Creation & Owner Transfer Rules (Detailed)

- 创建组织规则：
  - 创建组织必须包含初始管理员手机号。
  - 不允许创建空管理员组织。
- 负责人变更规则：
  - 负责人变更按 `org_id` 串行化处理。
  - 若新负责人未加入组织，系统自动加入组织。
  - 若新负责人手机号不存在用户，流程内自动创建用户并应用默认密码策略。
  - 自动授予新负责人组织域 `sys_admin`。
  - `owner_user_id` 变更、自动入组、授权 `sys_admin` 在单事务内全成功/全回滚。
  - 新负责人为 `DISABLED` 成员或组织为 `DISABLED` 时，禁止变更。
  - 旧负责人角色不自动移除，由人工治理处理。

### Bootstrap & Recovery Rules (Detailed)

- 首个平台管理员通过一次性初始化命令创建（示例：`seed:platform-admin`）。
- 初始化命令需具备幂等性：重复执行不重复创建。
- 平台域不强制“至少保留 1 名 `sys_admin`”。
- 若发生权限锁死，可通过初始化命令或数据库兜底恢复。

### Time Semantics Rules (Detailed)

- 数据库存储时间统一使用 UTC。
- API 响应时间统一返回 UTC。
- 前端展示统一转换为 `Asia/Shanghai`。

### Permission Registry & Enforcement Rules (Detailed)

- 权限清单来源：
  - `permissions` 由后端单一清单定义（Single Source of Truth）。
  - 应用启动时幂等同步入库。
- 权限编码：
  - `permission.code` 统一采用 `scope.resource.action` 规范。
- 接口映射：
  - 每个受保护接口必须显式声明 `permission.code`。
  - 后端按 `permission.code` 强鉴权，前端仅做展示裁剪。
- 防漏机制：
  - 受保护接口未声明权限时默认拒绝访问。
  - 启动自检与 CI 检查拦截漏声明接口。
- 角色禁用策略：
  - `roles.status=DISABLED` 立即失效，不参与权限计算。
  - 历史绑定不自动解绑，仅保留为历史记录。
  - 禁用状态角色不可被选中分配。
- `sys_admin` 分配边界：
  - 具备用户创建/编辑权限者可分配所有角色（含 `sys_admin`）。
- 权限树落库：
  - 仅保存最终勾选叶子权限点。
  - 父节点仅用于 UI 全选/半选展示。

### Observability & Recovery Minimum Baseline (Detailed)

- 观测指标：
  - 鉴权失败率。
  - 越权拒绝率。
  - 负责人变更失败率。
- 审计追踪：
  - 关键写接口全链路注入 `request_id`。
  - 审计明细记录关键操作 `before/after`。
- 灾备最小基线：
  - 定义备份频率与恢复流程。
  - 上线前至少完成一次恢复演练并留档。

### Database Entity Field Catalog (Detailed)

#### `users`

| 字段 | 类型 | 必填 | 说明 |
|---|---|---|---|
| `id` | `BIGINT UNSIGNED` | 是 | 用户主键（自增） |
| `phone` | `VARCHAR(20)` | 是 | 手机号，全局唯一 |
| `name` | `VARCHAR(64)` | 是 | 用户全局姓名 |
| `department_name` | `VARCHAR(128)` | 否 | 平台侧部门（手动输入） |
| `password_hash` | `VARCHAR(255)` | 是 | 密码哈希值 |
| `status` | `ENUM('ENABLED','DISABLED')` | 是 | 用户状态 |
| `session_version` | `INT UNSIGNED` | 是 | 会话版本号（默认 `0`） |
| `last_login_at` | `DATETIME` | 否 | 最近登录时间 |
| `deleted_at` | `DATETIME` | 否 | 软删除时间 |
| `created_at` | `DATETIME` | 是 | 创建时间 |
| `updated_at` | `DATETIME` | 是 | 更新时间 |

#### `orgs`

| 字段 | 类型 | 必填 | 说明 |
|---|---|---|---|
| `id` | `BIGINT UNSIGNED` | 是 | 组织主键（自增） |
| `name` | `VARCHAR(128)` | 是 | 组织名称 |
| `owner_user_id` | `BIGINT UNSIGNED` | 是 | 当前负责人用户ID |
| `status` | `ENUM('ENABLED','DISABLED')` | 是 | 组织状态 |
| `deleted_at` | `DATETIME` | 否 | 软删除时间 |
| `created_at` | `DATETIME` | 是 | 创建时间 |
| `updated_at` | `DATETIME` | 是 | 更新时间 |

#### `memberships`

| 字段 | 类型 | 必填 | 说明 |
|---|---|---|---|
| `id` | `BIGINT UNSIGNED` | 是 | 组织成员关系主键（自增） |
| `tenant_id` | `BIGINT UNSIGNED` | 是 | 组织ID |
| `user_id` | `BIGINT UNSIGNED` | 是 | 用户ID |
| `display_name` | `VARCHAR(64)` | 是 | 该组织下显示姓名 |
| `department_name` | `VARCHAR(128)` | 否 | 该组织下部门（手动输入） |
| `status` | `ENUM('ENABLED','DISABLED')` | 是 | 成员状态 |
| `joined_at` | `DATETIME` | 是 | 加入组织时间 |
| `deleted_at` | `DATETIME` | 否 | 软删除时间 |
| `created_at` | `DATETIME` | 是 | 创建时间 |
| `updated_at` | `DATETIME` | 是 | 更新时间 |

#### `roles`

| 字段 | 类型 | 必填 | 说明 |
|---|---|---|---|
| `id` | `BIGINT UNSIGNED` | 是 | 角色主键（自增） |
| `scope` | `ENUM('platform','tenant')` | 是 | 角色作用域 |
| `tenant_id` | `BIGINT UNSIGNED` | 是 | 组织域填组织ID；平台域固定 `0` |
| `code` | `VARCHAR(64)` | 是 | 角色编码；内置固定，自定义手动输入 |
| `name` | `VARCHAR(64)` | 是 | 角色名称 |
| `is_system` | `TINYINT(1)` | 是 | 是否系统内置角色 |
| `status` | `ENUM('ENABLED','DISABLED')` | 是 | 角色状态 |
| `deleted_at` | `DATETIME` | 否 | 软删除时间 |
| `created_at` | `DATETIME` | 是 | 创建时间 |
| `updated_at` | `DATETIME` | 是 | 更新时间 |

#### `permissions`

| 字段 | 类型 | 必填 | 说明 |
|---|---|---|---|
| `id` | `BIGINT UNSIGNED` | 是 | 权限主键（自增） |
| `scope` | `ENUM('platform','tenant')` | 是 | 权限作用域 |
| `code` | `VARCHAR(100)` | 是 | 权限编码（如 `tenant.user.create`） |
| `name` | `VARCHAR(100)` | 是 | 权限名称 |
| `type` | `ENUM('menu','button')` | 是 | 菜单或按钮权限 |
| `parent_id` | `BIGINT UNSIGNED` | 否 | 权限树父节点ID |
| `path_or_api` | `VARCHAR(255)` | 否 | 菜单路径或接口标识 |
| `http_method` | `VARCHAR(10)` | 否 | 接口方法（按钮权限可用） |
| `sort` | `INT` | 是 | 排序值 |
| `status` | `ENUM('ENABLED','DISABLED')` | 是 | 权限状态 |
| `deleted_at` | `DATETIME` | 否 | 软删除时间 |
| `created_at` | `DATETIME` | 是 | 创建时间 |
| `updated_at` | `DATETIME` | 是 | 更新时间 |

#### `role_permissions`

| 字段 | 类型 | 必填 | 说明 |
|---|---|---|---|
| `id` | `BIGINT UNSIGNED` | 是 | 主键（自增） |
| `role_id` | `BIGINT UNSIGNED` | 是 | 角色ID |
| `permission_id` | `BIGINT UNSIGNED` | 是 | 权限ID |
| `deleted_at` | `DATETIME` | 否 | 软删除时间 |
| `created_at` | `DATETIME` | 是 | 创建时间 |
| `updated_at` | `DATETIME` | 是 | 更新时间 |

#### `membership_roles`

| 字段 | 类型 | 必填 | 说明 |
|---|---|---|---|
| `id` | `BIGINT UNSIGNED` | 是 | 主键（自增） |
| `membership_id` | `BIGINT UNSIGNED` | 是 | 成员关系ID |
| `role_id` | `BIGINT UNSIGNED` | 是 | 角色ID |
| `deleted_at` | `DATETIME` | 否 | 软删除时间 |
| `created_at` | `DATETIME` | 是 | 创建时间 |
| `updated_at` | `DATETIME` | 是 | 更新时间 |

#### `user_roles`

| 字段 | 类型 | 必填 | 说明 |
|---|---|---|---|
| `id` | `BIGINT UNSIGNED` | 是 | 主键（自增） |
| `user_id` | `BIGINT UNSIGNED` | 是 | 用户ID |
| `role_id` | `BIGINT UNSIGNED` | 是 | 平台角色ID |
| `deleted_at` | `DATETIME` | 否 | 软删除时间 |
| `created_at` | `DATETIME` | 是 | 创建时间 |
| `updated_at` | `DATETIME` | 是 | 更新时间 |

#### `refresh_tokens`

| 字段 | 类型 | 必填 | 说明 |
|---|---|---|---|
| `id` | `BIGINT UNSIGNED` | 是 | 主键（自增） |
| `user_id` | `BIGINT UNSIGNED` | 是 | 用户ID |
| `token_hash` | `VARCHAR(255)` | 是 | 刷新令牌哈希 |
| `expires_at` | `DATETIME` | 是 | 过期时间 |
| `revoked_at` | `DATETIME` | 否 | 撤销时间 |
| `created_at` | `DATETIME` | 是 | 创建时间 |

#### `sms_codes`

| 字段 | 类型 | 必填 | 说明 |
|---|---|---|---|
| `id` | `BIGINT UNSIGNED` | 是 | 主键（自增） |
| `phone` | `VARCHAR(20)` | 是 | 手机号 |
| `code_hash` | `VARCHAR(255)` | 是 | 验证码哈希 |
| `expires_at` | `DATETIME` | 是 | 过期时间（15 分钟） |
| `used_at` | `DATETIME` | 否 | 使用时间 |
| `created_at` | `DATETIME` | 是 | 创建时间 |

#### `sys_configs`

| 字段 | 类型 | 必填 | 说明 |
|---|---|---|---|
| `id` | `BIGINT UNSIGNED` | 是 | 主键（自增） |
| `config_key` | `VARCHAR(100)` | 是 | 配置键（如 `auth.default_password`） |
| `value` | `TEXT` | 是 | 配置值（密码类配置存密文） |
| `remark` | `VARCHAR(255)` | 否 | 备注 |
| `created_at` | `DATETIME` | 是 | 创建时间 |
| `updated_at` | `DATETIME` | 是 | 更新时间 |

#### `audit_logs`

| 字段 | 类型 | 必填 | 说明 |
|---|---|---|---|
| `id` | `BIGINT UNSIGNED` | 是 | 主键（自增） |
| `operator_user_id` | `BIGINT UNSIGNED` | 否 | 操作人用户ID |
| `scope` | `ENUM('platform','tenant')` | 是 | 操作作用域 |
| `tenant_id` | `BIGINT UNSIGNED` | 否 | 组织ID（组织域操作必填） |
| `action` | `VARCHAR(100)` | 是 | 操作类型 |
| `target_type` | `VARCHAR(100)` | 否 | 目标实体类型 |
| `target_id` | `VARCHAR(64)` | 否 | 目标实体ID |
| `detail_json` | `JSON` | 否 | 变更详情 |
| `created_at` | `DATETIME` | 是 | 操作时间 |

### Relation Constraint Catalog (Detailed)

- 活跃唯一性：
  - `role_permissions(role_id, permission_id, deleted_at IS NULL)` 唯一。
  - `membership_roles(membership_id, role_id, deleted_at IS NULL)` 唯一。
  - `user_roles(user_id, role_id, deleted_at IS NULL)` 唯一。
- 重入规则：
  - 组织成员重入组创建新 `membership`，不恢复历史记录。
  - 历史 `membership_roles` 仅保留追溯，不复用。
- 级联与会话撤销规则：
  - 组织软删除时，成员、组织角色、角色绑定同步级联软删除，并使该组织会话上下文立即失效。
  - 用户软删除时，`memberships`、`user_roles` 同步失效或软删除，且立即撤销其全部 Refresh Token。
  - 角色软删除时，`role_permissions`、`membership_roles`、`user_roles` 同步软删除，避免悬挂授权关系。

### Deletion Cascade Matrix (Detailed)

| 根实体 | 前置条件 | 级联对象 | 级联动作 | 一致性要求 |
|---|---|---|---|---|
| `orgs` | 组织已 `DISABLED` | `memberships`, `roles(scope=tenant)`, `membership_roles`, `role_permissions` | 全部软删除 | 同事务提交；失败全回滚 |
| `users` | 用户已 `DISABLED` | `memberships`, `user_roles`, `refresh_tokens` | 关系软删除；Token 全撤销 | 会话立即失效；重复执行结果一致 |
| `roles` | 角色已 `DISABLED` | `role_permissions`, `membership_roles`, `user_roles` | 全部软删除 | 不得保留活跃授权关系 |

### Deletion Consistency Checks (Detailed)

- 发布门禁与日常巡检必须包含删除一致性校验，至少覆盖：
  - 父实体已软删除但子关系仍活跃。
  - `deleted_at IS NOT NULL` 但 `status='ENABLED'`（状态-删除语义冲突）。
  - 已软删除用户仍存在未撤销 Refresh Token。
- 推荐巡检 SQL（示例）：

```sql
-- 1) 组织已软删除但成员仍活跃
SELECT m.id
FROM memberships m
JOIN orgs o ON o.id = m.tenant_id
WHERE o.deleted_at IS NOT NULL AND m.deleted_at IS NULL;

-- 2) 状态语义冲突（以 users 为例，其他有 status 表同理）
SELECT id
FROM users
WHERE deleted_at IS NOT NULL AND status <> 'DISABLED';

-- 3) 用户已软删除但仍有未撤销 refresh token
SELECT rt.id
FROM refresh_tokens rt
JOIN users u ON u.id = rt.user_id
WHERE u.deleted_at IS NOT NULL AND rt.revoked_at IS NULL;
```

### Frontend Contract Baseline

- 组件与设计约束：
  - Web 端采用 `Ant Design 6+`，优先复用现有 `Custom*` 组件。
  - 禁止引入 Ant Design Pro 与额外第三方组件体系替代。
  - 图标统一 `@ant-design/icons`，图表统一 ECharts。
  - 移动端若实施，仅允许 `Ant Design Mobile` 及其封装组件体系。
- 交互基线：
  - 登录后按入口进入平台域/组织域。
  - 组织入口登录后先获取组织列表：单组织直达、多组织进入选择页；支持会话内切换组织。
  - 列表页统一搜索、分页、状态筛选、操作列模式。
  - 表单统一字段级校验 + 全局反馈；危险操作二次确认。
  - 列表错误态/加载态/空态采用统一组件与行为。
  - 提交按钮统一 loading + 防重复提交。
- 展示基线：
  - 时间展示格式 `yyyy-mm-dd hh:mm`。
  - 展示时区统一 `Asia/Shanghai`。
  - 列表默认按 `created_at` 倒序，默认 `pageSize=20`。
  - 支持前端传入 `pageSize` 并按请求值分页。

### Frontend Display Field Catalog (Detailed)

| 页面 | 展示字段 |
|---|---|
| 登录页（密码） | 手机号、密码 |
| 登录页（验证码） | 手机号、验证码、发送验证码按钮（60 秒倒计时） |
| 组织选择页（列表） | 统一组织图标、组织ID、组织名称 |
| 平台-用户列表 | 用户ID、手机号、姓名、部门、角色、状态、最近登录时间、创建时间 |
| 平台-用户编辑 | 用户ID（不可编辑）、手机号（不可编辑）、姓名、部门、角色（下拉多选） |
| 平台-角色列表 | 角色ID、角色编码、角色名称、状态、创建时间 |
| 平台-角色编辑 | 角色ID（不可编辑）、角色编码、角色名称、权限树（菜单/按钮） |
| 组织-成员列表 | 成员ID（`membership.id`）、手机号、姓名（组织内）、部门（组织内）、角色、状态、创建时间 |
| 组织-成员编辑 | 成员ID（不可编辑）、手机号（不可编辑）、姓名、部门、角色（下拉多选） |
| 组织-角色列表 | 角色ID、角色编码、角色名称、状态、创建时间 |
| 组织-角色编辑 | 角色ID（不可编辑）、角色编码、角色名称、权限树（菜单/按钮） |
| 负责人变更弹框 | 当前负责人（姓名/手机号）、新负责人（手机号）、提交结果提示 |
| 全局入口（非个人中心页） | 修改密码、切换组织、退出登录 |

### Frontend Filter Field Catalog (Detailed)

| 列表页面 | 筛选条件 |
|---|---|
| 用户列表（平台/组织） | 手机号（输入框）、姓名（输入框）、状态（下拉，默认“全部”）、创建时间（时间区间） |
| 角色列表（平台/组织） | 角色名称（输入框）、状态（下拉，默认“全部”）、创建时间（时间区间） |

### Frontend Interaction Rules (Detailed)

- 列表态规范：
  - 列表失败态在表格区域内展示并提供重试按钮。
  - 加载态统一使用 skeleton。
  - 空态统一使用 Empty 文案。
- 查询与分页：
  - 输入框回车触发查询。
  - 其他筛选控件值变化实时触发查询。
  - 页码与 `pageSize` 变化时保留当前筛选条件。
- 提交流程：
  - 提交成功后回列表并保留原筛选/分页。
  - 字段级错误与全局 Toast 同步反馈。
  - 所有提交操作统一按钮 loading + 防重复提交。
- 导航与安全反馈：
  - 无权限页面统一展示 403，提供“返回首页/切换组织”入口。
  - 编辑态离开页面、切换组织、关闭弹窗时统一未保存离开提醒。
  - 前端集中维护错误码映射（错误码 -> 文案/动作）。

### Testing & Readiness Baseline

- MVP 必测主线：
  - 认证：登录、刷新、登出、改密。
  - 租户隔离：跨组织不可见、不可操作。
  - RBAC 一致性：菜单/按钮/接口权限一致。
  - 负责人变更：自动入组 + 自动授权 + 并发冲突处理。
  - 初始化幂等：重复执行结果一致。
- 发布门禁：
  - P0 能力闭环通过。
  - Integration DoD 通过。
  - 一键回归覆盖（P0 + 集成链路 + 5 条旅程主路径）。

### Delivery Baseline

- 环境分层：本地、测试、正式（数据库与缓存严格隔离）。
- 运行方式：Docker / Docker Compose 统一运行时。
- 分支策略：`feature/* -> develop -> main`。
- CI：类型检查、测试、镜像构建、安全扫描。
- CD：`develop` 自动测试部署，`main` 发布流程控制。
- 回滚：保留稳定镜像版本并支持按镜像标签回滚。
- 灾备：定义备份频率、恢复流程并保留恢复演练记录。

### Decision Ledger (Consolidated)

- Blocker：
  - 权限并集模型，不引入显式 deny。
  - 组织域服务端最终上下文判定。
  - OpenAPI 契约完整性（字段、枚举、错误码、分页）。
  - 并发串行化与幂等写入。
- High：
  - 权限清单单一事实源。
  - 漏声明权限默认拒绝。
  - 角色禁用即时失效。
  - 权限树仅落叶子权限点。
- Medium：
  - 认证限流、重放检测、统一错误反馈策略。
  - 事务一致性、审计 before/after、UTC 存储 + 展示时区转换。
  - 前端失败态/空态/加载态与交互一致性。
- Low：
  - 批量操作、导出、高级筛选记忆等体验增强后置。

### Current Codebase Snapshot

- 代码现状：仓库仍处于文档驱动阶段，业务功能代码尚未完整落地。
- 可复用 UI 基础层：`apps/web/src/components` 下 8 个 `Custom*` 组件。
- 开发启动建议顺序：先契约与骨架，再数据模型，再权限主链路，再页面与联调。

### Merged Source Map

- 已合并的核心来源：
  - `2026-02-10-mvp-saas-auth-design.md`
  - `_bmad-output/brainstorming/brainstorming-session-2026-02-10.md`
  - `docs/api-contracts*.md`
  - `docs/data-models*.md`
  - `docs/architecture*.md`
  - `docs/development-guide.md`
  - `docs/deployment-guide.md`
  - `docs/component-inventory*.md`
  - `docs/contribution-guide.md`
- 用途：以上文件的关键决策与约束已收敛至本 PRD，可作为后续清理旧文件依据。
