const test = require('node:test');
const assert = require('node:assert/strict');
const http = require('node:http');
const net = require('node:net');
const { spawn } = require('node:child_process');
const { existsSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } = require('node:fs');
const { once } = require('node:events');
const { join, resolve } = require('node:path');
const { tmpdir } = require('node:os');
const { createApiApp } = require('../../api/src/app');
const { readConfig } = require('../../api/src/config/env');
const { createAuthService } = require('../../api/src/modules/auth/auth.service');

const WORKSPACE_ROOT = resolve(__dirname, '../../..');
const CHROME_BIN_CANDIDATES = [
  process.env.CHROME_BIN,
  '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome',
  '/usr/bin/google-chrome',
  '/usr/bin/chromium-browser',
  '/usr/bin/chromium'
].filter(Boolean);
const REAL_API_TEST_USER = {
  phone: '13920000001',
  password: 'Passw0rd!',
  tenantA: 'tenant-a',
  tenantB: 'tenant-b'
};

const sleep = (ms) => new Promise((resolveDelay) => setTimeout(resolveDelay, ms));

const reservePort = () =>
  new Promise((resolvePort, rejectPort) => {
    const server = net.createServer();
    server.on('error', rejectPort);
    server.listen(0, '127.0.0.1', () => {
      const address = server.address();
      const port = typeof address === 'object' && address ? address.port : 0;
      server.close((error) => {
        if (error) {
          rejectPort(error);
          return;
        }
        resolvePort(port);
      });
    });
  });

const waitForHttp = async (url, timeoutMs, label) => {
  const startedAt = Date.now();
  let lastError = 'unknown';

  while (Date.now() - startedAt < timeoutMs) {
    try {
      const response = await fetch(url);
      if (response.status >= 200 && response.status < 500) {
        return response;
      }
      lastError = `HTTP ${response.status}`;
    } catch (error) {
      lastError = error.message;
    }
    await sleep(200);
  }

  throw new Error(`Timeout waiting for ${label}: ${lastError}`);
};

const stopProcess = async (child, signal = 'SIGTERM') => {
  if (!child || child.exitCode !== null || child.killed) {
    return;
  }
  child.kill(signal);
  await Promise.race([once(child, 'exit'), sleep(3000)]);
  if (child.exitCode === null && !child.killed) {
    child.kill('SIGKILL');
    await Promise.race([once(child, 'exit'), sleep(1000)]);
  }
};

const resolveChromeBinary = () => {
  for (const candidate of CHROME_BIN_CANDIDATES) {
    if (typeof candidate === 'string' && candidate.length > 0 && existsSync(candidate)) {
      return candidate;
    }
  }
  throw new Error('Chrome binary not found. Set CHROME_BIN to a valid executable path.');
};

class CdpClient {
  constructor(wsUrl) {
    this.wsUrl = wsUrl;
    this.ws = null;
    this.nextId = 1;
    this.pending = new Map();
    this.listeners = [];
  }

  async connect() {
    await new Promise((resolveConnect, rejectConnect) => {
      const ws = new WebSocket(this.wsUrl);
      ws.addEventListener('open', () => {
        this.ws = ws;
        resolveConnect();
      });
      ws.addEventListener('error', (error) => rejectConnect(error));
      ws.addEventListener('close', () => {
        for (const reject of this.pending.values()) {
          reject(new Error('CDP connection closed'));
        }
        this.pending.clear();
      });
      ws.addEventListener('message', (event) => {
        const payload = JSON.parse(String(event.data));
        if (payload.id) {
          const callbacks = this.pending.get(payload.id);
          if (!callbacks) {
            return;
          }
          this.pending.delete(payload.id);
          if (payload.error) {
            callbacks.reject(new Error(payload.error.message));
            return;
          }
          callbacks.resolve(payload.result || {});
          return;
        }
        for (const listener of this.listeners) {
          listener(payload);
        }
      });
    });
  }

  send(method, params = {}, sessionId = null) {
    const id = this.nextId++;
    const message = { id, method, params };
    if (sessionId) {
      message.sessionId = sessionId;
    }

    return new Promise((resolveSend, rejectSend) => {
      this.pending.set(id, { resolve: resolveSend, reject: rejectSend });
      this.ws.send(JSON.stringify(message));
    });
  }

  onEvent(handler) {
    this.listeners.push(handler);
    return () => {
      this.listeners = this.listeners.filter((listener) => listener !== handler);
    };
  }

  async close() {
    if (this.ws && this.ws.readyState === WebSocket.OPEN) {
      this.ws.close();
    }
  }
}

const evaluate = async (cdp, sessionId, expression) => {
  const response = await cdp.send(
    'Runtime.evaluate',
    {
      expression,
      awaitPromise: true,
      returnByValue: true
    },
    sessionId
  );
  if (response.exceptionDetails) {
    throw new Error(response.exceptionDetails.text || 'Runtime.evaluate failed');
  }
  return response.result?.value;
};

const waitForCondition = async (cdp, sessionId, expression, timeoutMs, reason) => {
  const startedAt = Date.now();
  while (Date.now() - startedAt < timeoutMs) {
    const result = await evaluate(cdp, sessionId, expression);
    if (result) {
      return;
    }
    await sleep(150);
  }
  throw new Error(`Condition timed out: ${reason}`);
};

const waitForRequest = async (requests, predicate, timeoutMs, reason) => {
  const startedAt = Date.now();
  while (Date.now() - startedAt < timeoutMs) {
    if (requests.some(predicate)) {
      return;
    }
    await sleep(100);
  }
  throw new Error(`Request timed out: ${reason}`);
};

const createOtpApiServer = async () => {
  const requests = [];
  const responses = [];
  let otpSendCalls = 0;
  const tenantToken = 'tenant-flow-access-token';
  const tenantOptions = [
    { tenant_id: 'tenant-101', tenant_name: 'Tenant 101' },
    { tenant_id: 'tenant-202', tenant_name: 'Tenant 202' }
  ];
  let failTenantOptionsOnceAfterSelect = false;
  let failTenantOptionsOnceAfterSwitch = false;
  let activeTenantId = null;
  const tenantPermissionById = {
    'tenant-101': {
      scope_label: '组织权限（Tenant 101）',
      can_view_member_admin: true,
      can_operate_member_admin: true,
      can_view_billing: true,
      can_operate_billing: false
    },
    'tenant-202': {
      scope_label: '组织权限（Tenant 202）',
      can_view_member_admin: false,
      can_operate_member_admin: true,
      can_view_billing: true,
      can_operate_billing: true
    }
  };
  const currentTenantPermissionContext = () => {
    if (!activeTenantId) {
      return {
        scope_label: '组织未选择（无可操作权限）',
        can_view_member_admin: false,
        can_operate_member_admin: false,
        can_view_billing: false,
        can_operate_billing: false
      };
    }
    return tenantPermissionById[activeTenantId] || {
      scope_label: `组织权限（${activeTenantId}）`,
      can_view_member_admin: false,
      can_operate_member_admin: false,
      can_view_billing: false,
      can_operate_billing: false
    };
  };
  const server = http.createServer(async (req, res) => {
    const chunks = [];
    for await (const chunk of req) {
      chunks.push(chunk);
    }
    const bodyText = chunks.length > 0 ? Buffer.concat(chunks).toString('utf8') : '';
    const body = bodyText.length > 0 ? JSON.parse(bodyText) : {};

    requests.push({
      method: req.method || 'GET',
      path: req.url || '/',
      body
    });

    const sendJson = ({ status, contentType, payload, headers = {} }) => {
      res.statusCode = status;
      res.setHeader('content-type', contentType);
      for (const [header, value] of Object.entries(headers)) {
        res.setHeader(header, value);
      }
      responses.push({
        method: req.method || 'GET',
        path: req.url || '/',
        status,
        headers: {
          'content-type': contentType,
          ...headers
        },
        body: payload
      });
      res.end(JSON.stringify(payload));
    };

    if (req.method === 'POST' && req.url === '/auth/otp/send') {
      if (body.phone === '13800000002') {
        await sleep(300);
        sendJson({
          status: 200,
          contentType: 'application/json',
          payload: {
            sent: true,
            resend_after_seconds: 6,
            request_id: 'chrome-regression-send-delayed'
          }
        });
        return;
      }

      if (body.phone === '13800000004') {
        sendJson({
          status: 429,
          contentType: 'application/problem+json',
          headers: {
            'retry-after': '25',
            'x-ratelimit-limit': '1',
            'x-ratelimit-remaining': '0',
            'x-ratelimit-reset': '25',
            'x-ratelimit-policy': '1;w=60'
          },
          payload: {
            type: 'about:blank',
            title: 'Too Many Requests',
            status: 429,
            detail: '请求过于频繁，请稍后重试',
            error_code: 'AUTH-429-RATE-LIMITED',
            rate_limit_action: 'otp_send',
            retry_after_seconds: 25,
            request_id: 'chrome-regression-send-cooldown'
          }
        });
        return;
      }

      otpSendCalls += 1;
      if (otpSendCalls === 1) {
        sendJson({
          status: 200,
          contentType: 'application/json',
          payload: {
            sent: true,
            request_id: 'chrome-regression-send-ok',
            resend_after_seconds: 1
          }
        });
        return;
      }

      sendJson({
        status: 429,
        contentType: 'application/problem+json',
        headers: {
          'retry-after': '120',
          'x-ratelimit-limit': '1',
          'x-ratelimit-remaining': '0',
          'x-ratelimit-reset': '120',
          'x-ratelimit-policy': '1;w=60'
        },
        payload: {
          type: 'about:blank',
          title: 'Too Many Requests',
          status: 429,
          detail: '请求过于频繁，请稍后重试',
          error_code: 'AUTH-429-RATE-LIMITED',
          rate_limit_action: 'otp_send',
          retry_after_seconds: 120,
          request_id: 'chrome-regression-send-rate-limit'
        }
      });
      return;
    }

    if (req.method === 'POST' && req.url === '/auth/otp/login') {
      sendJson({
        status: 401,
        contentType: 'application/problem+json',
        payload: {
          type: 'about:blank',
          title: 'Authentication Failed',
          status: 401,
          detail: '验证码错误或已失效',
          error_code: 'AUTH-401-OTP-FAILED',
          request_id: 'chrome-regression-login'
        }
      });
      return;
    }

    if (req.method === 'POST' && req.url === '/auth/login') {
      if (body.phone === '13800000005' && body.password === 'Passw0rd!') {
        sendJson({
          status: 200,
          contentType: 'application/json',
          payload: {
            token_type: 'Bearer',
            access_token: tenantToken,
            refresh_token: 'tenant-flow-refresh-token',
            expires_in: 900,
            refresh_expires_in: 604800,
            session_id: 'tenant-flow-session',
            entry_domain: body.entry_domain || 'platform',
            active_tenant_id: body.entry_domain === 'tenant' ? activeTenantId : null,
            tenant_selection_required: body.entry_domain === 'tenant' ? activeTenantId === null : false,
            tenant_options: body.entry_domain === 'tenant' ? tenantOptions : [],
            tenant_permission_context: body.entry_domain === 'tenant'
              ? currentTenantPermissionContext()
              : {
                scope_label: '平台入口（无组织侧权限上下文）',
                can_view_member_admin: false,
                can_operate_member_admin: false,
                can_view_billing: false,
                can_operate_billing: false
              },
            request_id: 'chrome-regression-password-login'
          }
        });
        return;
      }

      sendJson({
        status: 401,
        contentType: 'application/problem+json',
        payload: {
          type: 'about:blank',
          title: 'Unauthorized',
          status: 401,
          detail: '手机号或密码错误',
          error_code: 'AUTH-401-LOGIN-FAILED',
          request_id: 'chrome-regression-password-login-failed'
        }
      });
      return;
    }

    if (req.method === 'GET' && req.url === '/auth/tenant/options') {
      if (failTenantOptionsOnceAfterSelect || failTenantOptionsOnceAfterSwitch) {
        failTenantOptionsOnceAfterSelect = false;
        failTenantOptionsOnceAfterSwitch = false;
        sendJson({
          status: 503,
          contentType: 'application/problem+json',
          payload: {
            type: 'about:blank',
            title: 'Service Unavailable',
            status: 503,
            detail: '组织上下文刷新失败',
            error_code: 'AUTH-503-TENANT-REFRESH',
            request_id: 'chrome-regression-tenant-options-failed'
          }
        });
        return;
      }
      sendJson({
        status: 200,
        contentType: 'application/json',
        payload: {
          session_id: 'tenant-flow-session',
          entry_domain: 'tenant',
          active_tenant_id: activeTenantId,
          tenant_selection_required: activeTenantId === null,
          tenant_options: tenantOptions,
          tenant_permission_context: currentTenantPermissionContext(),
          request_id: 'chrome-regression-tenant-options'
        }
      });
      return;
    }

    if (req.method === 'POST' && req.url === '/auth/tenant/select') {
      if (tenantOptions.some((option) => option.tenant_id === body.tenant_id)) {
        activeTenantId = body.tenant_id;
        failTenantOptionsOnceAfterSelect = true;
        sendJson({
          status: 200,
          contentType: 'application/json',
          payload: {
            session_id: 'tenant-flow-session',
            entry_domain: 'tenant',
            active_tenant_id: activeTenantId,
            tenant_selection_required: false,
            tenant_options: tenantOptions,
            tenant_permission_context: currentTenantPermissionContext(),
            request_id: 'chrome-regression-tenant-select'
          }
        });
      } else {
        sendJson({
          status: 403,
          contentType: 'application/problem+json',
          payload: {
            type: 'about:blank',
            title: 'Forbidden',
            status: 403,
            detail: '当前入口无可用访问域权限',
            error_code: 'AUTH-403-NO-DOMAIN',
            request_id: 'chrome-regression-tenant-select-denied'
          }
        });
      }
      return;
    }

    if (req.method === 'POST' && req.url === '/auth/tenant/switch') {
      if (tenantOptions.some((option) => option.tenant_id === body.tenant_id)) {
        activeTenantId = body.tenant_id;
        failTenantOptionsOnceAfterSwitch = true;
        sendJson({
          status: 200,
          contentType: 'application/json',
          payload: {
            session_id: 'tenant-flow-session',
            entry_domain: 'tenant',
            active_tenant_id: activeTenantId,
            tenant_selection_required: false,
            tenant_options: tenantOptions,
            tenant_permission_context: currentTenantPermissionContext(),
            request_id: 'chrome-regression-tenant-switch'
          }
        });
      } else {
        sendJson({
          status: 403,
          contentType: 'application/problem+json',
          payload: {
            type: 'about:blank',
            title: 'Forbidden',
            status: 403,
            detail: '当前入口无可用访问域权限',
            error_code: 'AUTH-403-NO-DOMAIN',
            request_id: 'chrome-regression-tenant-switch-denied'
          }
        });
      }
      return;
    }

    sendJson({
      status: 404,
      contentType: 'application/json',
      payload: { error: 'not found' }
    });
  });

  const apiPort = await reservePort();
  await new Promise((resolveListen, rejectListen) => {
    server.listen(apiPort, '127.0.0.1', (error) => {
      if (error) {
        rejectListen(error);
        return;
      }
      resolveListen();
    });
  });

  return {
    apiPort,
    requests,
    responses,
    close: async () => {
      await new Promise((resolveClose) => server.close(() => resolveClose()));
    }
  };
};

const createPlatformGovernanceApiServer = async () => {
  const requests = [];
  const responses = [];
  const permissionCatalog = [
    'platform.member_admin.view',
    'platform.member_admin.operate',
    'platform.billing.view',
    'platform.billing.operate',
    'platform.system_config.view',
    'platform.system_config.operate'
  ];

  let nextUserId = 3;
  let nextRoleId = 3;
  const users = new Map([
    ['platform-user-1', { user_id: 'platform-user-1', phone: '13800000011', status: 'active', deleted: false }],
    ['platform-user-2', { user_id: 'platform-user-2', phone: '13800000012', status: 'disabled', deleted: false }]
  ]);
  const roles = new Map([
    [
      'sys_admin',
      {
        role_id: 'sys_admin',
        code: 'SYS_ADMIN',
        name: '系统管理员',
        status: 'active',
        is_system: true,
        created_at: new Date().toISOString(),
        updated_at: new Date().toISOString()
      }
    ],
    [
      'platform_member_admin',
      {
        role_id: 'platform_member_admin',
        code: 'PLATFORM_MEMBER_ADMIN',
        name: '平台成员治理',
        status: 'active',
        is_system: false,
        created_at: new Date().toISOString(),
        updated_at: new Date().toISOString()
      }
    ]
  ]);
  const rolePermissions = new Map([
    ['sys_admin', [...permissionCatalog]],
    ['platform_member_admin', ['platform.member_admin.view', 'platform.member_admin.operate']]
  ]);

  const normalizeRoleIds = (roleEntries = []) => {
    const deduped = new Set();
    for (const roleEntry of Array.isArray(roleEntries) ? roleEntries : []) {
      const normalizedRoleId = String(roleEntry?.role_id || '').trim().toLowerCase();
      if (normalizedRoleId) {
        deduped.add(normalizedRoleId);
      }
    }
    return [...deduped];
  };

  const buildPermissionContext = (roleIds = []) => {
    const permissionSet = new Set();
    for (const roleId of roleIds) {
      const grants = rolePermissions.get(String(roleId || '').trim().toLowerCase()) || [];
      for (const permissionCode of grants) {
        permissionSet.add(permissionCode);
      }
    }
    return {
      scope_label: '平台权限（角色并集）',
      can_view_member_admin: permissionSet.has('platform.member_admin.view'),
      can_operate_member_admin: permissionSet.has('platform.member_admin.operate'),
      can_view_billing: permissionSet.has('platform.billing.view'),
      can_operate_billing: permissionSet.has('platform.billing.operate')
    };
  };

  const readRequestBody = async (req) => {
    const chunks = [];
    for await (const chunk of req) {
      chunks.push(chunk);
    }
    if (chunks.length <= 0) {
      return {};
    }
    const text = Buffer.concat(chunks).toString('utf8');
    if (!text.trim()) {
      return {};
    }
    try {
      return JSON.parse(text);
    } catch (_error) {
      return {};
    }
  };

  const server = http.createServer(async (req, res) => {
    const method = req.method || 'GET';
    const url = new URL(req.url || '/', 'http://127.0.0.1');
    const pathname = url.pathname;
    const body = await readRequestBody(req);
    const requestId = String(req.headers['x-request-id'] || `req-platform-ui-${Date.now()}`);

    requests.push({
      method,
      path: req.url || '/',
      body
    });

    const sendJson = ({ status, contentType, payload }) => {
      res.statusCode = status;
      res.setHeader('content-type', contentType);
      responses.push({
        method,
        path: req.url || '/',
        status,
        headers: {
          'content-type': contentType
        },
        body: payload
      });
      res.end(JSON.stringify(payload));
    };

    const sendProblem = ({
      status = 400,
      title = 'Bad Request',
      detail = '请求失败',
      errorCode = 'APP-400-BAD-REQUEST',
      retryable = false
    }) =>
      sendJson({
        status,
        contentType: 'application/problem+json',
        payload: {
          type: 'about:blank',
          title,
          status,
          detail,
          error_code: errorCode,
          request_id: requestId,
          retryable
        }
      });

    if (method === 'POST' && pathname === '/auth/login') {
      sendJson({
        status: 200,
        contentType: 'application/json',
        payload: {
          token_type: 'Bearer',
          access_token: 'platform-governance-access-token',
          refresh_token: 'platform-governance-refresh-token',
          expires_in: 900,
          refresh_expires_in: 1209600,
          session_id: 'platform-governance-session',
          entry_domain: body.entry_domain || 'platform',
          active_tenant_id: null,
          tenant_selection_required: false,
          tenant_options: [],
          tenant_permission_context: null,
          request_id: requestId
        }
      });
      return;
    }

    if (method === 'GET' && pathname === '/platform/users') {
      const page = Number(url.searchParams.get('page') || 1);
      const pageSize = Number(url.searchParams.get('page_size') || 20);
      const statusFilter = String(url.searchParams.get('status') || '').trim().toLowerCase();
      const keyword = String(url.searchParams.get('keyword') || '').trim();
      const listedUsers = [...users.values()].filter((user) => !user.deleted);
      const filteredUsers = listedUsers.filter((user) => {
        if (statusFilter && user.status !== statusFilter) {
          return false;
        }
        if (!keyword) {
          return true;
        }
        return user.user_id.includes(keyword) || user.phone.includes(keyword);
      });
      const offset = (Math.max(1, page) - 1) * Math.max(1, pageSize);
      const pageItems = filteredUsers.slice(offset, offset + Math.max(1, pageSize));
      sendJson({
        status: 200,
        contentType: 'application/json',
        payload: {
          items: pageItems.map((user) => ({
            user_id: user.user_id,
            phone: user.phone,
            status: user.status
          })),
          total: filteredUsers.length,
          page: Math.max(1, page),
          page_size: Math.max(1, pageSize),
          request_id: requestId
        }
      });
      return;
    }

    if (method === 'POST' && pathname === '/platform/users') {
      const phone = String(body.phone || '').trim();
      if (!/^1\d{10}$/.test(phone)) {
        sendProblem({
          status: 400,
          detail: '请求参数不完整或格式错误',
          errorCode: 'AUTH-400-INVALID-PAYLOAD'
        });
        return;
      }
      const userId = `platform-user-${nextUserId++}`;
      users.set(userId, {
        user_id: userId,
        phone,
        status: 'active',
        deleted: false
      });
      sendJson({
        status: 200,
        contentType: 'application/json',
        payload: {
          user_id: userId,
          created_user: true,
          reused_existing_user: false,
          request_id: requestId
        }
      });
      return;
    }

    if (method === 'POST' && pathname === '/platform/users/status') {
      const userId = String(body.user_id || '').trim();
      const status = String(body.status || '').trim().toLowerCase();
      const target = users.get(userId);
      if (!target || target.deleted) {
        sendProblem({
          status: 404,
          title: 'Not Found',
          detail: '目标平台用户不存在或无 platform 域访问',
          errorCode: 'USR-404-USER-NOT-FOUND'
        });
        return;
      }
      const nextStatus = status === 'enabled' ? 'active' : status;
      if (nextStatus !== 'active' && nextStatus !== 'disabled') {
        sendProblem({
          status: 400,
          detail: 'status 必须为 active 或 disabled',
          errorCode: 'USR-400-INVALID-PAYLOAD'
        });
        return;
      }
      const previousStatus = target.status;
      target.status = nextStatus;
      users.set(userId, target);
      sendJson({
        status: 200,
        contentType: 'application/json',
        payload: {
          user_id: userId,
          previous_status: previousStatus,
          current_status: nextStatus,
          request_id: requestId
        }
      });
      return;
    }

    const userDetailMatch = pathname.match(/^\/platform\/users\/([^/]+)$/);
    if (userDetailMatch && method === 'GET') {
      const userId = decodeURIComponent(userDetailMatch[1] || '');
      const target = users.get(userId);
      if (!target || target.deleted) {
        sendProblem({
          status: 404,
          title: 'Not Found',
          detail: '目标平台用户不存在或无 platform 域访问',
          errorCode: 'USR-404-USER-NOT-FOUND'
        });
        return;
      }
      sendJson({
        status: 200,
        contentType: 'application/json',
        payload: {
          user_id: target.user_id,
          phone: target.phone,
          status: target.status,
          request_id: requestId
        }
      });
      return;
    }

    if (userDetailMatch && method === 'DELETE') {
      const userId = decodeURIComponent(userDetailMatch[1] || '');
      const target = users.get(userId);
      if (!target || target.deleted) {
        sendProblem({
          status: 404,
          title: 'Not Found',
          detail: '目标平台用户不存在或无 platform 域访问',
          errorCode: 'USR-404-USER-NOT-FOUND'
        });
        return;
      }
      target.deleted = true;
      target.status = 'disabled';
      users.set(userId, target);
      sendJson({
        status: 200,
        contentType: 'application/json',
        payload: {
          user_id: userId,
          previous_status: 'active',
          current_status: 'disabled',
          revoked_session_count: 1,
          revoked_refresh_token_count: 1,
          request_id: requestId
        }
      });
      return;
    }

    if (method === 'GET' && pathname === '/platform/roles') {
      sendJson({
        status: 200,
        contentType: 'application/json',
        payload: {
          roles: [...roles.values()].map((role) => ({
            ...role,
            request_id: requestId
          })),
          request_id: requestId
        }
      });
      return;
    }

    if (method === 'POST' && pathname === '/platform/roles') {
      const roleId = String(body.role_id || '').trim().toLowerCase();
      if (!roleId) {
        sendProblem({
          status: 400,
          detail: '请求参数不完整或格式错误',
          errorCode: 'ROLE-400-INVALID-PAYLOAD'
        });
        return;
      }
      if (roles.has(roleId)) {
        sendProblem({
          status: 409,
          title: 'Conflict',
          detail: '角色标识冲突，请使用其他 role_id',
          errorCode: 'ROLE-409-ROLE-ID-CONFLICT'
        });
        return;
      }
      const now = new Date().toISOString();
      const createdRole = {
        role_id: roleId,
        code: String(body.code || `ROLE_${nextRoleId}`).trim() || `ROLE_${nextRoleId}`,
        name: String(body.name || `角色 ${nextRoleId}`).trim() || `角色 ${nextRoleId}`,
        status: String(body.status || 'active').trim().toLowerCase() || 'active',
        is_system: false,
        created_at: now,
        updated_at: now
      };
      nextRoleId += 1;
      roles.set(roleId, createdRole);
      rolePermissions.set(
        roleId,
        roleId.includes('billing')
          ? ['platform.billing.view', 'platform.billing.operate']
          : ['platform.member_admin.view']
      );
      sendJson({
        status: 200,
        contentType: 'application/json',
        payload: {
          ...createdRole,
          request_id: requestId
        }
      });
      return;
    }

    const roleItemMatch = pathname.match(/^\/platform\/roles\/([^/]+)$/);
    if (roleItemMatch && method === 'PATCH') {
      const roleId = decodeURIComponent(roleItemMatch[1] || '').trim().toLowerCase();
      const target = roles.get(roleId);
      if (!target) {
        sendProblem({
          status: 404,
          title: 'Not Found',
          detail: '目标平台角色不存在',
          errorCode: 'ROLE-404-ROLE-NOT-FOUND'
        });
        return;
      }
      if (target.is_system) {
        sendProblem({
          status: 403,
          title: 'Forbidden',
          detail: '受保护系统角色不允许编辑或删除',
          errorCode: 'ROLE-403-SYSTEM-ROLE-PROTECTED'
        });
        return;
      }
      const updated = {
        ...target,
        code: String(body.code || target.code),
        name: String(body.name || target.name),
        status: String(body.status || target.status).trim().toLowerCase() || target.status,
        updated_at: new Date().toISOString()
      };
      roles.set(roleId, updated);
      sendJson({
        status: 200,
        contentType: 'application/json',
        payload: {
          ...updated,
          request_id: requestId
        }
      });
      return;
    }

    if (roleItemMatch && method === 'DELETE') {
      const roleId = decodeURIComponent(roleItemMatch[1] || '').trim().toLowerCase();
      const target = roles.get(roleId);
      if (!target) {
        sendProblem({
          status: 404,
          title: 'Not Found',
          detail: '目标平台角色不存在',
          errorCode: 'ROLE-404-ROLE-NOT-FOUND'
        });
        return;
      }
      if (target.is_system) {
        sendProblem({
          status: 403,
          title: 'Forbidden',
          detail: '受保护系统角色不允许编辑或删除',
          errorCode: 'ROLE-403-SYSTEM-ROLE-PROTECTED'
        });
        return;
      }
      roles.delete(roleId);
      rolePermissions.delete(roleId);
      sendJson({
        status: 200,
        contentType: 'application/json',
        payload: {
          role_id: roleId,
          code: target.code,
          name: target.name,
          status: 'disabled',
          is_system: false,
          created_at: target.created_at,
          updated_at: new Date().toISOString(),
          request_id: requestId
        }
      });
      return;
    }

    const rolePermissionMatch = pathname.match(/^\/platform\/roles\/([^/]+)\/permissions$/);
    if (rolePermissionMatch && method === 'GET') {
      const roleId = decodeURIComponent(rolePermissionMatch[1] || '').trim().toLowerCase();
      if (!roles.has(roleId)) {
        sendProblem({
          status: 404,
          title: 'Not Found',
          detail: '目标平台角色不存在',
          errorCode: 'ROLE-404-ROLE-NOT-FOUND'
        });
        return;
      }
      sendJson({
        status: 200,
        contentType: 'application/json',
        payload: {
          role_id: roleId,
          permission_codes: rolePermissions.get(roleId) || [],
          available_permission_codes: permissionCatalog,
          request_id: requestId
        }
      });
      return;
    }

    if (rolePermissionMatch && method === 'PUT') {
      const roleId = decodeURIComponent(rolePermissionMatch[1] || '').trim().toLowerCase();
      if (!roles.has(roleId)) {
        sendProblem({
          status: 404,
          title: 'Not Found',
          detail: '目标平台角色不存在',
          errorCode: 'ROLE-404-ROLE-NOT-FOUND'
        });
        return;
      }
      const nextPermissions = [...new Set(
        (Array.isArray(body.permission_codes) ? body.permission_codes : [])
          .map((permissionCode) => String(permissionCode || '').trim())
          .filter((permissionCode) => permissionCode.startsWith('platform.'))
      )];
      rolePermissions.set(roleId, nextPermissions);
      sendJson({
        status: 200,
        contentType: 'application/json',
        payload: {
          role_id: roleId,
          permission_codes: nextPermissions,
          available_permission_codes: permissionCatalog,
          affected_user_count: 1,
          request_id: requestId
        }
      });
      return;
    }

    if (method === 'POST' && pathname === '/auth/platform/role-facts/replace') {
      const userId = String(body.user_id || '').trim();
      const targetUser = users.get(userId);
      if (!targetUser || targetUser.deleted) {
        sendProblem({
          status: 404,
          title: 'Not Found',
          detail: '目标平台用户不存在或无 platform 域访问',
          errorCode: 'AUTH-404-USER-NOT-FOUND'
        });
        return;
      }
      const roleIds = normalizeRoleIds(body.roles);
      if (roleIds.length < 1 || roleIds.length > 5) {
        sendProblem({
          status: 400,
          detail: 'roles must include 1 to 5 entries',
          errorCode: 'AUTH-400-INVALID-PAYLOAD'
        });
        return;
      }
      const context = buildPermissionContext(roleIds);
      sendJson({
        status: 200,
        contentType: 'application/json',
        payload: {
          synced: true,
          reason: 'platform-role-facts-updated',
          platform_permission_context: context,
          request_id: requestId
        }
      });
      return;
    }

    sendJson({
      status: 404,
      contentType: 'application/problem+json',
      payload: {
        type: 'about:blank',
        title: 'Not Found',
        status: 404,
        detail: `No route for ${pathname}`,
        error_code: 'AUTH-404-NOT-FOUND',
        request_id: requestId,
        retryable: false
      }
    });
  });

  const apiPort = await reservePort();
  await new Promise((resolveListen, rejectListen) => {
    server.listen(apiPort, '127.0.0.1', (error) => {
      if (error) {
        rejectListen(error);
        return;
      }
      resolveListen();
    });
  });

  return {
    apiPort,
    requests,
    responses,
    close: async () => {
      await new Promise((resolveClose) => server.close(() => resolveClose()));
    }
  };
};

const createRealApiServer = async () => {
  const config = readConfig({
    ALLOW_MOCK_BACKENDS: 'true'
  });
  const authService = createAuthService({
    seedUsers: [
      {
        id: 'chrome-real-user',
        phone: REAL_API_TEST_USER.phone,
        password: REAL_API_TEST_USER.password,
        status: 'active',
        domains: ['platform', 'tenant'],
        tenants: [
          {
            tenantId: REAL_API_TEST_USER.tenantA,
            tenantName: 'Tenant A',
            status: 'active',
            permission: {
              scopeLabel: '组织权限（Tenant A）',
              canViewMemberAdmin: true,
              canOperateMemberAdmin: true,
              canViewBilling: true,
              canOperateBilling: false
            }
          },
          {
            tenantId: REAL_API_TEST_USER.tenantB,
            tenantName: 'Tenant B',
            status: 'active',
            permission: {
              scopeLabel: '组织权限（Tenant B）',
              canViewMemberAdmin: false,
              canOperateMemberAdmin: false,
              canViewBilling: true,
              canOperateBilling: true
            }
          }
        ]
      }
    ],
    allowInMemoryOtpStores: true,
    requireSecureOtpStores: false
  });

  const app = await createApiApp(config, {
    dependencyProbe: async () => ({
      db: { ok: true, detail: 'mock db' },
      redis: { ok: true, detail: 'mock redis' }
    }),
    authService
  });
  await app.init();
  await app.listen(0, '127.0.0.1');
  const address = app.getHttpServer().address();
  const apiPort = typeof address === 'object' && address ? address.port : 0;

  return {
    apiPort,
    close: async () => {
      await app.close();
    }
  };
};

const requestRealApi = async ({ baseUrl, method = 'GET', path, body, accessToken }) => {
  const headers = {
    accept: 'application/json, application/problem+json'
  };
  if (body !== undefined) {
    headers['content-type'] = 'application/json';
  }
  if (accessToken) {
    headers.authorization = `Bearer ${accessToken}`;
  }

  const response = await fetch(`${baseUrl}${path}`, {
    method,
    headers,
    body: body === undefined ? undefined : JSON.stringify(body)
  });
  const payload = await response.json();
  return {
    status: response.status,
    body: payload
  };
};

test('chrome regression covers otp login flow with archived evidence', async (t) => {
  const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
  const evidenceDir = resolve(WORKSPACE_ROOT, 'artifacts/chrome-regression');
  mkdirSync(evidenceDir, { recursive: true });

  const chromeBinary = resolveChromeBinary();
  const api = await createOtpApiServer();
  const webPort = await reservePort();
  const cdpPort = await reservePort();
  const chromeProfileDir = mkdtempSync(join(tmpdir(), 'neweast-chrome-profile-'));

  let vite = null;
  let chrome = null;
  let cdp = null;
  let screenshotPath = '';

  const viteLogs = { stdout: '', stderr: '' };
  const chromeLogs = { stdout: '', stderr: '' };

  t.after(async () => {
    await cdp?.close();
    await stopProcess(chrome);
    await stopProcess(vite);
    await api.close();
    rmSync(chromeProfileDir, { recursive: true, force: true });
  });

  vite = spawn(
    'pnpm',
    [
      '--dir',
      'apps/web',
      'exec',
      'vite',
      '--host',
      '127.0.0.1',
      '--port',
      String(webPort),
      '--strictPort',
      '--config',
      'vite.config.js'
    ],
    {
      cwd: WORKSPACE_ROOT,
      env: {
        ...process.env,
        VITE_PROXY_TARGET: `http://127.0.0.1:${api.apiPort}`
      },
      stdio: ['ignore', 'pipe', 'pipe']
    }
  );
  vite.stdout.on('data', (data) => {
    viteLogs.stdout += String(data);
  });
  vite.stderr.on('data', (data) => {
    viteLogs.stderr += String(data);
  });

  await waitForHttp(`http://127.0.0.1:${webPort}/`, 30000, 'vite web server');

  chrome = spawn(
    chromeBinary,
    [
      `--remote-debugging-port=${cdpPort}`,
      `--user-data-dir=${chromeProfileDir}`,
      '--headless=new',
      '--disable-gpu',
      '--disable-dev-shm-usage',
      '--no-first-run',
      '--no-default-browser-check',
      'about:blank'
    ],
    {
      cwd: WORKSPACE_ROOT,
      stdio: ['ignore', 'pipe', 'pipe']
    }
  );
  chrome.stdout.on('data', (data) => {
    chromeLogs.stdout += String(data);
  });
  chrome.stderr.on('data', (data) => {
    chromeLogs.stderr += String(data);
  });

  const version = await (
    await waitForHttp(`http://127.0.0.1:${cdpPort}/json/version`, 20000, 'chrome devtools endpoint')
  ).json();
  cdp = new CdpClient(version.webSocketDebuggerUrl);
  await cdp.connect();

  const { targetId } = await cdp.send('Target.createTarget', { url: 'about:blank' });
  const { sessionId } = await cdp.send('Target.attachToTarget', { targetId, flatten: true });
  await cdp.send('Page.enable', {}, sessionId);
  await cdp.send('Runtime.enable', {}, sessionId);

  await cdp.send(
    'Page.navigate',
    { url: `http://127.0.0.1:${webPort}/` },
    sessionId
  );
  await waitForCondition(
    cdp,
    sessionId,
    `Boolean(document.querySelector('[data-testid="page-title"]'))`,
    10000,
    'page title should be visible'
  );

  const defaultModeVisible = await evaluate(
    cdp,
    sessionId,
    `Boolean(document.querySelector('[data-testid="input-password"]'))`
  );
  assert.equal(defaultModeVisible, true, 'password mode should be default');

  await evaluate(
    cdp,
    sessionId,
    `(() => { document.querySelector('[data-testid="mode-otp"]').click(); return true; })()`
  );
  await evaluate(
    cdp,
    sessionId,
    `(() => {
      const phone = document.querySelector('[data-testid="input-phone"]');
      const setter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value')?.set;
      setter.call(phone, '13800000000');
      phone.dispatchEvent(new Event('input', { bubbles: true }));
      phone.dispatchEvent(new Event('change', { bubbles: true }));
      return true;
    })()`
  );
  await waitForCondition(
    cdp,
    sessionId,
    `Boolean(document.querySelector('[data-testid="input-otp-code"]'))`,
    5000,
    'otp mode should be switched on'
  );

  await evaluate(
    cdp,
    sessionId,
    `(() => {
      const phone = document.querySelector('[data-testid="input-phone"]');
      const setter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value')?.set;
      setter.call(phone, '13800000000');
      phone.dispatchEvent(new Event('input', { bubbles: true }));
      phone.dispatchEvent(new Event('change', { bubbles: true }));
      return true;
    })()`
  );
  await waitForCondition(
    cdp,
    sessionId,
    `document.querySelector('[data-testid="input-phone"]')?.value === '13800000000'`,
    3000,
    'phone input value should be stable before otp send'
  );
  await sleep(120);
  await evaluate(
    cdp,
    sessionId,
    `(() => { document.querySelector('[data-testid="button-send-otp"]').click(); return true; })()`
  );
  await waitForRequest(
    api.requests,
    (request) => request.path === '/auth/otp/send',
    8000,
    'otp send request should reach API stub'
  );

  await waitForCondition(
    cdp,
    sessionId,
    `(() => {
      const text = String(document.querySelector('[data-testid="button-send-otp"]')?.textContent || '');
      const saved = Number(localStorage.getItem('neweast.auth.otp.resend_until_ms:13800000000') || 0);
      return text.includes('后重试') && saved > Date.now();
    })()`,
    10000,
    'otp send success should trigger countdown with persisted deadline'
  );

  await waitForCondition(
    cdp,
    sessionId,
    `(() => {
      const text = String(document.querySelector('[data-testid="button-send-otp"]')?.textContent || '');
      const saved = Number(localStorage.getItem('neweast.auth.otp.resend_until_ms:13800000000') || 0);
      return text.includes('发送验证码') && saved <= Date.now();
    })()`,
    10000,
    'otp send success countdown should clear before resend'
  );

  await evaluate(
    cdp,
    sessionId,
    `(() => { document.querySelector('[data-testid="button-send-otp"]').click(); return true; })()`
  );
  await waitForRequest(
    api.requests,
    (request) =>
      request.path === '/auth/otp/send' &&
      request.method === 'POST' &&
      api.requests.filter((item) => item.path === '/auth/otp/send').length >= 2,
    8000,
    'second otp send request should reach API stub and trigger 429'
  );
  await waitForCondition(
    cdp,
    sessionId,
    `(() => {
      const text = String(document.querySelector('[data-testid="button-send-otp"]')?.textContent || '');
      return text.includes('后重试');
    })()`,
    10000,
    'otp send rate-limit countdown should be visible'
  );

  await cdp.send('Page.reload', { ignoreCache: true }, sessionId);
  await waitForCondition(
    cdp,
    sessionId,
    `Boolean(document.querySelector('[data-testid="page-title"]'))`,
    10000,
    'page should be ready after reload'
  );
  await evaluate(
    cdp,
    sessionId,
    `(() => { document.querySelector('[data-testid="mode-otp"]').click(); return true; })()`
  );
  await evaluate(
    cdp,
    sessionId,
    `(() => {
      const phone = document.querySelector('[data-testid="input-phone"]');
      const setter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value')?.set;
      setter.call(phone, '13800000000');
      phone.dispatchEvent(new Event('input', { bubbles: true }));
      phone.dispatchEvent(new Event('change', { bubbles: true }));
      return true;
    })()`
  );
  await waitForCondition(
    cdp,
    sessionId,
    `(() => {
      const buttonText = String(document.querySelector('[data-testid="button-send-otp"]')?.textContent || '');
      const saved = Number(localStorage.getItem('neweast.auth.otp.resend_until_ms:13800000000') || 0);
      return buttonText.includes('后重试') && saved > Date.now();
    })()`,
    5000,
    'otp rate-limit countdown should recover after refresh'
  );

  await evaluate(
    cdp,
    sessionId,
    `(() => {
      const phone = document.querySelector('[data-testid="input-phone"]');
      const setter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value')?.set;
      setter.call(phone, '13800000001');
      phone.dispatchEvent(new Event('input', { bubbles: true }));
      phone.dispatchEvent(new Event('change', { bubbles: true }));
      return true;
    })()`
  );
  await waitForCondition(
    cdp,
    sessionId,
    `(() => {
      const buttonText = String(document.querySelector('[data-testid="button-send-otp"]')?.textContent || '');
      const savedA = Number(localStorage.getItem('neweast.auth.otp.resend_until_ms:13800000000') || 0);
      const savedB = Number(localStorage.getItem('neweast.auth.otp.resend_until_ms:13800000001') || 0);
      return buttonText.includes('发送验证码') && savedA > Date.now() && savedB <= Date.now();
    })()`,
    5000,
    'otp countdown persistence should be isolated by phone number'
  );

  await evaluate(
    cdp,
    sessionId,
    `(() => {
      const phone = document.querySelector('[data-testid="input-phone"]');
      const setter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value')?.set;
      setter.call(phone, '13800000002');
      phone.dispatchEvent(new Event('input', { bubbles: true }));
      phone.dispatchEvent(new Event('change', { bubbles: true }));
      return true;
    })()`
  );
  await evaluate(
    cdp,
    sessionId,
    `(() => { document.querySelector('[data-testid="button-send-otp"]').click(); return true; })()`
  );
  await evaluate(
    cdp,
    sessionId,
    `(() => {
      const phone = document.querySelector('[data-testid="input-phone"]');
      const setter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value')?.set;
      setter.call(phone, '13800000003');
      phone.dispatchEvent(new Event('input', { bubbles: true }));
      phone.dispatchEvent(new Event('change', { bubbles: true }));
      return true;
    })()`
  );
  await waitForCondition(
    cdp,
    sessionId,
    `(() => {
      const delayedSaved = Number(localStorage.getItem('neweast.auth.otp.resend_until_ms:13800000002') || 0);
      return delayedSaved > Date.now();
    })()`,
    5000,
    'delayed otp response should still persist countdown for original phone'
  );
  await waitForCondition(
    cdp,
    sessionId,
    `(() => {
      const buttonText = String(document.querySelector('[data-testid="button-send-otp"]')?.textContent || '');
      const currentSaved = Number(localStorage.getItem('neweast.auth.otp.resend_until_ms:13800000003') || 0);
      return buttonText.includes('发送验证码') && currentSaved <= Date.now();
    })()`,
    5000,
    'delayed response for previous phone must not override current phone countdown state'
  );

  await evaluate(
    cdp,
    sessionId,
    `(() => {
      const phone = document.querySelector('[data-testid="input-phone"]');
      const setter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value')?.set;
      setter.call(phone, '13800000004');
      phone.dispatchEvent(new Event('input', { bubbles: true }));
      phone.dispatchEvent(new Event('change', { bubbles: true }));
      return true;
    })()`
  );
  await sleep(100);
  await evaluate(
    cdp,
    sessionId,
    `(() => { document.querySelector('[data-testid="button-send-otp"]').click(); return true; })()`
  );
  await waitForRequest(
    api.requests,
    (request) => request.path === '/auth/otp/send' && request.body?.phone === '13800000004',
    8000,
    'otp send cooldown(429) request should reach API stub'
  );
  await waitForCondition(
    cdp,
    sessionId,
    `(() => {
      const message = String(document.querySelector('[data-testid="message-global"]')?.textContent || '');
      return message.includes('请稍后重试');
    })()`,
    10000,
    'otp send cooldown (429) should show retry message'
  );
  const cooldownMessageText = String(
    await evaluate(cdp, sessionId, `document.querySelector('[data-testid="message-global"]')?.textContent || ''`)
  );
  assert.equal(
    cooldownMessageText.indexOf('请稍后重试') === cooldownMessageText.lastIndexOf('请稍后重试'),
    true,
    'retry message must not contain duplicate "请稍后重试" suffix (was: ' + cooldownMessageText + ')'
  );
  await waitForCondition(
    cdp,
    sessionId,
    `(() => {
      const buttonText = String(document.querySelector('[data-testid="button-send-otp"]')?.textContent || '');
      return buttonText.includes('后重试');
    })()`,
    5000,
    'otp send cooldown (429) should trigger countdown'
  );

  await evaluate(
    cdp,
    sessionId,
    `(() => {
      const phone = document.querySelector('[data-testid="input-phone"]');
      const setter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value')?.set;
      setter.call(phone, '13800000000');
      phone.dispatchEvent(new Event('input', { bubbles: true }));
      phone.dispatchEvent(new Event('change', { bubbles: true }));
      return true;
    })()`
  );

  await evaluate(
    cdp,
    sessionId,
    `(() => {
      const otp = document.querySelector('[data-testid="input-otp-code"]');
      const setter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value')?.set;
      setter.call(otp, '123456');
      otp.dispatchEvent(new Event('input', { bubbles: true }));
      otp.dispatchEvent(new Event('change', { bubbles: true }));
      return true;
    })()`
  );
  await evaluate(
    cdp,
    sessionId,
    `(() => { document.querySelector('[data-testid="button-submit-login"]').click(); return true; })()`
  );

  await waitForCondition(
    cdp,
    sessionId,
    `(() => {
      const message = String(document.querySelector('[data-testid="message-global"]')?.textContent || '');
      return message.includes('请稍后重试');
    })()`,
    10000,
    'otp login failure message should follow retry semantics'
  );
  assert.match(
    String(await evaluate(cdp, sessionId, `document.querySelector('[data-testid="message-global"]')?.textContent || ''`)),
    /验证码错误或已失效.*请稍后重试/
  );

  await evaluate(
    cdp,
    sessionId,
    `(() => { document.querySelector('[data-testid="entry-tenant"]').click(); return true; })()`
  );
  await evaluate(
    cdp,
    sessionId,
    `(() => { document.querySelector('[data-testid="mode-password"]').click(); return true; })()`
  );
  await evaluate(
    cdp,
    sessionId,
    `(() => {
      const phone = document.querySelector('[data-testid="input-phone"]');
      const password = document.querySelector('[data-testid="input-password"]');
      const setter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value')?.set;
      setter.call(phone, '13800000005');
      phone.dispatchEvent(new Event('input', { bubbles: true }));
      phone.dispatchEvent(new Event('change', { bubbles: true }));
      setter.call(password, 'Passw0rd!');
      password.dispatchEvent(new Event('input', { bubbles: true }));
      password.dispatchEvent(new Event('change', { bubbles: true }));
      return true;
    })()`
  );
  await evaluate(
    cdp,
    sessionId,
    `(() => { document.querySelector('[data-testid="button-submit-login"]').click(); return true; })()`
  );
  await waitForCondition(
    cdp,
    sessionId,
    `Boolean(document.querySelector('[data-testid="tenant-select"]'))`,
    10000,
    'tenant-entry login should require tenant selection when multiple options exist'
  );
  await evaluate(
    cdp,
    sessionId,
    `(() => {
      const select = document.querySelector('[data-testid="tenant-select"]');
      const setter = Object.getOwnPropertyDescriptor(HTMLSelectElement.prototype, 'value')?.set;
      setter.call(select, 'tenant-101');
      select.dispatchEvent(new Event('change', { bubbles: true }));
      return true;
    })()`
  );
  await evaluate(
    cdp,
    sessionId,
    `(() => { document.querySelector('[data-testid="tenant-select-confirm"]').click(); return true; })()`
  );
  await waitForCondition(
    cdp,
    sessionId,
    `(() => {
      const dashboard = document.querySelector('[data-testid="dashboard-panel"]');
      const text = String(dashboard?.textContent || '');
      const message = String(document.querySelector('[data-testid="message-global"]')?.textContent || '');
      const memberMenu = document.querySelector('[data-testid="menu-member-admin"]');
      const billingMenu = document.querySelector('[data-testid="menu-billing"]');
      const memberBtn = document.querySelector('[data-testid="permission-member-admin-button"]');
      const billingBtn = document.querySelector('[data-testid="permission-billing-button"]');
      return (
        Boolean(dashboard) &&
        text.includes('tenant-101') &&
        message.includes('组织选择成功') &&
        message.includes('请稍后重试') === false &&
        Boolean(memberMenu) &&
        billingMenu === null &&
        Boolean(memberBtn) &&
        memberBtn.disabled === false &&
        billingBtn === null
      );
    })()`,
    10000,
    'tenant select should navigate to dashboard and materialize server-driven tenant-101 permissions'
  );
  await evaluate(
    cdp,
    sessionId,
    `(() => {
      const select = document.querySelector('[data-testid="tenant-switch"]');
      const setter = Object.getOwnPropertyDescriptor(HTMLSelectElement.prototype, 'value')?.set;
      setter.call(select, 'tenant-202');
      select.dispatchEvent(new Event('change', { bubbles: true }));
      return true;
    })()`
  );
  await evaluate(
    cdp,
    sessionId,
    `(() => { document.querySelector('[data-testid="tenant-switch-confirm"]').click(); return true; })()`
  );
  await waitForCondition(
    cdp,
    sessionId,
    `(() => {
      const dashboard = document.querySelector('[data-testid="dashboard-panel"]');
      const text = String(dashboard?.textContent || '');
      const message = String(document.querySelector('[data-testid="message-global"]')?.textContent || '');
      const memberMenu = document.querySelector('[data-testid="menu-member-admin"]');
      const billingMenu = document.querySelector('[data-testid="menu-billing"]');
      const memberBtn = document.querySelector('[data-testid="permission-member-admin-button"]');
      const billingBtn = document.querySelector('[data-testid="permission-billing-button"]');
      return (
        text.includes('tenant-202') &&
        message.includes('请稍后重试') === false &&
        memberMenu === null &&
        Boolean(billingMenu) &&
        memberBtn === null &&
        Boolean(billingBtn) &&
        billingBtn.disabled === false
      );
    })()`,
    10000,
    'tenant switch should recompute visibility and operability according to server-driven tenant-202 permissions'
  );

  const screenshot = await cdp.send('Page.captureScreenshot', { format: 'png' }, sessionId);
  screenshotPath = join(evidenceDir, `chrome-regression-${timestamp}.png`);
  writeFileSync(screenshotPath, Buffer.from(screenshot.data, 'base64'));

  assert.equal(api.requests.some((request) => request.path === '/auth/otp/send'), true);
  assert.equal(api.requests.some((request) => request.path === '/auth/otp/login'), true);
  assert.equal(
    api.requests.some((request) => request.path === '/auth/otp/send' && request.body?.phone === '13800000004'),
    true,
    'cooldown (429) request should have been made'
  );
  const cooldownRateLimitResponse = api.responses.find(
    (response) =>
      response.path === '/auth/otp/send' &&
      response.status === 429 &&
      response.body?.request_id === 'chrome-regression-send-cooldown'
  );
  assert.ok(cooldownRateLimitResponse, 'otp send cooldown response should be 429');
  assert.equal(cooldownRateLimitResponse.headers['retry-after'], '25');
  assert.equal(cooldownRateLimitResponse.headers['x-ratelimit-limit'], '1');
  assert.equal(cooldownRateLimitResponse.headers['x-ratelimit-remaining'], '0');
  assert.equal(cooldownRateLimitResponse.headers['x-ratelimit-reset'], '25');
  assert.equal(cooldownRateLimitResponse.body.rate_limit_action, 'otp_send');
  assert.deepEqual(api.requests.find((request) => request.path === '/auth/otp/send')?.body, {
    phone: '13800000000'
  });
  assert.deepEqual(api.requests.find((request) => request.path === '/auth/otp/login')?.body, {
    phone: '13800000000',
    otp_code: '123456',
    entry_domain: 'platform'
  });
  assert.deepEqual(
    api.requests.find((request) => request.path === '/auth/login' && request.body?.phone === '13800000005')?.body,
    {
      phone: '13800000005',
      password: 'Passw0rd!',
      entry_domain: 'tenant'
    }
  );
  assert.deepEqual(api.requests.find((request) => request.path === '/auth/tenant/select')?.body, {
    tenant_id: 'tenant-101'
  });
  assert.deepEqual(api.requests.find((request) => request.path === '/auth/tenant/switch')?.body, {
    tenant_id: 'tenant-202'
  });
  assert.equal(
    api.responses.filter(
      (response) =>
        response.path === '/auth/tenant/options'
        && response.status === 503
        && response.body?.error_code === 'AUTH-503-TENANT-REFRESH'
    ).length,
    2
  );
  await waitForCondition(
    cdp,
    sessionId,
    `(() => {
      const message = String(document.querySelector('[data-testid="message-global"]')?.textContent || '');
      return message.includes('组织切换成功') && message.includes('组织上下文刷新失败');
    })()`,
    10000,
    'tenant switch refresh failure should surface warning in message (not silently swallowed)'
  );

  const reportPath = join(evidenceDir, `chrome-regression-${timestamp}.json`);
  writeFileSync(
    reportPath,
    JSON.stringify(
      {
        generated_at: new Date().toISOString(),
        web_url: `http://127.0.0.1:${webPort}/`,
        api_stub_url: `http://127.0.0.1:${api.apiPort}`,
        chrome_binary: chromeBinary,
        screenshots: [resolve(screenshotPath)],
        assertions: {
          mode_switch: true,
          entry_domain_switch: true,
          otp_send_countdown_on_success: true,
          otp_send_cooldown_429: true,
          otp_send_rate_limit_headers: true,
          otp_rate_limit_countdown_recovery: true,
          otp_login_failure_semantics: true,
          tenant_selection_flow: true,
          tenant_switch_flow: true,
          tenant_permission_recompute: true
        },
        requests: api.requests
      },
      null,
      2
    )
  );

  if (vite.exitCode !== null) {
    throw new Error(`vite process exited early (${vite.exitCode}): ${viteLogs.stderr || viteLogs.stdout}`);
  }
  if (chrome.exitCode !== null) {
    throw new Error(
      `chrome process exited early (${chrome.exitCode}): ${chromeLogs.stderr || chromeLogs.stdout}`
    );
  }
});

test('chrome regression validates tenant permission UI against real API authorization semantics', async (t) => {
  const chromeBinary = resolveChromeBinary();
  const api = await createRealApiServer();
  const apiBaseUrl = `http://127.0.0.1:${api.apiPort}`;
  const webPort = await reservePort();
  const cdpPort = await reservePort();
  const chromeProfileDir = mkdtempSync(join(tmpdir(), 'neweast-chrome-real-api-profile-'));

  let vite = null;
  let chrome = null;
  let cdp = null;

  const viteLogs = { stdout: '', stderr: '' };
  const chromeLogs = { stdout: '', stderr: '' };

  t.after(async () => {
    await cdp?.close();
    await stopProcess(chrome);
    await stopProcess(vite);
    await api.close();
    rmSync(chromeProfileDir, { recursive: true, force: true });
  });

  vite = spawn(
    'pnpm',
    [
      '--dir',
      'apps/web',
      'exec',
      'vite',
      '--host',
      '127.0.0.1',
      '--port',
      String(webPort),
      '--strictPort',
      '--config',
      'vite.config.js'
    ],
    {
      cwd: WORKSPACE_ROOT,
      env: {
        ...process.env,
        VITE_PROXY_TARGET: apiBaseUrl
      },
      stdio: ['ignore', 'pipe', 'pipe']
    }
  );
  vite.stdout.on('data', (data) => {
    viteLogs.stdout += String(data);
  });
  vite.stderr.on('data', (data) => {
    viteLogs.stderr += String(data);
  });

  await waitForHttp(`http://127.0.0.1:${webPort}/`, 30000, 'vite web server');

  chrome = spawn(
    chromeBinary,
    [
      `--remote-debugging-port=${cdpPort}`,
      `--user-data-dir=${chromeProfileDir}`,
      '--headless=new',
      '--disable-gpu',
      '--disable-dev-shm-usage',
      '--no-first-run',
      '--no-default-browser-check',
      'about:blank'
    ],
    {
      cwd: WORKSPACE_ROOT,
      stdio: ['ignore', 'pipe', 'pipe']
    }
  );
  chrome.stdout.on('data', (data) => {
    chromeLogs.stdout += String(data);
  });
  chrome.stderr.on('data', (data) => {
    chromeLogs.stderr += String(data);
  });

  const version = await (
    await waitForHttp(`http://127.0.0.1:${cdpPort}/json/version`, 20000, 'chrome devtools endpoint')
  ).json();
  cdp = new CdpClient(version.webSocketDebuggerUrl);
  await cdp.connect();

  const { targetId } = await cdp.send('Target.createTarget', { url: 'about:blank' });
  const { sessionId } = await cdp.send('Target.attachToTarget', { targetId, flatten: true });
  await cdp.send('Page.enable', {}, sessionId);
  await cdp.send('Runtime.enable', {}, sessionId);

  await cdp.send('Page.navigate', { url: `http://127.0.0.1:${webPort}/` }, sessionId);
  await waitForCondition(
    cdp,
    sessionId,
    `Boolean(document.querySelector('[data-testid="page-title"]'))`,
    10000,
    'page title should be visible'
  );

  await evaluate(
    cdp,
    sessionId,
    `(() => { document.querySelector('[data-testid="entry-tenant"]').click(); return true; })()`
  );
  await evaluate(
    cdp,
    sessionId,
    `(() => { document.querySelector('[data-testid="mode-password"]').click(); return true; })()`
  );
  await evaluate(
    cdp,
    sessionId,
    `(() => {
      const phone = document.querySelector('[data-testid="input-phone"]');
      const password = document.querySelector('[data-testid="input-password"]');
      const setter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value')?.set;
      setter.call(phone, '${REAL_API_TEST_USER.phone}');
      phone.dispatchEvent(new Event('input', { bubbles: true }));
      phone.dispatchEvent(new Event('change', { bubbles: true }));
      setter.call(password, '${REAL_API_TEST_USER.password}');
      password.dispatchEvent(new Event('input', { bubbles: true }));
      password.dispatchEvent(new Event('change', { bubbles: true }));
      return true;
    })()`
  );
  await evaluate(
    cdp,
    sessionId,
    `(() => { document.querySelector('[data-testid="button-submit-login"]').click(); return true; })()`
  );
  await waitForCondition(
    cdp,
    sessionId,
    `Boolean(document.querySelector('[data-testid="tenant-select"]'))`,
    10000,
    'tenant entry login should require tenant selection'
  );
  await evaluate(
    cdp,
    sessionId,
    `(() => {
      const select = document.querySelector('[data-testid="tenant-select"]');
      const setter = Object.getOwnPropertyDescriptor(HTMLSelectElement.prototype, 'value')?.set;
      setter.call(select, '${REAL_API_TEST_USER.tenantA}');
      select.dispatchEvent(new Event('change', { bubbles: true }));
      return true;
    })()`
  );
  await evaluate(
    cdp,
    sessionId,
    `(() => { document.querySelector('[data-testid="tenant-select-confirm"]').click(); return true; })()`
  );
  await waitForCondition(
    cdp,
    sessionId,
    `(() => {
      const dashboard = document.querySelector('[data-testid="dashboard-panel"]');
      const text = String(dashboard?.textContent || '');
      const memberMenu = document.querySelector('[data-testid="menu-member-admin"]');
      const billingMenu = document.querySelector('[data-testid="menu-billing"]');
      const memberBtn = document.querySelector('[data-testid="permission-member-admin-button"]');
      const billingBtn = document.querySelector('[data-testid="permission-billing-button"]');
      return (
        Boolean(dashboard) &&
        text.includes('${REAL_API_TEST_USER.tenantA}') &&
        Boolean(memberMenu) &&
        billingMenu === null &&
        Boolean(memberBtn) &&
        memberBtn.disabled === false &&
        billingBtn === null
      );
    })()`,
    10000,
    'tenant-a UI permissions should match expected visibility/operability'
  );

  const loginByApi = await requestRealApi({
    baseUrl: apiBaseUrl,
    method: 'POST',
    path: '/auth/login',
    body: {
      phone: REAL_API_TEST_USER.phone,
      password: REAL_API_TEST_USER.password,
      entry_domain: 'tenant'
    }
  });
  assert.equal(loginByApi.status, 200);
  const accessToken = loginByApi.body.access_token;
  assert.equal(typeof accessToken, 'string');

  const selectTenantAByApi = await requestRealApi({
    baseUrl: apiBaseUrl,
    method: 'POST',
    path: '/auth/tenant/select',
    accessToken,
    body: {
      tenant_id: REAL_API_TEST_USER.tenantA
    }
  });
  assert.equal(selectTenantAByApi.status, 200);
  const probeAllowedByApi = await requestRealApi({
    baseUrl: apiBaseUrl,
    method: 'GET',
    path: '/auth/tenant/member-admin/probe',
    accessToken
  });
  assert.equal(probeAllowedByApi.status, 200);
  assert.equal(probeAllowedByApi.body.ok, true);
  assert.equal(typeof probeAllowedByApi.body.request_id, 'string');

  const switchTenantBByApi = await requestRealApi({
    baseUrl: apiBaseUrl,
    method: 'POST',
    path: '/auth/tenant/switch',
    accessToken,
    body: {
      tenant_id: REAL_API_TEST_USER.tenantB
    }
  });
  assert.equal(switchTenantBByApi.status, 200);
  const probeDeniedByApi = await requestRealApi({
    baseUrl: apiBaseUrl,
    method: 'GET',
    path: '/auth/tenant/member-admin/probe',
    accessToken
  });
  assert.equal(probeDeniedByApi.status, 403);
  assert.equal(probeDeniedByApi.body.error_code, 'AUTH-403-FORBIDDEN');

  await evaluate(
    cdp,
    sessionId,
    `(() => {
      const select = document.querySelector('[data-testid="tenant-switch"]');
      const setter = Object.getOwnPropertyDescriptor(HTMLSelectElement.prototype, 'value')?.set;
      setter.call(select, '${REAL_API_TEST_USER.tenantB}');
      select.dispatchEvent(new Event('change', { bubbles: true }));
      return true;
    })()`
  );
  await evaluate(
    cdp,
    sessionId,
    `(() => { document.querySelector('[data-testid="tenant-switch-confirm"]').click(); return true; })()`
  );
  await waitForCondition(
    cdp,
    sessionId,
    `(() => {
      const dashboard = document.querySelector('[data-testid="dashboard-panel"]');
      const text = String(dashboard?.textContent || '');
      const memberMenu = document.querySelector('[data-testid="menu-member-admin"]');
      const billingMenu = document.querySelector('[data-testid="menu-billing"]');
      const memberBtn = document.querySelector('[data-testid="permission-member-admin-button"]');
      const billingBtn = document.querySelector('[data-testid="permission-billing-button"]');
      return (
        Boolean(dashboard) &&
        text.includes('${REAL_API_TEST_USER.tenantB}') &&
        memberMenu === null &&
        Boolean(billingMenu) &&
        memberBtn === null &&
        Boolean(billingBtn) &&
        billingBtn.disabled === false
      );
    })()`,
    10000,
    'tenant-b UI permissions should match expected visibility/operability'
  );

  if (vite.exitCode !== null) {
    throw new Error(`vite process exited early (${vite.exitCode}): ${viteLogs.stderr || viteLogs.stdout}`);
  }
  if (chrome.exitCode !== null) {
    throw new Error(
      `chrome process exited early (${chrome.exitCode}): ${chromeLogs.stderr || chromeLogs.stdout}`
    );
  }
});

test('chrome regression validates platform governance workbench with modal/drawer and permission convergence', async (t) => {
  const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
  const evidenceDir = resolve(WORKSPACE_ROOT, 'artifacts/chrome-platform-governance');
  mkdirSync(evidenceDir, { recursive: true });

  const chromeBinary = resolveChromeBinary();
  const api = await createPlatformGovernanceApiServer();
  const webPort = await reservePort();
  const cdpPort = await reservePort();
  const chromeProfileDir = mkdtempSync(join(tmpdir(), 'neweast-chrome-platform-governance-'));

  let vite = null;
  let chrome = null;
  let cdp = null;
  let screenshotPath = '';

  const viteLogs = { stdout: '', stderr: '' };
  const chromeLogs = { stdout: '', stderr: '' };

  t.after(async () => {
    await cdp?.close();
    await stopProcess(chrome);
    await stopProcess(vite);
    await api.close();
    rmSync(chromeProfileDir, { recursive: true, force: true });
  });

  vite = spawn(
    'pnpm',
    [
      '--dir',
      'apps/web',
      'exec',
      'vite',
      '--host',
      '127.0.0.1',
      '--port',
      String(webPort),
      '--strictPort',
      '--config',
      'vite.config.js'
    ],
    {
      cwd: WORKSPACE_ROOT,
      env: {
        ...process.env,
        VITE_PROXY_TARGET: `http://127.0.0.1:${api.apiPort}`
      },
      stdio: ['ignore', 'pipe', 'pipe']
    }
  );
  vite.stdout.on('data', (data) => {
    viteLogs.stdout += String(data);
  });
  vite.stderr.on('data', (data) => {
    viteLogs.stderr += String(data);
  });

  await waitForHttp(`http://127.0.0.1:${webPort}/`, 30000, 'vite web server');

  chrome = spawn(
    chromeBinary,
    [
      `--remote-debugging-port=${cdpPort}`,
      `--user-data-dir=${chromeProfileDir}`,
      '--headless=new',
      '--disable-gpu',
      '--disable-dev-shm-usage',
      '--no-first-run',
      '--no-default-browser-check',
      'about:blank'
    ],
    {
      cwd: WORKSPACE_ROOT,
      stdio: ['ignore', 'pipe', 'pipe']
    }
  );
  chrome.stdout.on('data', (data) => {
    chromeLogs.stdout += String(data);
  });
  chrome.stderr.on('data', (data) => {
    chromeLogs.stderr += String(data);
  });

  const version = await (
    await waitForHttp(`http://127.0.0.1:${cdpPort}/json/version`, 20000, 'chrome devtools endpoint')
  ).json();
  cdp = new CdpClient(version.webSocketDebuggerUrl);
  await cdp.connect();

  const { targetId } = await cdp.send('Target.createTarget', { url: 'about:blank' });
  const { sessionId } = await cdp.send('Target.attachToTarget', { targetId, flatten: true });
  await cdp.send('Page.enable', {}, sessionId);
  await cdp.send('Runtime.enable', {}, sessionId);

  await cdp.send(
    'Page.navigate',
    { url: `http://127.0.0.1:${webPort}/` },
    sessionId
  );
  await waitForCondition(
    cdp,
    sessionId,
    `Boolean(document.querySelector('[data-testid="page-title"]'))`,
    10000,
    'page title should be visible'
  );

  await evaluate(
    cdp,
    sessionId,
    `(() => {
      const phone = document.querySelector('[data-testid="input-phone"]');
      const password = document.querySelector('[data-testid="input-password"]');
      const setter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value')?.set;
      setter.call(phone, '13800000011');
      phone.dispatchEvent(new Event('input', { bubbles: true }));
      phone.dispatchEvent(new Event('change', { bubbles: true }));
      setter.call(password, 'Passw0rd!');
      password.dispatchEvent(new Event('input', { bubbles: true }));
      password.dispatchEvent(new Event('change', { bubbles: true }));
      return true;
    })()`
  );
  await evaluate(
    cdp,
    sessionId,
    `(() => { document.querySelector('[data-testid="button-submit-login"]').click(); return true; })()`
  );

  await waitForCondition(
    cdp,
    sessionId,
    `Boolean(document.querySelector('[data-testid="platform-governance-panel"]'))`,
    10000,
    'platform governance panel should be visible after platform login'
  );
  await waitForCondition(
    cdp,
    sessionId,
    `Boolean(document.querySelector('[data-testid="platform-user-id-platform-user-1"]'))`,
    10000,
    'platform user table should load initial user list'
  );

  await evaluate(
    cdp,
    sessionId,
    `(() => {
      const input = document.querySelector('[data-testid="platform-user-filter-keyword"]');
      const setter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value')?.set;
      setter.call(input, '000012');
      input.dispatchEvent(new Event('input', { bubbles: true }));
      input.dispatchEvent(new Event('change', { bubbles: true }));
      return true;
    })()`
  );
  await evaluate(
    cdp,
    sessionId,
    `(() => {
      const submit = document.querySelector('[data-testid="platform-users-module"] button[type="submit"]');
      submit?.click();
      return true;
    })()`
  );
  await waitForRequest(
    api.requests,
    (request) => request.path.includes('/platform/users?') && request.path.includes('keyword=000012'),
    8000,
    'platform user list filter request should carry keyword query'
  );

  await evaluate(
    cdp,
    sessionId,
    `(() => { document.querySelector('[data-testid="platform-user-create-open"]').click(); return true; })()`
  );
  await waitForCondition(
    cdp,
    sessionId,
    `Boolean(document.querySelector('[data-testid="platform-user-create-phone"]'))`,
    5000,
    'create user modal should be visible'
  );
  await evaluate(
    cdp,
    sessionId,
    `(() => {
      const input = document.querySelector('[data-testid="platform-user-create-phone"]');
      const setter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value')?.set;
      setter.call(input, '13800000013');
      input.dispatchEvent(new Event('input', { bubbles: true }));
      input.dispatchEvent(new Event('change', { bubbles: true }));
      return true;
    })()`
  );
  await evaluate(
    cdp,
    sessionId,
    `(() => { document.querySelector('[data-testid="platform-user-create-confirm"]').click(); return true; })()`
  );
  await waitForRequest(
    api.requests,
    (request) => request.path === '/platform/users' && request.method === 'POST',
    8000,
    'platform user create request should reach API stub'
  );
  await waitForCondition(
    cdp,
    sessionId,
    `(() => {
      const drawer = document.querySelector('[data-testid="platform-user-detail-drawer"]');
      const text = String(drawer?.textContent || '');
      return (
        Boolean(drawer)
        && text.includes('user_id: platform-user-3')
        && text.includes('latest_action: create')
      );
    })()`,
    10000,
    'newly created platform user detail should be visible in drawer'
  );
  await evaluate(
    cdp,
    sessionId,
    `(() => {
      document.querySelector('.ant-drawer .ant-drawer-close')?.click();
      return true;
    })()`
  );
  await evaluate(
    cdp,
    sessionId,
    `(() => {
      const input = document.querySelector('[data-testid="platform-user-filter-keyword"]');
      const setter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value')?.set;
      setter.call(input, '');
      input.dispatchEvent(new Event('input', { bubbles: true }));
      input.dispatchEvent(new Event('change', { bubbles: true }));
      return true;
    })()`
  );
  await evaluate(
    cdp,
    sessionId,
    `(() => {
      const submit = document.querySelector('[data-testid="platform-users-module"] button[type="submit"]');
      submit?.click();
      return true;
    })()`
  );
  await waitForCondition(
    cdp,
    sessionId,
    `Boolean(document.querySelector('[data-testid="platform-user-status-platform-user-1"]'))`,
    10000,
    'platform user list should include platform-user-1 after clearing filter'
  );

  await evaluate(
    cdp,
    sessionId,
    `(() => { document.querySelector('[data-testid="platform-user-status-platform-user-1"]').click(); return true; })()`
  );
  await waitForCondition(
    cdp,
    sessionId,
    `Boolean(document.querySelector('[data-testid="platform-user-status-reason"]'))`,
    5000,
    'status action modal should be visible'
  );
  await evaluate(
    cdp,
    sessionId,
    `(() => {
      const input = document.querySelector('[data-testid="platform-user-status-reason"]');
      const setter = Object.getOwnPropertyDescriptor(HTMLTextAreaElement.prototype, 'value')?.set;
      setter.call(input, 'manual-governance');
      input.dispatchEvent(new Event('input', { bubbles: true }));
      input.dispatchEvent(new Event('change', { bubbles: true }));
      return true;
    })()`
  );
  await evaluate(
    cdp,
    sessionId,
    `(() => { document.querySelector('[data-testid="platform-user-status-confirm"]').click(); return true; })()`
  );
  await waitForRequest(
    api.requests,
    (request) => request.path === '/platform/users/status' && request.method === 'POST',
    8000,
    'platform user status request should reach API stub'
  );

  await evaluate(
    cdp,
    sessionId,
    `(() => { document.querySelector('[data-testid="platform-user-detail-platform-user-1"]').click(); return true; })()`
  );
  await waitForCondition(
    cdp,
    sessionId,
    `(() => {
      const drawer = document.querySelector('[data-testid="platform-user-detail-drawer"]');
      return Boolean(drawer) && String(drawer.textContent || '').includes('request_id');
    })()`,
    5000,
    'platform user detail drawer should show request_id trace'
  );

  await evaluate(
    cdp,
    sessionId,
    `(() => { document.querySelector('[data-testid="platform-tab-roles"]').click(); return true; })()`
  );
  await waitForCondition(
    cdp,
    sessionId,
    `Boolean(document.querySelector('[data-testid="platform-roles-module"]'))`,
    8000,
    'platform role module should be visible'
  );

  await evaluate(
    cdp,
    sessionId,
    `(() => { document.querySelector('[data-testid="platform-role-create-open"]').click(); return true; })()`
  );
  await waitForCondition(
    cdp,
    sessionId,
    `Boolean(document.querySelector('[data-testid="platform-role-edit-role-id"]'))`,
    5000,
    'role edit modal should be visible'
  );
  await evaluate(
    cdp,
    sessionId,
    `(() => {
      const setter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value')?.set;
      const roleId = document.querySelector('[data-testid="platform-role-edit-role-id"]');
      const code = document.querySelector('[data-testid="platform-role-edit-code"]');
      const name = document.querySelector('[data-testid="platform-role-edit-name"]');
      setter.call(roleId, 'platform_billing_admin');
      roleId.dispatchEvent(new Event('input', { bubbles: true }));
      roleId.dispatchEvent(new Event('change', { bubbles: true }));
      setter.call(code, 'PLATFORM_BILLING_ADMIN');
      code.dispatchEvent(new Event('input', { bubbles: true }));
      code.dispatchEvent(new Event('change', { bubbles: true }));
      setter.call(name, '平台账单治理');
      name.dispatchEvent(new Event('input', { bubbles: true }));
      name.dispatchEvent(new Event('change', { bubbles: true }));
      return true;
    })()`
  );
  await evaluate(
    cdp,
    sessionId,
    `(() => { document.querySelector('[data-testid="platform-role-create-confirm"]').click(); return true; })()`
  );
  await waitForRequest(
    api.requests,
    (request) => request.path === '/platform/roles' && request.method === 'POST',
    8000,
    'platform role create request should reach API stub'
  );

  const protectedEditDisabled = await evaluate(
    cdp,
    sessionId,
    `Boolean(document.querySelector('[data-testid="platform-role-edit-sys_admin"]')?.disabled)`
  );
  assert.equal(
    protectedEditDisabled,
    true,
    'sys_admin edit action should be disabled by protected-role policy'
  );

  await evaluate(
    cdp,
    sessionId,
    `(() => { document.querySelector('[data-testid="platform-role-detail-platform_member_admin"]').click(); return true; })()`
  );
  await waitForCondition(
    cdp,
    sessionId,
    `Boolean(document.querySelector('[data-testid="platform-role-permission-tree"]'))`,
    5000,
    'platform role permission tree should be visible in drawer'
  );
  await evaluate(
    cdp,
    sessionId,
    `(() => { document.querySelector('[data-testid="platform-role-permission-save"]').click(); return true; })()`
  );
  await waitForRequest(
    api.requests,
    (request) =>
      request.method === 'PUT'
      && request.path.includes('/platform/roles/platform_member_admin/permissions'),
    8000,
    'platform role permission save request should reach API stub'
  );

  await evaluate(
    cdp,
    sessionId,
    `(() => {
      const userIdInput = document.querySelector('[data-testid="platform-role-facts-user-id"]');
      const roleIdsInput = document.querySelector('[data-testid="platform-role-facts-role-ids"]');
      const setter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value')?.set;
      setter.call(userIdInput, 'platform-user-1');
      userIdInput.dispatchEvent(new Event('input', { bubbles: true }));
      userIdInput.dispatchEvent(new Event('change', { bubbles: true }));
      setter.call(roleIdsInput, 'platform_member_admin,platform_billing_admin');
      roleIdsInput.dispatchEvent(new Event('input', { bubbles: true }));
      roleIdsInput.dispatchEvent(new Event('change', { bubbles: true }));
      return true;
    })()`
  );
  await evaluate(
    cdp,
    sessionId,
    `(() => { document.querySelector('[data-testid="platform-role-facts-submit"]').click(); return true; })()`
  );
  await waitForRequest(
    api.requests,
    (request) => request.path === '/auth/platform/role-facts/replace' && request.method === 'POST',
    8000,
    'platform role-facts replace request should reach API stub'
  );
  await waitForCondition(
    cdp,
    sessionId,
    `(() => {
      const memberMenu = document.querySelector('[data-testid="platform-menu-member-admin"]');
      const billingMenu = document.querySelector('[data-testid="platform-menu-billing"]');
      const memberAction = document.querySelector('[data-testid="platform-action-member-admin"]');
      const billingAction = document.querySelector('[data-testid="platform-action-billing"]');
      return Boolean(memberMenu) && Boolean(billingMenu) && Boolean(memberAction) && Boolean(billingAction);
    })()`,
    8000,
    'role assignment should converge platform permission context in UI'
  );

  const screenshot = await cdp.send('Page.captureScreenshot', { format: 'png' }, sessionId);
  screenshotPath = join(evidenceDir, `chrome-platform-governance-${timestamp}.png`);
  writeFileSync(screenshotPath, Buffer.from(screenshot.data, 'base64'));

  const loginRequest = api.requests.find((request) => request.path === '/auth/login');
  assert.deepEqual(loginRequest?.body, {
    phone: '13800000011',
    password: 'Passw0rd!',
    entry_domain: 'platform'
  });

  const createUserRequest = api.requests.find(
    (request) => request.path === '/platform/users' && request.method === 'POST'
  );
  assert.equal(createUserRequest?.body?.phone, '13800000013');

  const updateStatusRequest = api.requests.find(
    (request) => request.path === '/platform/users/status' && request.method === 'POST'
  );
  assert.equal(updateStatusRequest?.body?.user_id, 'platform-user-1');
  assert.equal(updateStatusRequest?.body?.status, 'disabled');
  assert.equal(updateStatusRequest?.body?.reason, 'manual-governance');

  const createRoleRequest = api.requests.find(
    (request) => request.path === '/platform/roles' && request.method === 'POST'
  );
  assert.equal(createRoleRequest?.body?.role_id, 'platform_billing_admin');

  const replaceRoleFactsRequest = api.requests.find(
    (request) => request.path === '/auth/platform/role-facts/replace' && request.method === 'POST'
  );
  assert.equal(replaceRoleFactsRequest?.body?.user_id, 'platform-user-1');
  assert.deepEqual(
    replaceRoleFactsRequest?.body?.roles?.map((entry) => entry.role_id).sort(),
    ['platform_billing_admin', 'platform_member_admin']
  );

  const reportPath = join(evidenceDir, `chrome-platform-governance-${timestamp}.json`);
  writeFileSync(
    reportPath,
    JSON.stringify(
      {
        generated_at: new Date().toISOString(),
        web_url: `http://127.0.0.1:${webPort}/`,
        api_stub_url: `http://127.0.0.1:${api.apiPort}`,
        chrome_binary: chromeBinary,
        screenshots: [resolve(screenshotPath)],
        assertions: {
          platform_user_list_filter: true,
          platform_user_create_modal: true,
          platform_user_status_modal: true,
          platform_user_detail_drawer: true,
          platform_role_create_modal: true,
          protected_role_guard: true,
          platform_permission_tree_save: true,
          platform_role_facts_convergence: true
        },
        requests: api.requests,
        responses: api.responses
      },
      null,
      2
    )
  );

  if (vite.exitCode !== null) {
    throw new Error(`vite process exited early (${vite.exitCode}): ${viteLogs.stderr || viteLogs.stdout}`);
  }
  if (chrome.exitCode !== null) {
    throw new Error(
      `chrome process exited early (${chrome.exitCode}): ${chromeLogs.stderr || chromeLogs.stdout}`
    );
  }
});
