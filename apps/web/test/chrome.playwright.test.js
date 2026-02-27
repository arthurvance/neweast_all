const test = require('node:test');
const assert = require('node:assert/strict');
const http = require('node:http');
const net = require('node:net');
const { spawn } = require('node:child_process');
const { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } = require('node:fs');
const { once } = require('node:events');
const { dirname, join, resolve } = require('node:path');
const { tmpdir } = require('node:os');
const { createHash } = require('node:crypto');
const { createApiApp } = require('../../api/src/app');
const { readConfig } = require('../../api/src/config/env');
const { createAuthService } = require('../../api/src/shared-kernel/auth/create-auth-service');

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
const VISUAL_BASELINE_FILE = resolve(
  WORKSPACE_ROOT,
  'apps/web/test/visual-baseline/login-entry-snapshots.json'
);
const SHOULD_UPDATE_VISUAL_BASELINE = process.env.UPDATE_VISUAL_BASELINE === '1';

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

const waitForButtonEnabledByTestId = async (cdp, sessionId, testId, timeoutMs, reason) =>
  waitForCondition(
    cdp,
    sessionId,
    `(() => {
      const button = document.querySelector('[data-testid="${String(testId || '')}"]');
      if (!button) {
        return false;
      }
      if (button.disabled) {
        return false;
      }
      if (button.getAttribute('aria-disabled') === 'true') {
        return false;
      }
      return true;
    })()`,
    timeoutMs,
    reason
  );

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

const PNG_SIGNATURE = Buffer.from([137, 80, 78, 71, 13, 10, 26, 10]);
const readPngDimensions = (buffer) => {
  assert.ok(
    Buffer.isBuffer(buffer) && buffer.length >= 24,
    'PNG buffer is missing or too small'
  );
  assert.equal(
    buffer.subarray(0, PNG_SIGNATURE.length).equals(PNG_SIGNATURE),
    true,
    'Screenshot must be a valid PNG'
  );

  return {
    width: buffer.readUInt32BE(16),
    height: buffer.readUInt32BE(20)
  };
};

const hashOfBuffer = (buffer) => createHash('sha256').update(buffer).digest('hex');

const loadVisualBaseline = () => {
  if (!existsSync(VISUAL_BASELINE_FILE)) {
    return {};
  }
  try {
    const parsed = JSON.parse(readFileSync(VISUAL_BASELINE_FILE, 'utf8'));
    return parsed && typeof parsed === 'object' ? parsed : {};
  } catch (_error) {
    return {};
  }
};

const saveVisualBaseline = (baseline) => {
  mkdirSync(dirname(VISUAL_BASELINE_FILE), { recursive: true });
  writeFileSync(VISUAL_BASELINE_FILE, `${JSON.stringify(baseline, null, 2)}\n`);
};

const assertOrUpdateVisualSnapshot = ({
  snapshotName,
  screenshotBase64,
  baseline,
  nextBaseline
}) => {
  const screenshotBuffer = Buffer.from(screenshotBase64, 'base64');
  const { width, height } = readPngDimensions(screenshotBuffer);
  const current = {
    width,
    height,
    sha256: hashOfBuffer(screenshotBuffer)
  };

  if (SHOULD_UPDATE_VISUAL_BASELINE) {
    nextBaseline[snapshotName] = current;
    return current;
  }

  const expected = baseline[snapshotName];
  assert.ok(
    expected,
    `Missing visual baseline for ${snapshotName}. Run: UPDATE_VISUAL_BASELINE=1 pnpm --dir apps/web smoke`
  );
  assert.equal(current.width, expected.width, `Visual width changed for ${snapshotName}`);
  assert.equal(current.height, expected.height, `Visual height changed for ${snapshotName}`);
  assert.equal(current.sha256, expected.sha256, `Visual snapshot changed for ${snapshotName}`);
  return current;
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
  let failTenantOptionsOnceAfterSwitch = false;
  let activeTenantId = null;
  const tenantPermissionById = {
    'tenant-101': {
      scope_label: '组织权限（Tenant 101）',
      can_view_user_management: true,
      can_operate_user_management: true,
      can_view_role_management: true,
      can_operate_role_management: false,
      can_view_account_management: false,
      can_operate_account_management: false
    },
    'tenant-202': {
      scope_label: '组织权限（Tenant 202）',
      can_view_user_management: false,
      can_operate_user_management: true,
      can_view_role_management: true,
      can_operate_role_management: true,
      can_view_account_management: false,
      can_operate_account_management: false
    }
  };
  const currentTenantPermissionContext = () => {
    if (!activeTenantId) {
      return {
        scope_label: '组织未选择（无可操作权限）',
        can_view_user_management: false,
        can_operate_user_management: false,
        can_view_role_management: false,
        can_operate_role_management: false,
        can_view_account_management: false,
        can_operate_account_management: false
      };
    }
    return tenantPermissionById[activeTenantId] || {
      scope_label: `组织权限（${activeTenantId}）`,
      can_view_user_management: false,
      can_operate_user_management: false,
      can_view_role_management: false,
      can_operate_role_management: false,
      can_view_account_management: false,
      can_operate_account_management: false
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
            platform_permission_context: body.entry_domain === 'tenant'
              ? null
              : {
                scope_label: '平台权限（角色并集）',
                can_view_user_management: true,
                can_operate_user_management: true,
                can_view_tenant_management: true,
                can_operate_tenant_management: true,
                can_view_role_management: true,
                can_operate_role_management: true
              },
            tenant_permission_context: body.entry_domain === 'tenant'
              ? currentTenantPermissionContext()
              : {
                scope_label: '平台入口（无组织侧权限上下文）',
                can_view_user_management: false,
                can_operate_user_management: false,
                can_view_role_management: false,
                can_operate_role_management: false,
                can_view_account_management: false,
                can_operate_account_management: false
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
      if (failTenantOptionsOnceAfterSwitch) {
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

test('chrome visual baselines cover login entry pages', async (t) => {
  const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
  const evidenceDir = resolve(WORKSPACE_ROOT, 'artifacts/chrome-visual-baseline');
  mkdirSync(evidenceDir, { recursive: true });

  const chromeBinary = resolveChromeBinary();
  const webPort = await reservePort();
  const cdpPort = await reservePort();
  const chromeProfileDir = mkdtempSync(join(tmpdir(), 'neweast-chrome-visual-baseline-'));
  const visualEvidence = {};

  let vite = null;
  let chrome = null;
  let cdp = null;
  const viteLogs = { stdout: '', stderr: '' };
  const chromeLogs = { stdout: '', stderr: '' };

  t.after(async () => {
    await cdp?.close();
    await stopProcess(chrome);
    await stopProcess(vite);
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
        VITE_PROXY_TARGET: 'http://127.0.0.1:9'
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
    'Emulation.setDeviceMetricsOverride',
    {
      width: 1280,
      height: 900,
      deviceScaleFactor: 1,
      mobile: false
    },
    sessionId
  );

  const snapshots = [
    { name: 'login-default-root', url: `http://127.0.0.1:${webPort}/` },
    { name: 'login-platform-explicit', url: `http://127.0.0.1:${webPort}/login/platform` },
    { name: 'login-tenant-explicit', url: `http://127.0.0.1:${webPort}/login/tenant` }
  ];

  const baseline = loadVisualBaseline();
  const nextBaseline = { ...baseline };

  for (const snapshot of snapshots) {
    await cdp.send('Page.navigate', { url: snapshot.url }, sessionId);
    await waitForCondition(
      cdp,
      sessionId,
      `Boolean(document.querySelector('[data-testid="page-title"]'))`,
      10000,
      `${snapshot.name} page title should be visible`
    );
    await evaluate(
      cdp,
      sessionId,
      `(() => {
        const globalMessage = document.querySelector('[data-testid="message-global"]');
        if (globalMessage) {
          globalMessage.remove();
        }
        return true;
      })()`
    );

    const screenshot = await cdp.send('Page.captureScreenshot', { format: 'png' }, sessionId);
    const screenshotPath = join(evidenceDir, `${snapshot.name}-${timestamp}.png`);
    writeFileSync(screenshotPath, Buffer.from(screenshot.data, 'base64'));
    const metrics = assertOrUpdateVisualSnapshot({
      snapshotName: snapshot.name,
      screenshotBase64: screenshot.data,
      baseline,
      nextBaseline
    });
    visualEvidence[snapshot.name] = {
      file: resolve(screenshotPath),
      width: metrics.width,
      height: metrics.height,
      sha256: metrics.sha256
    };
  }

  if (SHOULD_UPDATE_VISUAL_BASELINE) {
    saveVisualBaseline(nextBaseline);
  }

  const reportPath = join(evidenceDir, `chrome-visual-baseline-${timestamp}.json`);
  writeFileSync(
    reportPath,
    JSON.stringify(
      {
        generated_at: new Date().toISOString(),
        web_url: `http://127.0.0.1:${webPort}/`,
        baseline_file: VISUAL_BASELINE_FILE,
        update_mode: SHOULD_UPDATE_VISUAL_BASELINE,
        snapshots: visualEvidence
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

const createPlatformGovernanceApiServer = async () => {
  const requests = [];
  const responses = [];
  const permissionCatalog = [
    'platform.user_management.view',
    'platform.user_management.operate',
    'platform.tenant_management.view',
    'platform.tenant_management.operate',
    'platform.role_management.view',
    'platform.role_management.operate'
  ];

  let nextUserId = 3;
  let nextRoleId = 3;
  const users = new Map([
    [
      'platform-user-1',
      {
        user_id: 'platform-user-1',
        phone: '13800000011',
        name: '平台管理员甲',
        department: '平台治理',
        role_ids: ['platform_user_management'],
        status: 'active',
        created_at: new Date().toISOString(),
        deleted: false
      }
    ],
    [
      'platform-user-2',
      {
        user_id: 'platform-user-2',
        phone: '13800000012',
        name: '平台管理员乙',
        department: null,
        role_ids: [],
        status: 'disabled',
        created_at: new Date().toISOString(),
        deleted: false
      }
    ]
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
      'platform_user_management',
      {
        role_id: 'platform_user_management',
        code: 'PLATFORM_USER_MANAGEMENT',
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
    ['platform_user_management', ['platform.user_management.view', 'platform.user_management.operate']]
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
      can_view_user_management: permissionSet.has('platform.user_management.view'),
      can_operate_user_management: permissionSet.has('platform.user_management.operate'),
      can_view_tenant_management: permissionSet.has('platform.tenant_management.view'),
      can_operate_tenant_management: permissionSet.has('platform.tenant_management.operate'),
      can_view_role_management: permissionSet.has('platform.role_management.view'),
      can_operate_role_management: permissionSet.has('platform.role_management.operate')
    };
  };
  const toRoleReadModel = (roleId) => {
    const normalizedRoleId = String(roleId || '').trim().toLowerCase();
    if (!normalizedRoleId) {
      return null;
    }
    const roleRecord = roles.get(normalizedRoleId);
    if (!roleRecord) {
      return null;
    }
    return {
      role_id: normalizedRoleId,
      code: roleRecord.code,
      name: roleRecord.name,
      status: roleRecord.status
    };
  };
  const toUserReadModel = (user) => ({
    user_id: user.user_id,
    phone: user.phone,
    name: user.name || null,
    department: user.department || null,
    roles: (Array.isArray(user.role_ids) ? user.role_ids : [])
      .map((roleId) => toRoleReadModel(roleId))
      .filter(Boolean),
    status: user.status,
    created_at: user.created_at || new Date().toISOString()
  });

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
      const displayUserName = String(users.get('platform-user-1')?.name || '').trim() || null;
      sendJson({
        status: 200,
        contentType: 'application/json',
        payload: {
          token_type: 'Bearer',
          access_token: 'platform-management-access-token',
          refresh_token: 'platform-management-refresh-token',
          expires_in: 900,
          refresh_expires_in: 1209600,
          session_id: 'platform-management-session',
          entry_domain: body.entry_domain || 'platform',
          active_tenant_id: null,
          tenant_selection_required: false,
          tenant_options: [],
          user_name: displayUserName,
          platform_permission_context: {
            scope_label: '平台权限（角色并集）',
            can_view_user_management: true,
            can_operate_user_management: true,
            can_view_tenant_management: true,
            can_operate_tenant_management: true,
            can_view_role_management: true,
            can_operate_role_management: true
          },
          tenant_permission_context: null,
          request_id: requestId
        }
      });
      return;
    }

    if (method === 'GET' && pathname === '/auth/platform/options') {
      const currentSessionUser = users.get('platform-user-1') || null;
      const displayUserName = String(currentSessionUser?.name || '').trim() || null;
      sendJson({
        status: 200,
        contentType: 'application/json',
        payload: {
          session_id: 'platform-management-session',
          entry_domain: 'platform',
          active_tenant_id: null,
          user_name: displayUserName,
          platform_permission_context: {
            scope_label: '平台权限（角色并集）',
            can_view_user_management: true,
            can_operate_user_management: true,
            can_view_tenant_management: true,
            can_operate_tenant_management: true,
            can_view_role_management: true,
            can_operate_role_management: true
          },
          request_id: requestId
        }
      });
      return;
    }

    if (method === 'GET' && pathname === '/platform/users') {
      const page = Number(url.searchParams.get('page') || 1);
      const pageSize = Number(url.searchParams.get('page_size') || 20);
      const statusFilter = String(url.searchParams.get('status') || '').trim().toLowerCase();
      const phoneFilter = String(url.searchParams.get('phone') || '').trim();
      const nameFilter = String(url.searchParams.get('name') || '').trim().toLowerCase();
      const listedUsers = [...users.values()].filter((user) => !user.deleted);
      const filteredUsers = listedUsers.filter((user) => {
        if (statusFilter && user.status !== statusFilter) {
          return false;
        }
        if (phoneFilter && user.phone !== phoneFilter) {
          return false;
        }
        if (nameFilter) {
          return String(user.name || '').toLowerCase().includes(nameFilter);
        }
        return true;
      });
      const offset = (Math.max(1, page) - 1) * Math.max(1, pageSize);
      const pageItems = filteredUsers.slice(offset, offset + Math.max(1, pageSize));
      sendJson({
        status: 200,
        contentType: 'application/json',
        payload: {
          items: pageItems.map((user) => toUserReadModel(user)),
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
      const name = String(body.name || '').trim();
      const department = String(body.department || '').trim() || null;
      const requestedRoleIds = [...new Set(
        (Array.isArray(body.role_ids) ? body.role_ids : [])
          .map((roleId) => String(roleId || '').trim().toLowerCase())
          .filter(Boolean)
      )];
      const hasInvalidRoleId = requestedRoleIds.some((roleId) => {
        const roleRecord = roles.get(roleId);
        return !roleRecord || roleRecord.status !== 'active';
      });
      if (
        !/^1\d{10}$/.test(phone)
        || !name
        || hasInvalidRoleId
      ) {
        sendProblem({
          status: 400,
          detail: '请求参数不完整或格式错误',
          errorCode: 'USR-400-INVALID-PAYLOAD'
        });
        return;
      }
      const userId = `platform-user-${nextUserId++}`;
      users.set(userId, {
        user_id: userId,
        phone,
        name,
        department,
        role_ids: requestedRoleIds,
        status: 'active',
        created_at: new Date().toISOString(),
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
          ...toUserReadModel(target),
          request_id: requestId
        }
      });
      return;
    }

    if (userDetailMatch && method === 'PATCH') {
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
      const name = String(body.name || '').trim();
      const department = String(body.department || '').trim() || null;
      const hasRoleIds = Object.prototype.hasOwnProperty.call(body, 'role_ids');
      const requestedRoleIds = hasRoleIds
        ? [...new Set(
          (Array.isArray(body.role_ids) ? body.role_ids : [])
            .map((roleId) => String(roleId || '').trim().toLowerCase())
            .filter(Boolean)
        )]
        : [];
      const hasInvalidRoleId = hasRoleIds
        && requestedRoleIds.some((roleId) => {
          const roleRecord = roles.get(roleId);
          return !roleRecord || roleRecord.status !== 'active';
        });
      if (
        !name
        || hasInvalidRoleId
      ) {
        sendProblem({
          status: 400,
          detail: '请求参数不完整或格式错误',
          errorCode: 'USR-400-INVALID-PAYLOAD'
        });
        return;
      }
      users.set(userId, {
        ...target,
        name,
        department,
        role_ids: hasRoleIds ? requestedRoleIds : target.role_ids
      });
      sendJson({
        status: 200,
        contentType: 'application/json',
        payload: {
          ...toUserReadModel(users.get(userId)),
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
      const roleCode = String(body.code || '').trim();
      const roleName = String(body.name || '').trim();
      if (!roleCode || !roleName) {
        sendProblem({
          status: 400,
          detail: '请求参数不完整或格式错误',
          errorCode: 'ROLE-400-INVALID-PAYLOAD'
        });
        return;
      }
      const normalizedRoleIdBase = roleCode
        .toLowerCase()
        .replace(/[^a-z0-9._-]+/g, '_')
        .replace(/^_+|_+$/g, '');
      let roleId = normalizedRoleIdBase || `platform_role_${nextRoleId}`;
      let roleIdSuffix = 1;
      while (roles.has(roleId)) {
        roleId = `${normalizedRoleIdBase || `platform_role_${nextRoleId}`}_${roleIdSuffix++}`;
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
        code: roleCode,
        name: roleName,
        status: 'active',
        is_system: false,
        created_at: now,
        updated_at: now
      };
      nextRoleId += 1;
      roles.set(roleId, createdRole);
      rolePermissions.set(
        roleId,
        roleId.includes('tenant_management')
          ? ['platform.tenant_management.view', 'platform.tenant_management.operate']
          : ['platform.user_management.view']
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

const createTenantManagementApiServer = async () => {
  const requests = [];
  const responses = [];
  const tenantOptions = [
    { tenant_id: 'tenant-101', tenant_name: 'Tenant 101' },
    { tenant_id: 'tenant-202', tenant_name: 'Tenant 202' }
  ];
  const permissionCatalog = [
    'tenant.user_management.view',
    'tenant.user_management.operate',
    'tenant.role_management.view',
    'tenant.role_management.operate',
    'tenant.account_management.view',
    'tenant.account_management.operate',
    'tenant.customer_management.view',
    'tenant.customer_management.operate',
    'tenant.customer_scope_my.view',
    'tenant.customer_scope_assist.view',
    'tenant.customer_scope_all.view'
  ];
  const protectedRoleIds = new Set(['tenant_owner', 'tenant_admin', 'tenant_member']);
  const sessionMembershipByTenantId = {
    'tenant-101': 'membership-tenant-101-admin',
    'tenant-202': 'membership-tenant-202-admin'
  };

  let activeTenantId = null;
  let nextMemberId = 3;
  let nextRoleSequence = 3;
  let nextAccountSequence = 3;
  let nextCustomerSequence = 3;

  const membersByTenantId = new Map([
    [
      'tenant-101',
      new Map([
        [
          'membership-tenant-101-admin',
          {
            membership_id: 'membership-tenant-101-admin',
            user_id: 'tenant-user-admin',
            tenant_id: 'tenant-101',
            tenant_name: 'Tenant 101',
            phone: '13800000021',
            status: 'active',
            display_name: '组织管理员',
            department_name: '运营',
            joined_at: new Date().toISOString(),
            left_at: null
          }
        ],
        [
          'membership-tenant-101-member',
          {
            membership_id: 'membership-tenant-101-member',
            user_id: 'tenant-user-02',
            tenant_id: 'tenant-101',
            tenant_name: 'Tenant 101',
            phone: '13800000022',
            status: 'active',
            display_name: '成员乙',
            department_name: '产品',
            joined_at: new Date().toISOString(),
            left_at: null
          }
        ]
      ])
    ],
    [
      'tenant-202',
      new Map([
        [
          'membership-tenant-202-admin',
          {
            membership_id: 'membership-tenant-202-admin',
            user_id: 'tenant-user-admin',
            tenant_id: 'tenant-202',
            tenant_name: 'Tenant 202',
            phone: '13800000021',
            status: 'active',
            display_name: '组织管理员',
            department_name: '运营',
            joined_at: new Date().toISOString(),
            left_at: null
          }
        ]
      ])
    ]
  ]);
  const rolesByTenantId = new Map([
    [
      'tenant-101',
      new Map([
        [
          'tenant_owner',
          {
            role_id: 'tenant_owner',
            tenant_id: 'tenant-101',
            code: 'TENANT_OWNER',
            name: '组织负责人',
            status: 'active',
            is_system: true,
            created_at: new Date().toISOString(),
            updated_at: new Date().toISOString()
          }
        ],
        [
          'tenant_user_management',
          {
            role_id: 'tenant_user_management',
            tenant_id: 'tenant-101',
            code: 'TENANT_USER_MANAGEMENT',
            name: '组织成员治理',
            status: 'active',
            is_system: false,
            created_at: new Date().toISOString(),
            updated_at: new Date().toISOString()
          }
        ],
        [
          'tenant_role_management_admin',
          {
            role_id: 'tenant_role_management_admin',
            tenant_id: 'tenant-101',
            code: 'TENANT_ROLE_MANAGEMENT_ADMIN',
            name: '组织角色治理',
            status: 'active',
            is_system: false,
            created_at: new Date().toISOString(),
            updated_at: new Date().toISOString()
          }
        ]
      ])
    ],
    [
      'tenant-202',
      new Map([
        [
          'tenant_owner',
          {
            role_id: 'tenant_owner',
            tenant_id: 'tenant-202',
            code: 'TENANT_OWNER',
            name: '组织负责人',
            status: 'active',
            is_system: true,
            created_at: new Date().toISOString(),
            updated_at: new Date().toISOString()
          }
        ],
        [
          'tenant_member',
          {
            role_id: 'tenant_member',
            tenant_id: 'tenant-202',
            code: 'TENANT_MEMBER',
            name: '组织成员',
            status: 'active',
            is_system: true,
            created_at: new Date().toISOString(),
            updated_at: new Date().toISOString()
          }
        ]
      ])
    ]
  ]);
  const rolePermissionsByTenantId = new Map([
    [
      'tenant-101',
      new Map([
        ['tenant_owner', [...permissionCatalog]],
        [
          'tenant_user_management',
          [
            'tenant.user_management.view',
            'tenant.user_management.operate'
          ]
        ],
        [
          'tenant_role_management_admin',
          [
            'tenant.role_management.view',
            'tenant.role_management.operate',
            'tenant.account_management.view',
            'tenant.account_management.operate',
            'tenant.customer_management.view',
            'tenant.customer_management.operate',
            'tenant.customer_scope_my.view',
            'tenant.customer_scope_assist.view',
            'tenant.customer_scope_all.view'
          ]
        ]
      ])
    ],
    [
      'tenant-202',
      new Map([
        ['tenant_owner', [...permissionCatalog]],
        ['tenant_member', ['tenant.role_management.view']]
      ])
    ]
  ]);
  const memberRoleBindingsByTenantId = new Map([
    [
      'tenant-101',
      new Map([
        ['membership-tenant-101-admin', ['tenant_user_management']],
        ['membership-tenant-101-member', ['tenant_user_management']]
      ])
    ],
    [
      'tenant-202',
      new Map([
        ['membership-tenant-202-admin', ['tenant_member']]
      ])
    ]
  ]);
  const accountsByTenantId = new Map([
    [
      'tenant-101',
      new Map([
        [
          'account-tenant-101-1',
          {
            account_id: 'account-tenant-101-1',
            tenant_id: 'tenant-101',
            wechat_id: 'wx_tenant_101_admin',
            nickname: '管理员主号',
            avatar_url: '',
            owner_membership_id: 'membership-tenant-101-admin',
            owner_name: '组织管理员',
            assistant_membership_ids: ['membership-tenant-101-member'],
            assistant_names: ['成员乙'],
            customer_count: 12,
            group_chat_count: 4,
            status: 'active',
            created_at: new Date().toISOString(),
            updated_at: new Date().toISOString()
          }
        ],
        [
          'account-tenant-101-2',
          {
            account_id: 'account-tenant-101-2',
            tenant_id: 'tenant-101',
            wechat_id: 'wx_tenant_101_sales',
            nickname: '销售号',
            avatar_url: '',
            owner_membership_id: 'membership-tenant-101-member',
            owner_name: '成员乙',
            assistant_membership_ids: ['membership-tenant-101-admin'],
            assistant_names: ['组织管理员'],
            customer_count: 8,
            group_chat_count: 2,
            status: 'disabled',
            created_at: new Date().toISOString(),
            updated_at: new Date().toISOString()
          }
        ]
      ])
    ],
    [
      'tenant-202',
      new Map([
        [
          'account-tenant-202-1',
          {
            account_id: 'account-tenant-202-1',
            tenant_id: 'tenant-202',
            wechat_id: 'wx_tenant_202_admin',
            nickname: '租户202主号',
            avatar_url: '',
            owner_membership_id: 'membership-tenant-202-admin',
            owner_name: '组织管理员',
            assistant_membership_ids: [],
            assistant_names: [],
            customer_count: 5,
            group_chat_count: 1,
            status: 'active',
            created_at: new Date().toISOString(),
            updated_at: new Date().toISOString()
          }
        ]
      ])
    ]
  ]);
  const accountOperationLogsByTenantId = new Map([
    [
      'tenant-101',
      new Map([
        [
          'account-tenant-101-1',
          [
            {
              operation_type: '新建账号',
              operated_at: new Date().toISOString(),
              operator_name: '系统',
              content: '初始化账号'
            }
          ]
        ],
        [
          'account-tenant-101-2',
          [
            {
              operation_type: '新建账号',
              operated_at: new Date().toISOString(),
              operator_name: '系统',
              content: '初始化账号'
            }
          ]
        ]
      ])
    ],
    [
      'tenant-202',
      new Map([
        [
          'account-tenant-202-1',
          [
            {
              operation_type: '新建账号',
              operated_at: new Date().toISOString(),
              operator_name: '系统',
              content: '初始化账号'
            }
          ]
        ]
      ])
    ]
  ]);
  const customersByTenantId = new Map([
    [
      'tenant-101',
      new Map([
        [
          'customer-tenant-101-1',
          {
            customer_id: 'customer-tenant-101-1',
            tenant_id: 'tenant-101',
            account_id: 'account-tenant-101-1',
            account_wechat_id: 'wx_tenant_101_admin',
            account_nickname: '管理员主号',
            wechat_id: 'wx_customer_101_primary',
            nickname: '客户甲',
            source: 'ground',
            school: '第一中学',
            class_name: '高二(1)班',
            real_name: '张三',
            relation: '家长',
            phone: '13900000001',
            address: '浦东新区',
            status: 'enabled',
            created_by_name: '系统',
            created_at: new Date().toISOString(),
            updated_at: new Date().toISOString()
          }
        ],
        [
          'customer-tenant-101-2',
          {
            customer_id: 'customer-tenant-101-2',
            tenant_id: 'tenant-101',
            account_id: 'account-tenant-101-2',
            account_wechat_id: 'wx_tenant_101_sales',
            account_nickname: '销售号',
            wechat_id: 'wx_customer_101_assist',
            nickname: '客户乙',
            source: 'fission',
            school: '第二中学',
            class_name: '高一(3)班',
            real_name: '李四',
            relation: '学生',
            phone: '13900000002',
            address: '海淀区',
            status: 'enabled',
            created_by_name: '系统',
            created_at: new Date().toISOString(),
            updated_at: new Date().toISOString()
          }
        ]
      ])
    ],
    [
      'tenant-202',
      new Map([
        [
          'customer-tenant-202-1',
          {
            customer_id: 'customer-tenant-202-1',
            tenant_id: 'tenant-202',
            account_id: 'account-tenant-202-1',
            account_wechat_id: 'wx_tenant_202_admin',
            account_nickname: '租户202主号',
            wechat_id: 'wx_customer_202_primary',
            nickname: '客户丙',
            source: 'other',
            school: '',
            class_name: '',
            real_name: '',
            relation: '',
            phone: '',
            address: '',
            status: 'enabled',
            created_by_name: '系统',
            created_at: new Date().toISOString(),
            updated_at: new Date().toISOString()
          }
        ]
      ])
    ]
  ]);
  const customerOperationLogsByTenantId = new Map([
    [
      'tenant-101',
      new Map([
        [
          'customer-tenant-101-1',
          [
            {
              operation_type: 'create',
              operated_at: new Date().toISOString(),
              operator_name: '系统',
              content: '初始化客户'
            }
          ]
        ],
        [
          'customer-tenant-101-2',
          [
            {
              operation_type: 'create',
              operated_at: new Date().toISOString(),
              operator_name: '系统',
              content: '初始化客户'
            }
          ]
        ]
      ])
    ],
    [
      'tenant-202',
      new Map([
        [
          'customer-tenant-202-1',
          [
            {
              operation_type: 'create',
              operated_at: new Date().toISOString(),
              operator_name: '系统',
              content: '初始化客户'
            }
          ]
        ]
      ])
    ]
  ]);
  const tenant101Members = membersByTenantId.get('tenant-101');
  const tenant101Bindings = memberRoleBindingsByTenantId.get('tenant-101');
  if (tenant101Members && tenant101Bindings) {
    for (let index = 1; index <= 9; index += 1) {
      const membershipId = `membership-tenant-101-extra-${index}`;
      const userId = `tenant-user-extra-${index}`;
      tenant101Members.set(membershipId, {
        membership_id: membershipId,
        user_id: userId,
        tenant_id: 'tenant-101',
        tenant_name: 'Tenant 101',
        phone: `138000001${String(index).padStart(2, '0')}`,
        status: 'active',
        display_name: `成员补充${index}`,
        department_name: '运营',
        joined_at: new Date().toISOString(),
        left_at: null
      });
      tenant101Bindings.set(membershipId, ['tenant_user_management']);
    }
  }

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

  const normalizeRoleIds = (rawRoleIds = []) => {
    const deduped = new Set();
    for (const roleId of Array.isArray(rawRoleIds) ? rawRoleIds : []) {
      const normalizedRoleId = String(roleId || '').trim().toLowerCase();
      if (normalizedRoleId) {
        deduped.add(normalizedRoleId);
      }
    }
    return [...deduped];
  };

  const normalizeCustomerSource = (source) => {
    const normalizedSource = String(source || '').trim().toLowerCase();
    if (normalizedSource === 'ground' || normalizedSource === '地推' || normalizedSource === '地堆') {
      return 'ground';
    }
    if (normalizedSource === 'fission' || normalizedSource === '裂变') {
      return 'fission';
    }
    if (normalizedSource === 'other' || normalizedSource === '其它' || normalizedSource === '其他') {
      return 'other';
    }
    return '';
  };

  const normalizeCustomerStatus = (status) => {
    const normalizedStatus = String(status || '').trim().toLowerCase();
    if (normalizedStatus === 'active' || normalizedStatus === 'enabled') {
      return 'enabled';
    }
    if (normalizedStatus === 'inactive' || normalizedStatus === 'disabled') {
      return 'disabled';
    }
    return '';
  };

  const parseCsvList = (value) =>
    [...new Set(
      String(value || '')
        .split(',')
        .map((item) => String(item || '').trim())
        .filter(Boolean)
    )];

  const ensureTenantMaps = (tenantId) => {
    if (!membersByTenantId.has(tenantId)) {
      membersByTenantId.set(tenantId, new Map());
    }
    if (!rolesByTenantId.has(tenantId)) {
      rolesByTenantId.set(tenantId, new Map());
    }
    if (!rolePermissionsByTenantId.has(tenantId)) {
      rolePermissionsByTenantId.set(tenantId, new Map());
    }
    if (!memberRoleBindingsByTenantId.has(tenantId)) {
      memberRoleBindingsByTenantId.set(tenantId, new Map());
    }
    if (!accountsByTenantId.has(tenantId)) {
      accountsByTenantId.set(tenantId, new Map());
    }
    if (!accountOperationLogsByTenantId.has(tenantId)) {
      accountOperationLogsByTenantId.set(tenantId, new Map());
    }
    if (!customersByTenantId.has(tenantId)) {
      customersByTenantId.set(tenantId, new Map());
    }
    if (!customerOperationLogsByTenantId.has(tenantId)) {
      customerOperationLogsByTenantId.set(tenantId, new Map());
    }
  };

  const getCurrentTenantMaps = () => {
    const tenantId = String(activeTenantId || '').trim();
    ensureTenantMaps(tenantId);
    return {
      tenantId,
      members: membersByTenantId.get(tenantId),
      roles: rolesByTenantId.get(tenantId),
      rolePermissions: rolePermissionsByTenantId.get(tenantId),
      memberRoleBindings: memberRoleBindingsByTenantId.get(tenantId),
      accounts: accountsByTenantId.get(tenantId),
      accountOperationLogs: accountOperationLogsByTenantId.get(tenantId),
      customers: customersByTenantId.get(tenantId),
      customerOperationLogs: customerOperationLogsByTenantId.get(tenantId)
    };
  };

  const buildTenantPermissionContext = () => {
    if (!activeTenantId) {
      return {
        scope_label: '组织未选择（无可操作权限）',
        can_view_user_management: false,
        can_operate_user_management: false,
        can_view_role_management: false,
        can_operate_role_management: false,
        can_view_account_management: false,
        can_operate_account_management: false,
        can_view_customer_management: false,
        can_operate_customer_management: false,
        can_view_customer_scope_my: false,
        can_view_customer_scope_assist: false,
        can_view_customer_scope_all: false
      };
    }
    const { tenantId, rolePermissions, memberRoleBindings } = getCurrentTenantMaps();
    const sessionMembershipId = sessionMembershipByTenantId[tenantId];
    const roleIds = memberRoleBindings.get(sessionMembershipId) || [];
    const permissionSet = new Set();
    for (const roleId of roleIds) {
      const grants = rolePermissions.get(roleId) || [];
      for (const permissionCode of grants) {
        permissionSet.add(permissionCode);
      }
    }
    return {
      scope_label: `组织权限（${tenantId}）`,
      can_view_user_management: permissionSet.has('tenant.user_management.view'),
      can_operate_user_management: permissionSet.has('tenant.user_management.operate'),
      can_view_role_management: permissionSet.has('tenant.role_management.view'),
      can_operate_role_management: permissionSet.has('tenant.role_management.operate'),
      can_view_account_management: permissionSet.has('tenant.account_management.view'),
      can_operate_account_management: permissionSet.has('tenant.account_management.operate'),
      can_view_customer_management: permissionSet.has('tenant.customer_management.view'),
      can_operate_customer_management: permissionSet.has('tenant.customer_management.operate'),
      can_view_customer_scope_my: permissionSet.has('tenant.customer_scope_my.view'),
      can_view_customer_scope_assist: permissionSet.has('tenant.customer_scope_assist.view'),
      can_view_customer_scope_all: permissionSet.has('tenant.customer_scope_all.view')
    };
  };

  const server = http.createServer(async (req, res) => {
    const method = req.method || 'GET';
    const url = new URL(req.url || '/', 'http://127.0.0.1');
    const pathname = url.pathname;
    const body = await readRequestBody(req);
    const requestId = String(req.headers['x-request-id'] || `req-tenant-ui-${Date.now()}`);

    requests.push({
      method,
      path: req.url || '/',
      headers: {
        ...req.headers
      },
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
      errorCode = 'AUTH-400-INVALID-PAYLOAD',
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

    const ensureTenantSelected = () => {
      if (activeTenantId) {
        return true;
      }
      sendProblem({
        status: 403,
        title: 'Forbidden',
        detail: '当前入口无可用访问域权限',
        errorCode: 'AUTH-403-NO-DOMAIN'
      });
      return false;
    };

    if (method === 'POST' && pathname === '/auth/login') {
      if (body.phone === '13800000021' && body.password === 'Passw0rd!') {
        const isTenantDomain = String(body.entry_domain || 'platform') === 'tenant';
        sendJson({
          status: 200,
          contentType: 'application/json',
          payload: {
            token_type: 'Bearer',
            access_token: 'tenant-management-access-token',
            refresh_token: 'tenant-management-refresh-token',
            expires_in: 900,
            refresh_expires_in: 1209600,
            session_id: 'tenant-management-session',
            entry_domain: isTenantDomain ? 'tenant' : 'platform',
            active_tenant_id: isTenantDomain ? activeTenantId : null,
            tenant_selection_required: isTenantDomain ? activeTenantId === null : false,
            tenant_options: isTenantDomain ? tenantOptions : [],
            platform_permission_context: isTenantDomain
              ? null
              : {
                scope_label: '平台权限（角色并集）',
                can_view_user_management: true,
                can_operate_user_management: true,
                can_view_tenant_management: true,
                can_operate_tenant_management: true,
                can_view_role_management: true,
                can_operate_role_management: true
              },
            tenant_permission_context: isTenantDomain
              ? buildTenantPermissionContext()
              : null,
            request_id: requestId
          }
        });
        return;
      }

      sendProblem({
        status: 401,
        title: 'Unauthorized',
        detail: '手机号或密码错误',
        errorCode: 'AUTH-401-LOGIN-FAILED'
      });
      return;
    }

    if (method === 'GET' && pathname === '/auth/tenant/options') {
      sendJson({
        status: 200,
        contentType: 'application/json',
        payload: {
          session_id: 'tenant-management-session',
          entry_domain: 'tenant',
          active_tenant_id: activeTenantId,
          tenant_selection_required: activeTenantId === null,
          tenant_options: tenantOptions,
          tenant_permission_context: buildTenantPermissionContext(),
          request_id: requestId
        }
      });
      return;
    }

    if (method === 'POST' && pathname === '/auth/tenant/switch') {
      const tenantId = String(body.tenant_id || '').trim();
      if (!tenantOptions.some((option) => option.tenant_id === tenantId)) {
        sendProblem({
          status: 403,
          title: 'Forbidden',
          detail: '当前入口无可用访问域权限',
          errorCode: 'AUTH-403-NO-DOMAIN'
        });
        return;
      }
      activeTenantId = tenantId;
      sendJson({
        status: 200,
        contentType: 'application/json',
        payload: {
          session_id: 'tenant-management-session',
          entry_domain: 'tenant',
          active_tenant_id: activeTenantId,
          tenant_selection_required: false,
          tenant_options: tenantOptions,
          tenant_permission_context: buildTenantPermissionContext(),
          request_id: requestId
        }
      });
      return;
    }

    if (!ensureTenantSelected()) {
      return;
    }
    const {
      tenantId,
      members,
      roles,
      rolePermissions,
      memberRoleBindings,
      accounts,
      accountOperationLogs,
      customers,
      customerOperationLogs
    } = getCurrentTenantMaps();
    const tenantPermissionContext = buildTenantPermissionContext();
    const sessionMembershipId = String(sessionMembershipByTenantId[tenantId] || '').trim();

    if (method === 'GET' && pathname === '/tenant/users') {
      const page = Number(url.searchParams.get('page') || 1);
      const pageSize = Number(url.searchParams.get('page_size') || 20);
      const listedMembers = [...members.values()];
      const offset = (Math.max(1, page) - 1) * Math.max(1, pageSize);
      const pageItems = listedMembers.slice(offset, offset + Math.max(1, pageSize));
      sendJson({
        status: 200,
        contentType: 'application/json',
        payload: {
          tenant_id: tenantId,
          page: Math.max(1, page),
          page_size: Math.max(1, pageSize),
          members: pageItems,
          request_id: requestId
        }
      });
      return;
    }

    if (method === 'POST' && pathname === '/tenant/users') {
      const phone = String(body.phone || '').trim();
      if (!/^1\d{10}$/.test(phone)) {
        sendProblem({
          status: 400,
          detail: '请求参数不完整或格式错误',
          errorCode: 'AUTH-400-INVALID-PAYLOAD'
        });
        return;
      }
      await sleep(250);
      const membershipId = `membership-${tenantId}-${nextMemberId}`;
      const userId = `tenant-user-${nextMemberId}`;
      nextMemberId += 1;
      members.set(membershipId, {
        membership_id: membershipId,
        user_id: userId,
        tenant_id: tenantId,
        tenant_name: tenantOptions.find((option) => option.tenant_id === tenantId)?.tenant_name || tenantId,
        phone,
        status: 'active',
        display_name: '',
        department_name: '',
        joined_at: new Date().toISOString(),
        left_at: null
      });
      memberRoleBindings.set(membershipId, ['tenant_user_management']);
      sendJson({
        status: 200,
        contentType: 'application/json',
        payload: {
          membership_id: membershipId,
          user_id: userId,
          tenant_id: tenantId,
          status: 'active',
          created_user: true,
          reused_existing_user: false,
          request_id: requestId
        }
      });
      return;
    }

    const memberMatch = pathname.match(/^\/tenant\/users\/([^/]+)$/);
    if (memberMatch && method === 'GET') {
      const membershipId = decodeURIComponent(memberMatch[1] || '');
      const member = members.get(membershipId);
      if (!member) {
        sendProblem({
          status: 404,
          title: 'Not Found',
          detail: '目标成员关系不存在',
          errorCode: 'AUTH-404-TENANT-MEMBERSHIP-NOT-FOUND'
        });
        return;
      }
      sendJson({
        status: 200,
        contentType: 'application/json',
        payload: {
          ...member,
          request_id: requestId
        }
      });
      return;
    }

    const memberStatusMatch = pathname.match(/^\/tenant\/users\/([^/]+)\/status$/);
    if (memberStatusMatch && method === 'PATCH') {
      const membershipId = decodeURIComponent(memberStatusMatch[1] || '');
      const member = members.get(membershipId);
      if (!member) {
        sendProblem({
          status: 404,
          title: 'Not Found',
          detail: '目标成员关系不存在',
          errorCode: 'AUTH-404-TENANT-MEMBERSHIP-NOT-FOUND'
        });
        return;
      }
      const nextStatus = String(body.status || '').trim().toLowerCase();
      if (!['active', 'disabled', 'left'].includes(nextStatus)) {
        sendProblem({
          status: 400,
          detail: 'status 必须为 active、disabled 或 left',
          errorCode: 'AUTH-400-INVALID-PAYLOAD'
        });
        return;
      }
      const previousStatus = member.status;
      member.status = nextStatus;
      members.set(membershipId, member);
      sendJson({
        status: 200,
        contentType: 'application/json',
        payload: {
          membership_id: membershipId,
          user_id: member.user_id,
          tenant_id: tenantId,
          previous_status: previousStatus,
          current_status: nextStatus,
          request_id: requestId
        }
      });
      return;
    }

    const memberProfileMatch = pathname.match(/^\/tenant\/users\/([^/]+)\/profile$/);
    if (memberProfileMatch && method === 'PATCH') {
      const membershipId = decodeURIComponent(memberProfileMatch[1] || '');
      const member = members.get(membershipId);
      if (!member) {
        sendProblem({
          status: 404,
          title: 'Not Found',
          detail: '目标成员关系不存在',
          errorCode: 'AUTH-404-TENANT-MEMBERSHIP-NOT-FOUND'
        });
        return;
      }
      if (String(body.display_name || '').trim() === 'FAIL-DEPENDENCY') {
        sendProblem({
          status: 503,
          title: 'Service Unavailable',
          detail: '组织成员治理依赖暂不可用，请稍后重试',
          errorCode: 'AUTH-503-TENANT-MEMBER-DEPENDENCY-UNAVAILABLE',
          retryable: true
        });
        return;
      }
      if (!String(body.display_name || '').trim()) {
        sendProblem({
          status: 400,
          detail: 'display_name 为必填字段',
          errorCode: 'AUTH-400-INVALID-PAYLOAD'
        });
        return;
      }
      member.display_name = String(body.display_name || '').trim();
      member.department_name = body.department_name == null ? null : String(body.department_name).trim();
      members.set(membershipId, member);
      sendJson({
        status: 200,
        contentType: 'application/json',
        payload: {
          ...member,
          request_id: requestId
        }
      });
      return;
    }

    const memberRolesMatch = pathname.match(/^\/tenant\/users\/([^/]+)\/roles$/);
    if (memberRolesMatch && method === 'GET') {
      const membershipId = decodeURIComponent(memberRolesMatch[1] || '');
      if (!members.has(membershipId)) {
        sendProblem({
          status: 404,
          title: 'Not Found',
          detail: '目标成员关系不存在',
          errorCode: 'AUTH-404-TENANT-MEMBERSHIP-NOT-FOUND'
        });
        return;
      }
      sendJson({
        status: 200,
        contentType: 'application/json',
        payload: {
          membership_id: membershipId,
          role_ids: memberRoleBindings.get(membershipId) || [],
          request_id: requestId
        }
      });
      return;
    }

    if (memberRolesMatch && method === 'PUT') {
      const membershipId = decodeURIComponent(memberRolesMatch[1] || '');
      if (!members.has(membershipId)) {
        sendProblem({
          status: 404,
          title: 'Not Found',
          detail: '目标成员关系不存在',
          errorCode: 'AUTH-404-TENANT-MEMBERSHIP-NOT-FOUND'
        });
        return;
      }
      const roleIds = normalizeRoleIds(body.role_ids);
      if (roleIds.length < 1 || roleIds.length > 5) {
        sendProblem({
          status: 400,
          detail: 'role_ids 必须为 1 到 5 条',
          errorCode: 'AUTH-400-INVALID-PAYLOAD'
        });
        return;
      }
      const hasUnknownRole = roleIds.some((roleId) => !roles.has(roleId));
      if (hasUnknownRole) {
        sendProblem({
          status: 404,
          title: 'Not Found',
          detail: '目标角色不存在',
          errorCode: 'TROLE-404-ROLE-NOT-FOUND'
        });
        return;
      }
      memberRoleBindings.set(membershipId, roleIds);
      sendJson({
        status: 200,
        contentType: 'application/json',
        payload: {
          membership_id: membershipId,
          role_ids: roleIds,
          request_id: requestId
        }
      });
      return;
    }

    if (method === 'GET' && pathname === '/tenant/accounts') {
      const page = Number(url.searchParams.get('page') || 1);
      const pageSize = Number(url.searchParams.get('page_size') || 20);
      const wechatIdFilter = String(url.searchParams.get('wechat_id') || '').trim();
      const nicknameFilter = String(url.searchParams.get('nickname') || '').trim().toLowerCase();
      const ownerKeywordFilter = String(url.searchParams.get('owner_keyword') || '').trim().toLowerCase();
      const assistantKeywordFilter = String(url.searchParams.get('assistant_keyword') || '').trim().toLowerCase();
      const statusFilter = normalizeCustomerStatus(url.searchParams.get('status'));
      const createdTimeStart = Date.parse(String(url.searchParams.get('created_time_start') || '').trim());
      const createdTimeEnd = Date.parse(String(url.searchParams.get('created_time_end') || '').trim());
      const hasCreatedTimeStart = !Number.isNaN(createdTimeStart);
      const hasCreatedTimeEnd = !Number.isNaN(createdTimeEnd);

      const listedAccounts = [...accounts.values()];
      const filteredAccounts = listedAccounts.filter((account) => {
        const accountWechatId = String(account?.wechat_id || '').trim();
        const accountNickname = String(account?.nickname || '').trim().toLowerCase();
        const accountOwner = String(account?.owner_name || '').trim().toLowerCase();
        const accountAssistantJoined = String(
          (Array.isArray(account?.assistant_names) ? account.assistant_names : []).join(' ')
        ).trim().toLowerCase();
        const accountStatus = normalizeCustomerStatus(account?.status);
        const accountCreatedAt = Date.parse(String(account?.created_at || '').trim());
        if (wechatIdFilter && accountWechatId !== wechatIdFilter) {
          return false;
        }
        if (nicknameFilter && !accountNickname.includes(nicknameFilter)) {
          return false;
        }
        if (ownerKeywordFilter && !accountOwner.includes(ownerKeywordFilter)) {
          return false;
        }
        if (assistantKeywordFilter && !accountAssistantJoined.includes(assistantKeywordFilter)) {
          return false;
        }
        if (statusFilter && accountStatus !== statusFilter) {
          return false;
        }
        if ((hasCreatedTimeStart || hasCreatedTimeEnd) && Number.isNaN(accountCreatedAt)) {
          return false;
        }
        if (hasCreatedTimeStart && accountCreatedAt < createdTimeStart) {
          return false;
        }
        if (hasCreatedTimeEnd && accountCreatedAt > createdTimeEnd) {
          return false;
        }
        return true;
      });
      filteredAccounts.sort((left, right) => {
        const leftCreatedAt = Date.parse(String(left?.created_at || '').trim());
        const rightCreatedAt = Date.parse(String(right?.created_at || '').trim());
        if (!Number.isNaN(leftCreatedAt) && !Number.isNaN(rightCreatedAt) && leftCreatedAt !== rightCreatedAt) {
          return rightCreatedAt - leftCreatedAt;
        }
        return String(left?.account_id || '').localeCompare(String(right?.account_id || ''));
      });
      const offset = (Math.max(1, page) - 1) * Math.max(1, pageSize);
      const pageItems = filteredAccounts.slice(offset, offset + Math.max(1, pageSize));
      sendJson({
        status: 200,
        contentType: 'application/json',
        payload: {
          tenant_id: tenantId,
          page: Math.max(1, page),
          page_size: Math.max(1, pageSize),
          total: filteredAccounts.length,
          accounts: pageItems,
          request_id: requestId
        }
      });
      return;
    }

    if (method === 'POST' && pathname === '/tenant/accounts') {
      const wechatId = String(body.wechat_id || '').trim();
      const nickname = String(body.nickname || '').trim();
      const ownerMembershipId = String(body.owner_membership_id || '').trim();
      const assistantMembershipIds = [...new Set(
        (Array.isArray(body.assistant_membership_ids) ? body.assistant_membership_ids : [])
          .map((membershipId) => String(membershipId || '').trim())
          .filter(Boolean)
      )];
      if (!wechatId || !nickname || !ownerMembershipId) {
        sendProblem({
          status: 400,
          detail: '请求参数不完整或格式错误',
          errorCode: 'TACCOUNT-400-INVALID-PAYLOAD'
        });
        return;
      }
      const ownerMember = members.get(ownerMembershipId);
      if (!ownerMember) {
        sendProblem({
          status: 404,
          title: 'Not Found',
          detail: '目标成员关系不存在',
          errorCode: 'AUTH-404-TENANT-MEMBERSHIP-NOT-FOUND'
        });
        return;
      }
      const invalidAssistant = assistantMembershipIds.find(
        (membershipId) => !members.has(membershipId)
      );
      if (invalidAssistant) {
        sendProblem({
          status: 404,
          title: 'Not Found',
          detail: '目标成员关系不存在',
          errorCode: 'AUTH-404-TENANT-MEMBERSHIP-NOT-FOUND'
        });
        return;
      }
      const accountId = `account-${tenantId}-${nextAccountSequence++}`;
      const now = new Date().toISOString();
      const assistantNames = assistantMembershipIds.map((membershipId) =>
        String(members.get(membershipId)?.display_name || members.get(membershipId)?.phone || membershipId)
      );
      const createdAccount = {
        account_id: accountId,
        tenant_id: tenantId,
        wechat_id: wechatId,
        nickname,
        avatar_url: '',
        owner_membership_id: ownerMembershipId,
        owner_name: String(ownerMember?.display_name || ownerMember?.phone || ownerMembershipId),
        assistant_membership_ids: assistantMembershipIds,
        assistant_names: assistantNames,
        customer_count: 0,
        group_chat_count: 0,
        status: 'active',
        created_at: now,
        updated_at: now
      };
      accounts.set(accountId, createdAccount);
      accountOperationLogs.set(accountId, [
        {
          operation_type: '新建账号',
          operated_at: now,
          operator_name: '当前用户',
          content: `request_id: ${requestId}`
        }
      ]);
      sendJson({
        status: 200,
        contentType: 'application/json',
        payload: {
          ...createdAccount,
          request_id: requestId
        }
      });
      return;
    }

    const accountMatch = pathname.match(/^\/tenant\/accounts\/([^/]+)$/);
    if (accountMatch && method === 'GET') {
      const accountId = decodeURIComponent(accountMatch[1] || '').trim();
      const account = accounts.get(accountId);
      if (!account) {
        sendProblem({
          status: 404,
          title: 'Not Found',
          detail: '目标账号不存在',
          errorCode: 'TACCOUNT-404-ACCOUNT-NOT-FOUND'
        });
        return;
      }
      sendJson({
        status: 200,
        contentType: 'application/json',
        payload: {
          ...account,
          operation_logs: accountOperationLogs.get(accountId) || [],
          request_id: requestId
        }
      });
      return;
    }

    if (accountMatch && method === 'PATCH') {
      const accountId = decodeURIComponent(accountMatch[1] || '').trim();
      const account = accounts.get(accountId);
      if (!account) {
        sendProblem({
          status: 404,
          title: 'Not Found',
          detail: '目标账号不存在',
          errorCode: 'TACCOUNT-404-ACCOUNT-NOT-FOUND'
        });
        return;
      }
      const wechatId = String(body.wechat_id || '').trim();
      const nickname = String(body.nickname || '').trim();
      const ownerMembershipId = String(body.owner_membership_id || '').trim();
      const assistantMembershipIds = [...new Set(
        (Array.isArray(body.assistant_membership_ids) ? body.assistant_membership_ids : [])
          .map((membershipId) => String(membershipId || '').trim())
          .filter(Boolean)
      )];
      if (!wechatId || !nickname || !ownerMembershipId) {
        sendProblem({
          status: 400,
          detail: '请求参数不完整或格式错误',
          errorCode: 'TACCOUNT-400-INVALID-PAYLOAD'
        });
        return;
      }
      const ownerMember = members.get(ownerMembershipId);
      if (!ownerMember) {
        sendProblem({
          status: 404,
          title: 'Not Found',
          detail: '目标成员关系不存在',
          errorCode: 'AUTH-404-TENANT-MEMBERSHIP-NOT-FOUND'
        });
        return;
      }
      const invalidAssistant = assistantMembershipIds.find(
        (membershipId) => !members.has(membershipId)
      );
      if (invalidAssistant) {
        sendProblem({
          status: 404,
          title: 'Not Found',
          detail: '目标成员关系不存在',
          errorCode: 'AUTH-404-TENANT-MEMBERSHIP-NOT-FOUND'
        });
        return;
      }
      const updatedAt = new Date().toISOString();
      const assistantNames = assistantMembershipIds.map((membershipId) =>
        String(members.get(membershipId)?.display_name || members.get(membershipId)?.phone || membershipId)
      );
      const updatedAccount = {
        ...account,
        wechat_id: wechatId,
        nickname,
        owner_membership_id: ownerMembershipId,
        owner_name: String(ownerMember?.display_name || ownerMember?.phone || ownerMembershipId),
        assistant_membership_ids: assistantMembershipIds,
        assistant_names: assistantNames,
        updated_at: updatedAt
      };
      accounts.set(accountId, updatedAccount);
      const logs = accountOperationLogs.get(accountId) || [];
      logs.unshift({
        operation_type: '编辑账号',
        operated_at: updatedAt,
        operator_name: '当前用户',
        content: `request_id: ${requestId}`
      });
      accountOperationLogs.set(accountId, logs);
      sendJson({
        status: 200,
        contentType: 'application/json',
        payload: {
          ...updatedAccount,
          request_id: requestId
        }
      });
      return;
    }

    const accountStatusMatch = pathname.match(/^\/tenant\/accounts\/([^/]+)\/status$/);
    if (accountStatusMatch && method === 'PATCH') {
      const accountId = decodeURIComponent(accountStatusMatch[1] || '').trim();
      const account = accounts.get(accountId);
      if (!account) {
        sendProblem({
          status: 404,
          title: 'Not Found',
          detail: '目标账号不存在',
          errorCode: 'TACCOUNT-404-ACCOUNT-NOT-FOUND'
        });
        return;
      }
      const nextStatus = String(body.status || '').trim().toLowerCase();
      if (!['active', 'disabled'].includes(nextStatus)) {
        sendProblem({
          status: 400,
          detail: 'status 必须为 active 或 disabled',
          errorCode: 'TACCOUNT-400-INVALID-PAYLOAD'
        });
        return;
      }
      const previousStatus = String(account.status || '').trim().toLowerCase();
      const updatedAt = new Date().toISOString();
      const updatedAccount = {
        ...account,
        status: nextStatus,
        updated_at: updatedAt
      };
      accounts.set(accountId, updatedAccount);
      const logs = accountOperationLogs.get(accountId) || [];
      logs.unshift({
        operation_type: '状态变更',
        operated_at: updatedAt,
        operator_name: '当前用户',
        content: `${previousStatus} -> ${nextStatus}`
      });
      accountOperationLogs.set(accountId, logs);
      sendJson({
        status: 200,
        contentType: 'application/json',
        payload: {
          account_id: accountId,
          tenant_id: tenantId,
          previous_status: previousStatus,
          current_status: nextStatus,
          request_id: requestId
        }
      });
      return;
    }

    const ensureCustomerViewPermission = () => {
      if (tenantPermissionContext?.can_view_customer_management) {
        return true;
      }
      sendProblem({
        status: 403,
        title: 'Forbidden',
        detail: '当前角色缺少客户资料查看权限',
        errorCode: 'TCUSTOMER-403-VIEW-FORBIDDEN'
      });
      return false;
    };
    const ensureCustomerOperatePermission = () => {
      if (tenantPermissionContext?.can_operate_customer_management) {
        return true;
      }
      sendProblem({
        status: 403,
        title: 'Forbidden',
        detail: '当前角色缺少客户资料操作权限',
        errorCode: 'TCUSTOMER-403-OPERATE-FORBIDDEN'
      });
      return false;
    };

    if (method === 'GET' && pathname === '/tenant/customers') {
      if (!ensureCustomerViewPermission()) {
        return;
      }

      const scope = String(url.searchParams.get('scope') || 'my').trim().toLowerCase() || 'my';
      const scopePermissionByKey = {
        my: Boolean(tenantPermissionContext?.can_view_customer_scope_my),
        assist: Boolean(tenantPermissionContext?.can_view_customer_scope_assist),
        all: Boolean(tenantPermissionContext?.can_view_customer_scope_all)
      };
      if (!scopePermissionByKey[scope]) {
        const detail = scopePermissionByKey[scope] === undefined
          ? 'scope 参数非法'
          : '当前角色缺少对应客户范围查看权限';
        sendProblem({
          status: scopePermissionByKey[scope] === undefined ? 400 : 403,
          detail,
          errorCode: scopePermissionByKey[scope] === undefined
            ? 'TCUSTOMER-400-INVALID-SCOPE'
            : 'TCUSTOMER-403-SCOPE-FORBIDDEN'
        });
        return;
      }

      const page = Number(url.searchParams.get('page') || 1);
      const pageSize = Number(url.searchParams.get('page_size') || 20);
      const wechatIdFilter = String(url.searchParams.get('wechat_id') || '').trim();
      const accountIdsFilter = parseCsvList(url.searchParams.get('account_ids'));
      const nicknameFilter = String(url.searchParams.get('nickname') || '').trim().toLowerCase();
      const sourceFilter = normalizeCustomerSource(url.searchParams.get('source'));
      const realNameFilter = String(url.searchParams.get('real_name') || '').trim().toLowerCase();
      const phoneFilter = String(url.searchParams.get('phone') || '').trim();
      const statusFilter = normalizeCustomerStatus(url.searchParams.get('status'));
      const createdTimeStart = Date.parse(String(url.searchParams.get('created_time_start') || '').trim());
      const createdTimeEnd = Date.parse(String(url.searchParams.get('created_time_end') || '').trim());
      const hasCreatedTimeStart = !Number.isNaN(createdTimeStart);
      const hasCreatedTimeEnd = !Number.isNaN(createdTimeEnd);

      const listedCustomers = [...customers.values()];
      const filteredCustomers = listedCustomers.filter((customer) => {
        const accountId = String(customer?.account_id || '').trim();
        const account = accounts.get(accountId) || null;
        const ownerMembershipId = String(account?.owner_membership_id || '').trim();
        const assistantMembershipIds = Array.isArray(account?.assistant_membership_ids)
          ? account.assistant_membership_ids.map((membershipId) => String(membershipId || '').trim())
          : [];
        if (scope === 'my' && ownerMembershipId !== sessionMembershipId) {
          return false;
        }
        if (scope === 'assist' && !assistantMembershipIds.includes(sessionMembershipId)) {
          return false;
        }

        const customerWechatId = String(customer?.wechat_id || '').trim();
        const customerAccountId = String(customer?.account_id || '').trim();
        const customerNickname = String(customer?.nickname || '').trim().toLowerCase();
        const customerSource = normalizeCustomerSource(customer?.source);
        const customerRealName = String(customer?.real_name || '').trim().toLowerCase();
        const customerPhone = String(customer?.phone || '').trim();
        const customerStatus = normalizeCustomerStatus(customer?.status);
        const customerCreatedAt = Date.parse(String(customer?.created_at || '').trim());

        if (wechatIdFilter && customerWechatId !== wechatIdFilter) {
          return false;
        }
        if (accountIdsFilter.length > 0 && !accountIdsFilter.includes(customerAccountId)) {
          return false;
        }
        if (nicknameFilter && !customerNickname.includes(nicknameFilter)) {
          return false;
        }
        if (sourceFilter && customerSource !== sourceFilter) {
          return false;
        }
        if (realNameFilter && !customerRealName.includes(realNameFilter)) {
          return false;
        }
        if (phoneFilter && customerPhone !== phoneFilter) {
          return false;
        }
        if (statusFilter && customerStatus !== statusFilter) {
          return false;
        }
        if ((hasCreatedTimeStart || hasCreatedTimeEnd) && Number.isNaN(customerCreatedAt)) {
          return false;
        }
        if (hasCreatedTimeStart && customerCreatedAt < createdTimeStart) {
          return false;
        }
        if (hasCreatedTimeEnd && customerCreatedAt > createdTimeEnd) {
          return false;
        }
        return true;
      });
      filteredCustomers.sort((left, right) => {
        const leftCreatedAt = Date.parse(String(left?.created_at || '').trim());
        const rightCreatedAt = Date.parse(String(right?.created_at || '').trim());
        if (!Number.isNaN(leftCreatedAt) && !Number.isNaN(rightCreatedAt) && leftCreatedAt !== rightCreatedAt) {
          return rightCreatedAt - leftCreatedAt;
        }
        return String(left?.customer_id || '').localeCompare(String(right?.customer_id || ''));
      });
      const offset = (Math.max(1, page) - 1) * Math.max(1, pageSize);
      const pageItems = filteredCustomers.slice(offset, offset + Math.max(1, pageSize));
      sendJson({
        status: 200,
        contentType: 'application/json',
        payload: {
          tenant_id: tenantId,
          page: Math.max(1, page),
          page_size: Math.max(1, pageSize),
          total: filteredCustomers.length,
          customers: pageItems,
          request_id: requestId
        }
      });
      return;
    }

    if (method === 'POST' && pathname === '/tenant/customers') {
      if (!ensureCustomerViewPermission() || !ensureCustomerOperatePermission()) {
        return;
      }

      const accountId = String(body.account_id || '').trim();
      const wechatId = String(body.wechat_id || '').trim();
      const nickname = String(body.nickname || '').trim();
      const source = normalizeCustomerSource(body.source);
      if (!accountId || !wechatId || !nickname || !source) {
        sendProblem({
          status: 400,
          detail: '请求参数不完整或格式错误',
          errorCode: 'TCUSTOMER-400-INVALID-PAYLOAD'
        });
        return;
      }
      const account = accounts.get(accountId);
      if (!account) {
        sendProblem({
          status: 404,
          title: 'Not Found',
          detail: '目标账号不存在',
          errorCode: 'TACCOUNT-404-ACCOUNT-NOT-FOUND'
        });
        return;
      }

      const now = new Date().toISOString();
      const customerId = `customer-${tenantId}-${nextCustomerSequence++}`;
      const createdCustomer = {
        customer_id: customerId,
        tenant_id: tenantId,
        account_id: accountId,
        account_wechat_id: String(account.wechat_id || '').trim(),
        account_nickname: String(account.nickname || '').trim(),
        wechat_id: wechatId,
        nickname,
        source,
        school: String(body.school || '').trim(),
        class_name: String(body.class_name || '').trim(),
        real_name: String(body.real_name || '').trim(),
        relation: String(body.relation || '').trim(),
        phone: String(body.phone || '').trim(),
        address: String(body.address || '').trim(),
        status: 'enabled',
        created_by_user_id: sessionMembershipId || null,
        created_by_name: '当前用户',
        created_at: now,
        updated_at: now
      };
      customers.set(customerId, createdCustomer);
      customerOperationLogs.set(customerId, [
        {
          operation_type: 'create',
          operated_at: now,
          operator_name: '当前用户',
          content: `request_id: ${requestId}`
        }
      ]);
      accounts.set(accountId, {
        ...account,
        customer_count: Math.max(0, Number(account?.customer_count || 0)) + 1,
        updated_at: now
      });
      sendJson({
        status: 200,
        contentType: 'application/json',
        payload: {
          ...createdCustomer,
          request_id: requestId
        }
      });
      return;
    }

    const customerMatch = pathname.match(/^\/tenant\/customers\/([^/]+)$/);
    if (customerMatch && method === 'GET') {
      if (!ensureCustomerViewPermission()) {
        return;
      }
      const customerId = decodeURIComponent(customerMatch[1] || '').trim();
      const customer = customers.get(customerId);
      if (!customer) {
        sendProblem({
          status: 404,
          title: 'Not Found',
          detail: '目标客户不存在',
          errorCode: 'TCUSTOMER-404-CUSTOMER-NOT-FOUND'
        });
        return;
      }
      sendJson({
        status: 200,
        contentType: 'application/json',
        payload: {
          ...customer,
          operation_logs: customerOperationLogs.get(customerId) || [],
          request_id: requestId
        }
      });
      return;
    }

    const customerBasicMatch = pathname.match(/^\/tenant\/customers\/([^/]+)\/basic$/);
    if (customerBasicMatch && method === 'PATCH') {
      if (!ensureCustomerViewPermission() || !ensureCustomerOperatePermission()) {
        return;
      }
      const customerId = decodeURIComponent(customerBasicMatch[1] || '').trim();
      const customer = customers.get(customerId);
      if (!customer) {
        sendProblem({
          status: 404,
          title: 'Not Found',
          detail: '目标客户不存在',
          errorCode: 'TCUSTOMER-404-CUSTOMER-NOT-FOUND'
        });
        return;
      }
      const source = normalizeCustomerSource(body.source);
      if (!source) {
        sendProblem({
          status: 400,
          detail: 'source 必须为 ground、fission 或 other',
          errorCode: 'TCUSTOMER-400-INVALID-PAYLOAD'
        });
        return;
      }
      const now = new Date().toISOString();
      const updatedCustomer = {
        ...customer,
        source,
        updated_at: now
      };
      customers.set(customerId, updatedCustomer);
      const logs = customerOperationLogs.get(customerId) || [];
      logs.unshift({
        operation_type: 'update_basic',
        operated_at: now,
        operator_name: '当前用户',
        content: `source -> ${source}`
      });
      customerOperationLogs.set(customerId, logs);
      sendJson({
        status: 200,
        contentType: 'application/json',
        payload: {
          ...updatedCustomer,
          request_id: requestId
        }
      });
      return;
    }

    const customerRealnameMatch = pathname.match(/^\/tenant\/customers\/([^/]+)\/realname$/);
    if (customerRealnameMatch && method === 'PATCH') {
      if (!ensureCustomerViewPermission() || !ensureCustomerOperatePermission()) {
        return;
      }
      const customerId = decodeURIComponent(customerRealnameMatch[1] || '').trim();
      const customer = customers.get(customerId);
      if (!customer) {
        sendProblem({
          status: 404,
          title: 'Not Found',
          detail: '目标客户不存在',
          errorCode: 'TCUSTOMER-404-CUSTOMER-NOT-FOUND'
        });
        return;
      }
      const now = new Date().toISOString();
      const updatedCustomer = {
        ...customer,
        real_name: String(body.real_name || '').trim(),
        school: String(body.school || '').trim(),
        class_name: String(body.class_name || '').trim(),
        relation: String(body.relation || '').trim(),
        phone: String(body.phone || '').trim(),
        address: String(body.address || '').trim(),
        updated_at: now
      };
      customers.set(customerId, updatedCustomer);
      const logs = customerOperationLogs.get(customerId) || [];
      logs.unshift({
        operation_type: 'update_realname',
        operated_at: now,
        operator_name: '当前用户',
        content: `request_id: ${requestId}`
      });
      customerOperationLogs.set(customerId, logs);
      sendJson({
        status: 200,
        contentType: 'application/json',
        payload: {
          ...updatedCustomer,
          request_id: requestId
        }
      });
      return;
    }

    const customerLogsMatch = pathname.match(/^\/tenant\/customers\/([^/]+)\/operation-logs$/);
    if (customerLogsMatch && method === 'GET') {
      if (!ensureCustomerViewPermission()) {
        return;
      }
      const customerId = decodeURIComponent(customerLogsMatch[1] || '').trim();
      if (!customers.has(customerId)) {
        sendProblem({
          status: 404,
          title: 'Not Found',
          detail: '目标客户不存在',
          errorCode: 'TCUSTOMER-404-CUSTOMER-NOT-FOUND'
        });
        return;
      }
      sendJson({
        status: 200,
        contentType: 'application/json',
        payload: {
          customer_id: customerId,
          logs: customerOperationLogs.get(customerId) || [],
          request_id: requestId
        }
      });
      return;
    }

    if (method === 'GET' && pathname === '/tenant/roles') {
      sendJson({
        status: 200,
        contentType: 'application/json',
        payload: {
          tenant_id: tenantId,
          roles: [...roles.values()].map((role) => ({
            ...role,
            request_id: requestId
          })),
          request_id: requestId
        }
      });
      return;
    }

    if (method === 'POST' && pathname === '/tenant/roles') {
      const roleId = String(body.role_id || '').trim().toLowerCase();
      if (!roleId) {
        sendProblem({
          status: 400,
          detail: 'role_id 不能为空',
          errorCode: 'TROLE-400-INVALID-PAYLOAD'
        });
        return;
      }
      if (roles.has(roleId)) {
        sendProblem({
          status: 409,
          title: 'Conflict',
          detail: '组织角色标识冲突，请使用其他 role_id',
          errorCode: 'TROLE-409-ROLE-ID-CONFLICT'
        });
        return;
      }
      const now = new Date().toISOString();
      const createdRole = {
        role_id: roleId,
        tenant_id: tenantId,
        code: String(body.code || `TENANT_ROLE_${nextRoleSequence}`).trim(),
        name: String(body.name || `组织角色 ${nextRoleSequence}`).trim(),
        status: String(body.status || 'active').trim().toLowerCase() || 'active',
        is_system: false,
        created_at: now,
        updated_at: now
      };
      nextRoleSequence += 1;
      roles.set(roleId, createdRole);
      rolePermissions.set(roleId, []);
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

    const roleMatch = pathname.match(/^\/tenant\/roles\/([^/]+)$/);
    if (roleMatch && method === 'PATCH') {
      const roleId = decodeURIComponent(roleMatch[1] || '').trim().toLowerCase();
      const targetRole = roles.get(roleId);
      if (!targetRole) {
        sendProblem({
          status: 404,
          title: 'Not Found',
          detail: '目标角色不存在',
          errorCode: 'TROLE-404-ROLE-NOT-FOUND'
        });
        return;
      }
      if (protectedRoleIds.has(roleId) || targetRole.is_system) {
        sendProblem({
          status: 403,
          title: 'Forbidden',
          detail: '受保护系统角色定义不允许创建、编辑或删除',
          errorCode: 'TROLE-403-SYSTEM-ROLE-PROTECTED'
        });
        return;
      }
      const updatedRole = {
        ...targetRole,
        code: String(body.code || targetRole.code).trim(),
        name: String(body.name || targetRole.name).trim(),
        status: String(body.status || targetRole.status).trim().toLowerCase(),
        updated_at: new Date().toISOString()
      };
      roles.set(roleId, updatedRole);
      sendJson({
        status: 200,
        contentType: 'application/json',
        payload: {
          ...updatedRole,
          request_id: requestId
        }
      });
      return;
    }

    if (roleMatch && method === 'DELETE') {
      const roleId = decodeURIComponent(roleMatch[1] || '').trim().toLowerCase();
      const targetRole = roles.get(roleId);
      if (!targetRole) {
        sendProblem({
          status: 404,
          title: 'Not Found',
          detail: '目标角色不存在',
          errorCode: 'TROLE-404-ROLE-NOT-FOUND'
        });
        return;
      }
      if (protectedRoleIds.has(roleId) || targetRole.is_system) {
        sendProblem({
          status: 403,
          title: 'Forbidden',
          detail: '受保护系统角色定义不允许创建、编辑或删除',
          errorCode: 'TROLE-403-SYSTEM-ROLE-PROTECTED'
        });
        return;
      }
      roles.delete(roleId);
      rolePermissions.delete(roleId);
      for (const [membershipId, bindingRoleIds] of memberRoleBindings.entries()) {
        memberRoleBindings.set(
          membershipId,
          bindingRoleIds.filter((boundRoleId) => boundRoleId !== roleId)
        );
      }
      sendJson({
        status: 200,
        contentType: 'application/json',
        payload: {
          role_id: roleId,
          tenant_id: tenantId,
          status: 'disabled',
          request_id: requestId
        }
      });
      return;
    }

    const rolePermissionMatch = pathname.match(/^\/tenant\/roles\/([^/]+)\/permissions$/);
    if (rolePermissionMatch && method === 'GET') {
      const roleId = decodeURIComponent(rolePermissionMatch[1] || '').trim().toLowerCase();
      if (!roles.has(roleId)) {
        sendProblem({
          status: 404,
          title: 'Not Found',
          detail: '目标角色不存在',
          errorCode: 'TROLE-404-ROLE-NOT-FOUND'
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
          detail: '目标角色不存在',
          errorCode: 'TROLE-404-ROLE-NOT-FOUND'
        });
        return;
      }
      const nextPermissionCodes = [...new Set(
        (Array.isArray(body.permission_codes) ? body.permission_codes : [])
          .map((permissionCode) => String(permissionCode || '').trim())
          .filter((permissionCode) => permissionCode.startsWith('tenant.'))
      )];
      rolePermissions.set(roleId, nextPermissionCodes);
      let affectedUserCount = 0;
      for (const roleIds of memberRoleBindings.values()) {
        if (roleIds.includes(roleId)) {
          affectedUserCount += 1;
        }
      }
      sendJson({
        status: 200,
        contentType: 'application/json',
        payload: {
          role_id: roleId,
          permission_codes: nextPermissionCodes,
          available_permission_codes: permissionCatalog,
          affected_user_count: affectedUserCount,
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

const ensureAuthStoreCustomerCapabilities = (authService) => {
  const authStore = authService?._internals?.authStore;
  if (!authStore || typeof authStore !== 'object') {
    return;
  }
  if (typeof authStore.listTenantCustomersByTenantId !== 'function') {
    authStore.listTenantCustomersByTenantId = async () => [];
  }
  if (typeof authStore.createTenantCustomer !== 'function') {
    authStore.createTenantCustomer = async () => null;
  }
  if (typeof authStore.findTenantCustomerByCustomerId !== 'function') {
    authStore.findTenantCustomerByCustomerId = async () => null;
  }
  if (typeof authStore.updateTenantCustomerBasic !== 'function') {
    authStore.updateTenantCustomerBasic = async () => null;
  }
  if (typeof authStore.updateTenantCustomerRealname !== 'function') {
    authStore.updateTenantCustomerRealname = async () => null;
  }
  if (typeof authStore.listTenantCustomerOperationLogs !== 'function') {
    authStore.listTenantCustomerOperationLogs = async () => [];
  }
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
              canViewUserManagement: true,
              canOperateUserManagement: true,
              canViewRoleManagement: true,
              canOperateRoleManagement: false
            }
          },
          {
            tenantId: REAL_API_TEST_USER.tenantB,
            tenantName: 'Tenant B',
            status: 'active',
            permission: {
              scopeLabel: '组织权限（Tenant B）',
              canViewUserManagement: false,
              canOperateUserManagement: false,
              canViewRoleManagement: true,
              canOperateRoleManagement: true
            }
          }
        ]
      }
    ],
    allowInMemoryOtpStores: true,
    requireSecureOtpStores: false
  });
  ensureAuthStoreCustomerCapabilities(authService);

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
    `(() => { document.querySelector('[data-testid="mode-otp"]')?.click(); return true; })()`
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
      return message.includes('验证码错误或已失效');
    })()`,
    10000,
    'otp login failure should replace cooldown message with invalid-otp message'
  );
  assert.match(
    String(await evaluate(cdp, sessionId, `document.querySelector('[data-testid="message-global"]')?.textContent || ''`)),
    /验证码错误或已失效.*请稍后重试/
  );

  await cdp.send('Page.navigate', { url: `http://127.0.0.1:${webPort}/login/platform` }, sessionId);
  await waitForCondition(
    cdp,
    sessionId,
    `Boolean(document.querySelector('[data-testid="page-title"]'))`,
    10000,
    'platform login page should be visible'
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
    `Boolean(document.querySelector('[data-testid="platform-management-panel"]'))`,
    10000,
    'platform login should require explicit /login/platform url and enter platform dashboard'
  );

  await cdp.send('Page.navigate', { url: `http://127.0.0.1:${webPort}/login/tenant` }, sessionId);
  await waitForCondition(
    cdp,
    sessionId,
    `Boolean(document.querySelector('[data-testid="page-title"]'))`,
    10000,
    'tenant login page should be visible'
  );
  await evaluate(
    cdp,
    sessionId,
    `(() => { document.querySelector('[data-testid="mode-password"]')?.click(); return true; })()`
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
    `Boolean(document.querySelector('[data-testid="tenant-org-switch-shell"]'))`,
    10000,
    'tenant-entry login should require tenant switch page when multiple options exist'
  );
  await evaluate(
    cdp,
    sessionId,
    `(() => {
      document.querySelector('[data-testid="tenant-org-switch-card-tenant-101"]')?.click();
      return true;
    })()`
  );
  await waitForCondition(
    cdp,
    sessionId,
    `(() => {
      const tenantPanel = document.querySelector('[data-testid="tenant-management-panel"]');
      const message = String(document.querySelector('[data-testid="message-global"]')?.textContent || '');
      const userTab = document.querySelector('[data-testid="tenant-tab-users"]');
      const roleTab = document.querySelector('[data-testid="tenant-tab-roles"]');
      const configTab = document.querySelector('[data-testid="tenant-tab-config"]');
      const configMenu = document.querySelector('[data-testid="tenant-menu-config"]');
      const membersModule = document.querySelector('[data-testid="tenant-members-module"]');
      return (
        Boolean(tenantPanel) &&
        Boolean(membersModule) &&
        Boolean(userTab) &&
        roleTab === null &&
        configTab === null &&
        configMenu === null &&
        message.includes('请稍后重试') === false
      );
    })()`,
    10000,
    'tenant select should navigate to dashboard and materialize server-driven tenant-101 permissions'
  );
  await evaluate(
    cdp,
    sessionId,
    `(() => {
      const trigger = document.querySelector('[data-testid="layout-user-name"]')?.closest('span');
      trigger?.click();
      return true;
    })()`
  );
  await waitForCondition(
    cdp,
    sessionId,
    `(() => {
      const switchItem = [...document.querySelectorAll('.ant-dropdown-menu-item')]
        .find((item) => String(item.textContent || '').includes('切换组织'));
      return Boolean(switchItem);
    })()`,
    8000,
    'tenant org switch menu item should be visible'
  );
  await evaluate(
    cdp,
    sessionId,
    `(() => {
      const switchItem = [...document.querySelectorAll('.ant-dropdown-menu-item')]
        .find((item) => String(item.textContent || '').includes('切换组织'));
      switchItem?.click();
      return true;
    })()`
  );
  await waitForCondition(
    cdp,
    sessionId,
    `Boolean(document.querySelector('[data-testid="tenant-org-switch-shell"]'))`,
    8000,
    'tenant org switch page should be visible'
  );
  await evaluate(
    cdp,
    sessionId,
    `(() => { document.querySelector('[data-testid="tenant-org-switch-card-tenant-202"]')?.click(); return true; })()`
  );
  await waitForCondition(
    cdp,
    sessionId,
    `(() => {
      const tenantPanel = document.querySelector('[data-testid="tenant-management-panel"]');
      const roleModule = document.querySelector('[data-testid="tenant-roles-module"]');
      const userModule = document.querySelector('[data-testid="tenant-members-module"]');
      const userTab = document.querySelector('[data-testid="tenant-tab-users"]');
      const roleTab = document.querySelector('[data-testid="tenant-tab-roles"]');
      const configTab = document.querySelector('[data-testid="tenant-tab-config"]');
      const configMenu = document.querySelector('[data-testid="tenant-menu-config"]');
      const message = String(document.querySelector('[data-testid="message-global"]')?.textContent || '');
      return (
        Boolean(tenantPanel) &&
        Boolean(roleModule) &&
        userModule === null &&
        userTab === null &&
        Boolean(roleTab) &&
        configTab === null &&
        configMenu === null &&
        message.includes('请稍后重试') === false &&
        message.includes('组织切换成功')
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
    entry_domain: 'tenant'
  });
  assert.equal(
    api.requests.some(
      (request) =>
        request.path === '/auth/login'
        && request.body?.phone === '13800000005'
        && request.body?.password === 'Passw0rd!'
        && request.body?.entry_domain === 'platform'
    ),
    true,
    'platform login should only be available through explicit /login/platform URL'
  );
  assert.equal(
    api.requests.some(
      (request) =>
        request.path === '/auth/login'
        && request.body?.phone === '13800000005'
        && request.body?.password === 'Passw0rd!'
        && request.body?.entry_domain === 'tenant'
    ),
    true,
    'tenant login should remain available through /login/tenant URL'
  );
  const tenantSwitchRequests = api.requests
    .filter((request) => request.path === '/auth/tenant/switch')
    .map((request) => String(request.body?.tenant_id || '').trim());
  assert.deepEqual(
    tenantSwitchRequests.slice(0, 2),
    ['tenant-101', 'tenant-202']
  );
  await waitForRequest(
    api.responses,
    () =>
      api.responses.filter(
        (response) =>
          response.path === '/auth/tenant/options'
          && response.status === 503
          && response.body?.error_code === 'AUTH-503-TENANT-REFRESH'
      ).length >= 2,
    10000,
    'tenant context refresh should fail after initial tenant switch and explicit tenant switch'
  );
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
          entry_domain_url_routing: true,
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

  await cdp.send('Page.navigate', { url: `http://127.0.0.1:${webPort}/login/tenant` }, sessionId);
  await waitForCondition(
    cdp,
    sessionId,
    `Boolean(document.querySelector('[data-testid="page-title"]'))`,
    10000,
    'tenant login page should be visible'
  );
  await evaluate(
    cdp,
    sessionId,
    `(() => { document.querySelector('[data-testid="mode-password"]')?.click(); return true; })()`
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
    `Boolean(document.querySelector('[data-testid="tenant-org-switch-shell"]'))`,
    10000,
    'tenant entry login should require tenant switch page'
  );
  await evaluate(
    cdp,
    sessionId,
    `(() => {
      document.querySelector('[data-testid="tenant-org-switch-card-${REAL_API_TEST_USER.tenantA}"]')?.click();
      return true;
    })()`
  );
  await waitForCondition(
    cdp,
    sessionId,
    `(() => {
      const tenantPanel = document.querySelector('[data-testid="tenant-management-panel"]');
      const membersModule = document.querySelector('[data-testid="tenant-members-module"]');
      const userTab = document.querySelector('[data-testid="tenant-tab-users"]');
      const roleTab = document.querySelector('[data-testid="tenant-tab-roles"]');
      const configTab = document.querySelector('[data-testid="tenant-tab-config"]');
      const configMenu = document.querySelector('[data-testid="tenant-menu-config"]');
      return (
        Boolean(tenantPanel) &&
        Boolean(membersModule) &&
        Boolean(userTab) &&
        roleTab === null &&
        configTab === null &&
        configMenu === null
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

  const switchTenantAByApi = await requestRealApi({
    baseUrl: apiBaseUrl,
    method: 'POST',
    path: '/auth/tenant/switch',
    accessToken,
    body: {
      tenant_id: REAL_API_TEST_USER.tenantA
    }
  });
  assert.equal(switchTenantAByApi.status, 200);
  const probeAllowedByApi = await requestRealApi({
    baseUrl: apiBaseUrl,
    method: 'GET',
    path: '/auth/tenant/user-management/probe',
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
    path: '/auth/tenant/user-management/probe',
    accessToken
  });
  assert.equal(probeDeniedByApi.status, 403);
  assert.equal(probeDeniedByApi.body.error_code, 'AUTH-403-FORBIDDEN');

  await evaluate(
    cdp,
    sessionId,
    `(() => {
      const trigger = document.querySelector('[data-testid="layout-user-name"]')?.closest('span');
      trigger?.click();
      return true;
    })()`
  );
  await waitForCondition(
    cdp,
    sessionId,
    `(() => {
      const switchItem = [...document.querySelectorAll('.ant-dropdown-menu-item')]
        .find((item) => String(item.textContent || '').includes('切换组织'));
      return Boolean(switchItem);
    })()`,
    8000,
    'tenant org switch menu item should be visible'
  );
  await evaluate(
    cdp,
    sessionId,
    `(() => {
      const switchItem = [...document.querySelectorAll('.ant-dropdown-menu-item')]
        .find((item) => String(item.textContent || '').includes('切换组织'));
      switchItem?.click();
      return true;
    })()`
  );
  await waitForCondition(
    cdp,
    sessionId,
    `Boolean(document.querySelector('[data-testid="tenant-org-switch-shell"]'))`,
    8000,
    'tenant org switch page should be visible'
  );
  await evaluate(
    cdp,
    sessionId,
    `(() => { document.querySelector('[data-testid="tenant-org-switch-card-${REAL_API_TEST_USER.tenantB}"]')?.click(); return true; })()`
  );
  await waitForCondition(
    cdp,
    sessionId,
    `(() => {
      const tenantPanel = document.querySelector('[data-testid="tenant-management-panel"]');
      const membersModule = document.querySelector('[data-testid="tenant-members-module"]');
      const roleModule = document.querySelector('[data-testid="tenant-roles-module"]');
      const userTab = document.querySelector('[data-testid="tenant-tab-users"]');
      const roleTab = document.querySelector('[data-testid="tenant-tab-roles"]');
      const configTab = document.querySelector('[data-testid="tenant-tab-config"]');
      const configMenu = document.querySelector('[data-testid="tenant-menu-config"]');
      return (
        Boolean(tenantPanel) &&
        membersModule === null &&
        Boolean(roleModule) &&
        userTab === null &&
        Boolean(roleTab) &&
        configTab === null &&
        configMenu === null
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

test('chrome regression validates platform management workbench with modal/drawer and permission convergence', async (t) => {
  const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
  const evidenceDir = resolve(WORKSPACE_ROOT, 'artifacts/chrome-platform-management');
  mkdirSync(evidenceDir, { recursive: true });

  const chromeBinary = resolveChromeBinary();
  const api = await createPlatformGovernanceApiServer();
  const webPort = await reservePort();
  const cdpPort = await reservePort();
  const chromeProfileDir = mkdtempSync(join(tmpdir(), 'neweast-chrome-platform-management-'));

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
    { url: `http://127.0.0.1:${webPort}/login/platform` },
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
    `Boolean(document.querySelector('[data-testid="platform-management-panel"]'))`,
    10000,
    'platform management panel should be visible after platform login'
  );
  await waitForCondition(
    cdp,
    sessionId,
    `Boolean(document.querySelector('[data-testid="platform-user-id-platform-user-1"]'))`,
    10000,
    'platform user table should load initial user list'
  );
  await waitForCondition(
    cdp,
    sessionId,
    `(() => String(document.querySelector('[data-testid="layout-user-name"]')?.textContent || '').trim() === '平台管理员甲')()`,
    10000,
    'platform layout should show current user name beside avatar'
  );

  await evaluate(
    cdp,
    sessionId,
    `(() => {
      const input = document.querySelector('[data-testid="platform-user-filter-phone"]');
      const setter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value')?.set;
      setter.call(input, '13800000012');
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
    (request) => request.path.includes('/platform/users?') && request.path.includes('phone=13800000012'),
    8000,
    'platform user list filter request should carry phone query'
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
      const phoneInput = document.querySelector('[data-testid="platform-user-create-phone"]');
      const nameInput = document.querySelector('[data-testid="platform-user-create-name"]');
      const setter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value')?.set;
      setter.call(phoneInput, '13800000013');
      phoneInput.dispatchEvent(new Event('input', { bubbles: true }));
      phoneInput.dispatchEvent(new Event('change', { bubbles: true }));
      setter.call(nameInput, '平台新用户');
      nameInput.dispatchEvent(new Event('input', { bubbles: true }));
      nameInput.dispatchEvent(new Event('change', { bubbles: true }));
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
    `(() => !document.querySelector('[data-testid="platform-user-create-phone"]'))()`,
    10000,
    'platform user create modal should close after successful submit'
  );
  await waitForCondition(
    cdp,
    sessionId,
    `(() => !document.querySelector('[data-testid="platform-user-detail-drawer"]'))()`,
    5000,
    'detail drawer should stay closed after creating platform user'
  );
  await evaluate(
    cdp,
    sessionId,
    `(() => {
      const input = document.querySelector('[data-testid="platform-user-filter-phone"]');
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
    `(() => { document.querySelector('[data-testid="platform-user-edit-platform-user-1"]')?.click(); return true; })()`
  );
  await waitForCondition(
    cdp,
    sessionId,
    `Boolean(document.querySelector('[data-testid="platform-user-edit-user-id"]'))`,
    5000,
    'platform user edit modal should be visible'
  );
  await evaluate(
    cdp,
    sessionId,
    `(() => {
      const setter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value')?.set;
      const nameInput = document.querySelector('[data-testid="platform-user-edit-name"]');
      const departmentInput = document.querySelector('[data-testid="platform-user-edit-department"]');
      setter.call(nameInput, '平台管理员甲（已编辑）');
      nameInput.dispatchEvent(new Event('input', { bubbles: true }));
      nameInput.dispatchEvent(new Event('change', { bubbles: true }));
      setter.call(departmentInput, '平台治理中台');
      departmentInput.dispatchEvent(new Event('input', { bubbles: true }));
      departmentInput.dispatchEvent(new Event('change', { bubbles: true }));
      return true;
    })()`
  );
  await evaluate(
    cdp,
    sessionId,
    `(() => { document.querySelector('[data-testid="platform-user-edit-confirm"]')?.click(); return true; })()`
  );
  await waitForRequest(
    api.requests,
    (request) => request.path === '/platform/users/platform-user-1' && request.method === 'PATCH',
    8000,
    'platform user edit request should reach API stub'
  );
  await waitForRequest(
    api.requests,
    (request) => request.path === '/auth/platform/options' && request.method === 'GET',
    8000,
    'platform permission refresh should call /auth/platform/options after user edit'
  );
  await waitForCondition(
    cdp,
    sessionId,
    `(() => !document.querySelector('[data-testid="platform-user-edit-user-id"]'))()`,
    5000,
    'platform user edit modal should close after successful submit'
  );
  await waitForCondition(
    cdp,
    sessionId,
    `(() => String(document.querySelector('[data-testid="layout-user-name"]')?.textContent || '').trim() === '平台管理员甲（已编辑）')()`,
    8000,
    'platform current session user name should update after self profile edit'
  );
  await evaluate(
    cdp,
    sessionId,
    `(() => {
      window.location.reload();
      return true;
    })()`
  );
  await waitForCondition(
    cdp,
    sessionId,
    `Boolean(document.querySelector('[data-testid="platform-user-status-platform-user-1"]'))`,
    10000,
    'platform user table should recover after refresh'
  );
  await waitForCondition(
    cdp,
    sessionId,
    `(() => String(document.querySelector('[data-testid="layout-user-name"]')?.textContent || '').trim() === '平台管理员甲（已编辑）')()`,
    8000,
    'platform current session user name should remain updated after refresh'
  );

  await evaluate(
    cdp,
    sessionId,
    `(() => { document.querySelector('[data-testid="platform-user-status-platform-user-1"]').click(); return true; })()`
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
    `(() => { document.querySelector('[data-row-key="platform-user-1"]')?.click(); return true; })()`
  );
  await waitForCondition(
    cdp,
    sessionId,
    `(() => {
      const drawer = document.querySelector('[data-testid="platform-user-detail-drawer"]');
      const content = String(drawer?.textContent || '');
      return (
        Boolean(drawer)
        && content.includes('手机号')
        && !content.includes('request_id')
        && !content.includes('latest_action')
      );
    })()`,
    5000,
    'platform user detail drawer should hide request_id/latest_action fields'
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
    `Boolean(document.querySelector('[data-testid="platform-role-edit-code"]'))`,
    5000,
    'role edit modal should be visible'
  );
  await waitForCondition(
    cdp,
    sessionId,
    `Boolean(document.querySelector('[data-testid="platform-role-create-permission-tree"]'))`,
    5000,
    'role create permission tree should be visible'
  );
  await evaluate(
    cdp,
    sessionId,
    `(() => {
      const setter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value')?.set;
      const code = document.querySelector('[data-testid="platform-role-edit-code"]');
      const name = document.querySelector('[data-testid="platform-role-edit-name"]');
      setter.call(code, 'PLATFORM_TENANT_MANAGEMENT_ADMIN');
      code.dispatchEvent(new Event('input', { bubbles: true }));
      code.dispatchEvent(new Event('change', { bubbles: true }));
      setter.call(name, '平台角色治理');
      name.dispatchEvent(new Event('input', { bubbles: true }));
      name.dispatchEvent(new Event('change', { bubbles: true }));
      const rootNode = Array.from(document.querySelectorAll('.ant-tree-treenode'))
        .find((node) => String(node.textContent || '').includes('设置'));
      const rootCheckbox = rootNode?.querySelector('.ant-tree-checkbox');
      if (rootCheckbox && typeof rootCheckbox.click === 'function') {
        rootCheckbox.click();
      }
      return true;
    })()`
  );
  const createRoleRequestBaseline = api.requests.length;
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
  await waitForRequest(
    api.requests,
    (request, index) =>
      index >= createRoleRequestBaseline
      && request.method === 'PUT'
      && request.path.includes('/platform/roles/')
      && request.path.includes('/permissions'),
    8000,
    'platform role create permission save request should reach API stub'
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
    `(() => { document.querySelector('[data-testid="platform-role-edit-platform_user_management"]').click(); return true; })()`
  );
  await waitForCondition(
    cdp,
    sessionId,
    `(() => {
      const modalTitle = String(document.querySelector('.ant-modal-title')?.textContent || '');
      return modalTitle.includes('编辑');
    })()`,
    5000,
    'platform role edit modal title should be 编辑'
  );
  await waitForCondition(
    cdp,
    sessionId,
    `Boolean(document.querySelector('[data-testid="platform-role-edit-permission-tree"]'))`,
    5000,
    'platform role edit permission tree should be visible'
  );
  await evaluate(
    cdp,
    sessionId,
    `(() => {
      const setter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value')?.set;
      const code = document.querySelector('[data-testid="platform-role-edit-code"]');
      setter.call(code, 'SYS_ADMIN');
      code.dispatchEvent(new Event('input', { bubbles: true }));
      code.dispatchEvent(new Event('change', { bubbles: true }));
      return true;
    })()`
  );
  await evaluate(
    cdp,
    sessionId,
    `(() => { document.querySelector('[data-testid="platform-role-edit-confirm"]').click(); return true; })()`
  );
  await waitForCondition(
    cdp,
    sessionId,
    `(() => String(document.body.textContent || '').includes('角色编码需在组织内唯一'))()`,
    5000,
    'duplicate role code should be blocked by uniqueness validation'
  );
  await evaluate(
    cdp,
    sessionId,
    `(() => {
      const setter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value')?.set;
      const code = document.querySelector('[data-testid="platform-role-edit-code"]');
      const name = document.querySelector('[data-testid="platform-role-edit-name"]');
      setter.call(code, 'PLATFORM_USER_MANAGEMENT_V2');
      code.dispatchEvent(new Event('input', { bubbles: true }));
      code.dispatchEvent(new Event('change', { bubbles: true }));
      setter.call(name, '平台成员治理-已编辑');
      name.dispatchEvent(new Event('input', { bubbles: true }));
      name.dispatchEvent(new Event('change', { bubbles: true }));
      return true;
    })()`
  );
  const editRoleRequestBaseline = api.requests.length;
  await evaluate(
    cdp,
    sessionId,
    `(() => { document.querySelector('[data-testid="platform-role-edit-confirm"]').click(); return true; })()`
  );
  await waitForRequest(
    api.requests,
    (request, index) =>
      index >= editRoleRequestBaseline
      && request.path === '/platform/roles/platform_user_management'
      && request.method === 'PATCH',
    8000,
    'platform role edit request should reach API stub'
  );

  await evaluate(
    cdp,
    sessionId,
    `(() => { document.querySelector('[data-row-key="platform_user_management"]')?.click(); return true; })()`
  );
  await waitForCondition(
    cdp,
    sessionId,
    `(() => String(document.querySelector('.ant-drawer-title')?.textContent || '').includes('角色ID：platform_user_management'))()`,
    5000,
    'platform role detail drawer title should include role id'
  );
  await waitForCondition(
    cdp,
    sessionId,
    `Boolean(document.querySelector('[data-testid="platform-role-permission-tree"]'))`,
    5000,
    'platform role permission tree should be visible in drawer'
  );
  await waitForCondition(
    cdp,
    sessionId,
    `Boolean(document.querySelector('[data-testid="platform-role-detail-edit"]')) && Boolean(document.querySelector('[data-testid="platform-role-detail-status-toggle"]'))`,
    5000,
    'platform role detail drawer should show edit and status toggle actions'
  );
  await evaluate(
    cdp,
    sessionId,
    `(() => { document.querySelector('[data-testid="platform-role-detail-edit"]')?.click(); return true; })()`
  );
  await waitForCondition(
    cdp,
    sessionId,
    `(() => String(document.querySelector('.ant-modal-title')?.textContent || '').includes('编辑'))()`,
    5000,
    'role edit modal should be opened from drawer edit action'
  );
  await evaluate(
    cdp,
    sessionId,
    `(() => { document.querySelector('[data-testid="platform-role-edit-cancel"]')?.click(); return true; })()`
  );
  const roleDrawerStatusToggleRequestBaseline = api.requests.length;
  await evaluate(
    cdp,
    sessionId,
    `(() => { document.querySelector('[data-testid="platform-role-detail-status-toggle"]')?.click(); return true; })()`
  );
  await waitForRequest(
    api.requests,
    (request, index) =>
      index >= roleDrawerStatusToggleRequestBaseline
      && request.method === 'PATCH'
      && request.path === '/platform/roles/platform_user_management',
    8000,
    'platform role status toggle request should reach API stub from drawer'
  );
  const roleStatusToggleRequestFromDrawer = api.requests
    .slice(roleDrawerStatusToggleRequestBaseline)
    .find((request) => request.method === 'PATCH' && request.path === '/platform/roles/platform_user_management');
  assert.equal(
    roleStatusToggleRequestFromDrawer?.body?.status,
    'disabled',
    'drawer status toggle should submit disabled as target status for active role'
  );

  const screenshot = await cdp.send('Page.captureScreenshot', { format: 'png' }, sessionId);
  screenshotPath = join(evidenceDir, `chrome-platform-management-${timestamp}.png`);
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
  assert.equal(createUserRequest?.body?.name, '平台新用户');

  const updateUserRequest = api.requests.find(
    (request) => request.path === '/platform/users/platform-user-1' && request.method === 'PATCH'
  );
  assert.equal(updateUserRequest?.body?.name, '平台管理员甲（已编辑）');
  assert.equal(updateUserRequest?.body?.department, '平台治理中台');

  const updateStatusRequest = api.requests.find(
    (request) => request.path === '/platform/users/status' && request.method === 'POST'
  );
  assert.equal(updateStatusRequest?.body?.user_id, 'platform-user-1');
  assert.equal(updateStatusRequest?.body?.status, 'disabled');
  assert.equal(Object.prototype.hasOwnProperty.call(updateStatusRequest?.body || {}, 'reason'), false);

  const createRoleRequest = api.requests.find(
    (request) => request.path === '/platform/roles' && request.method === 'POST'
  );
  assert.equal(createRoleRequest?.body?.code, 'PLATFORM_TENANT_MANAGEMENT_ADMIN');
  assert.equal(createRoleRequest?.body?.name, '平台角色治理');

  const reportPath = join(evidenceDir, `chrome-platform-management-${timestamp}.json`);
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
          platform_user_header_name: true,
          platform_user_create_modal: true,
          platform_user_status_modal: true,
          platform_user_detail_drawer: true,
          platform_role_create_modal: true,
          protected_role_guard: true,
          platform_permission_tree_save: true
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

test('chrome regression validates tenant management workbench with modal/drawer and permission convergence', async (t) => {
  const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
  const evidenceDir = resolve(WORKSPACE_ROOT, 'artifacts/chrome-tenant-management');
  mkdirSync(evidenceDir, { recursive: true });

  const chromeBinary = resolveChromeBinary();
  const api = await createTenantManagementApiServer();
  const webPort = await reservePort();
  const cdpPort = await reservePort();
  const chromeProfileDir = mkdtempSync(join(tmpdir(), 'neweast-chrome-tenant-management-'));

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

  await cdp.send('Page.navigate', { url: `http://127.0.0.1:${webPort}/login/tenant` }, sessionId);
  await waitForCondition(
    cdp,
    sessionId,
    `Boolean(document.querySelector('[data-testid="page-title"]'))`,
    10000,
    'tenant login page should be visible'
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
      setter.call(phone, '13800000021');
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
    `Boolean(document.querySelector('[data-testid="tenant-org-switch-shell"]'))`,
    10000,
    'tenant entry login should require tenant switch page'
  );
  await evaluate(
    cdp,
    sessionId,
    `(() => {
      document.querySelector('[data-testid="tenant-org-switch-card-tenant-101"]')?.click();
      return true;
    })()`
  );
  await waitForCondition(
    cdp,
    sessionId,
    `Boolean(document.querySelector('[data-testid="tenant-management-panel"]'))`,
    12000,
    'tenant management panel should be visible after tenant selection'
  );
  await waitForCondition(
    cdp,
    sessionId,
    `Boolean(document.querySelector('[data-testid="tenant-member-user-id-tenant-user-admin"]'))`,
    12000,
    'tenant user table should load initial records'
  );
  await evaluate(
    cdp,
    sessionId,
    `(() => { document.querySelector('[data-testid="tenant-member-user-id-tenant-user-admin"]')?.click(); return true; })()`
  );
  await waitForCondition(
    cdp,
    sessionId,
    `(() => {
      const drawer = document.querySelector('[data-testid="tenant-member-detail-drawer"]');
      const title = String(document.querySelector('.ant-drawer-title')?.textContent || '');
      const text = String(drawer?.textContent || '');
      return (
        Boolean(drawer)
        && title.includes('用户ID:tenant-user-admin')
        && text.includes('手机号')
        && text.includes('组织管理员')
      );
    })()`,
    8000,
    'tenant user row click should open detail drawer'
  );
  await waitForCondition(
    cdp,
    sessionId,
    `Boolean(document.querySelector('[data-testid="tenant-member-detail-edit"]')) && Boolean(document.querySelector('[data-testid="tenant-member-detail-status"]'))`,
    8000,
    'tenant user detail drawer should show edit and status actions'
  );
  await evaluate(
    cdp,
    sessionId,
    `(() => {
      document.querySelector('.ant-drawer .ant-drawer-close')?.click();
      return true;
    })()`
  );
  await waitForRequest(
    api.requests,
    (request) =>
      request.method === 'GET'
      && request.path.includes('/tenant/users?')
      && request.path.includes('page=1')
      && request.path.includes('page_size=10'),
    8000,
    'tenant user list should request first page with page/page_size semantics'
  );
  await waitForCondition(
    cdp,
    sessionId,
    `(() => {
      const nextButton = document.querySelector('[data-testid="tenant-members-module"] .ant-pagination-next button');
      return Boolean(nextButton) && !nextButton.disabled;
    })()`,
    8000,
    'tenant user list should expose next page when more records exist'
  );
  await evaluate(
    cdp,
    sessionId,
    `(() => {
      document.querySelector('[data-testid="tenant-members-module"] .ant-pagination-next button')?.click();
      return true;
    })()`
  );
  await waitForRequest(
    api.requests,
    (request) =>
      request.method === 'GET'
      && request.path.includes('/tenant/users?')
      && request.path.includes('page=2')
      && request.path.includes('page_size=10'),
    8000,
    'tenant user pagination should request second page'
  );
  await waitForCondition(
    cdp,
    sessionId,
    `Boolean(document.querySelector('[data-testid="tenant-member-user-id-tenant-user-extra-9"]'))`,
    8000,
    'tenant user second page should render paged records'
  );
  await evaluate(
    cdp,
    sessionId,
    `(() => {
      document.querySelector('[data-testid="tenant-members-module"] .ant-pagination-prev button')?.click();
      return true;
    })()`
  );
  await waitForRequest(
    api.requests,
    (request) =>
      request.method === 'GET'
      && request.path.includes('/tenant/users?')
      && request.path.includes('page=1')
      && request.path.includes('page_size=10')
      && api.requests.filter(
        (entry) =>
          entry.method === 'GET'
          && entry.path.includes('/tenant/users?')
          && entry.path.includes('page=1')
          && entry.path.includes('page_size=10')
      ).length >= 2,
    8000,
    'tenant user pagination should support navigating back to first page'
  );
  await waitForCondition(
    cdp,
    sessionId,
    `(() => {
      const roleTab = document.querySelector('[data-testid="tenant-tab-roles"]');
      return roleTab === null;
    })()`,
    8000,
    'tenant permission panel should not expose role_management before role assignment'
  );

  await evaluate(
    cdp,
    sessionId,
    `(() => {
      const expandButton = [...document.querySelectorAll('[data-testid="tenant-members-module"] button')]
        .find((button) => String(button.textContent || '').includes('展开'));
      expandButton?.click();
      return true;
    })()`
  );
  await waitForCondition(
    cdp,
    sessionId,
    `Boolean(document.querySelector('[data-testid="tenant-member-filter-name"]'))`,
    8000,
    'tenant user filter name field should be available'
  );
  await evaluate(
    cdp,
    sessionId,
    `(() => {
      const input = document.querySelector('[data-testid="tenant-member-filter-name"]');
      if (!input) {
        return false;
      }
      const setter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value')?.set;
      setter.call(input, '成员乙');
      input.dispatchEvent(new Event('input', { bubbles: true }));
      input.dispatchEvent(new Event('change', { bubbles: true }));
      return true;
    })()`
  );
  await evaluate(
    cdp,
    sessionId,
    `(() => {
      const submit = document.querySelector('[data-testid="tenant-members-module"] button[type="submit"]');
      submit?.click();
      return true;
    })()`
  );
  await waitForCondition(
    cdp,
    sessionId,
    `Boolean(document.querySelector('[data-testid="tenant-member-user-id-tenant-user-02"]'))`,
    8000,
    'member filter should keep target member visible'
  );
  await evaluate(
    cdp,
    sessionId,
    `(() => {
      const input = document.querySelector('[data-testid="tenant-member-filter-name"]');
      if (!input) {
        return false;
      }
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
      const submit = document.querySelector('[data-testid="tenant-members-module"] button[type="submit"]');
      submit?.click();
      return true;
    })()`
  );

  await evaluate(
    cdp,
    sessionId,
    `(() => { document.querySelector('[data-testid="tenant-member-create-open"]').click(); return true; })()`
  );
  await waitForCondition(
    cdp,
    sessionId,
    `Boolean(document.querySelector('[data-testid="tenant-member-create-phone"]'))`,
    8000,
    'tenant user create modal should be visible'
  );
  await evaluate(
    cdp,
    sessionId,
    `(() => {
      const phoneInput = document.querySelector('[data-testid="tenant-member-create-phone"]');
      const nameInput = document.querySelector('[data-testid="tenant-member-create-display-name"]');
      const setter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value')?.set;
      setter.call(phoneInput, '13800000029');
      phoneInput.dispatchEvent(new Event('input', { bubbles: true }));
      phoneInput.dispatchEvent(new Event('change', { bubbles: true }));
      setter.call(nameInput, '新建成员甲');
      nameInput.dispatchEvent(new Event('input', { bubbles: true }));
      nameInput.dispatchEvent(new Event('change', { bubbles: true }));
      return true;
    })()`
  );
  await evaluate(
    cdp,
    sessionId,
    `(() => {
      const submit = document.querySelector('[data-testid="tenant-member-create-confirm"]');
      submit?.click();
      submit?.click();
      return true;
    })()`
  );
  await waitForRequest(
    api.requests,
    (request) => request.path === '/tenant/users' && request.method === 'POST',
    8000,
    'tenant user create request should reach API stub'
  );
  await sleep(500);
  assert.equal(
    api.requests.filter((request) => request.path === '/tenant/users' && request.method === 'POST').length,
    1,
    'loading lock should prevent duplicate create submissions'
  );
  await waitForCondition(
    cdp,
    sessionId,
    `(() => {
      return !document.querySelector('[data-testid="tenant-member-detail-drawer"]');
    })()`,
    8000,
    'tenant user create save should not auto-open detail drawer'
  );

  const tenantUserStatusToggleRequestBaseline = api.requests.length;
  await evaluate(
    cdp,
    sessionId,
    `(() => { document.querySelector('[data-testid="tenant-member-status-membership-tenant-101-admin"]').click(); return true; })()`
  );
  await waitForCondition(
    cdp,
    sessionId,
    `!Boolean(document.querySelector('[data-testid="tenant-member-status-reason"]'))`,
    8000,
    'tenant user status modal should not be visible'
  );
  await waitForRequest(
    api.requests,
    (request, index) =>
      index >= tenantUserStatusToggleRequestBaseline
      && request.method === 'PATCH'
      && request.path.includes('/tenant/users/membership-tenant-101-admin/status'),
    8000,
    'tenant user status patch should reach API stub'
  );
  const tenantUserStatusToggleRequest = api.requests
    .slice(tenantUserStatusToggleRequestBaseline)
    .find(
      (request) =>
        request.method === 'PATCH'
        && request.path.includes('/tenant/users/membership-tenant-101-admin/status')
    );
  assert.equal(
    tenantUserStatusToggleRequest?.body?.status,
    'disabled',
    'tenant user status toggle should submit disabled for active member'
  );
  assert.equal(
    Object.prototype.hasOwnProperty.call(tenantUserStatusToggleRequest?.body || {}, 'reason'),
    false,
    'tenant user status toggle should not include reason'
  );
  await waitForRequest(
    api.responses,
    (response) =>
      response.method === 'PATCH'
      && response.path.includes('/tenant/users/membership-tenant-101-admin/status')
      && response.status === 200,
    8000,
    'tenant user status patch should return success'
  );
  await evaluate(
    cdp,
    sessionId,
    `(() => { document.querySelector('[data-testid="tenant-member-profile-membership-tenant-101-admin"]').click(); return true; })()`
  );
  await waitForCondition(
    cdp,
    sessionId,
    `Boolean(document.querySelector('[data-testid="tenant-member-profile-display-name"]'))`,
    8000,
    'tenant user profile modal should be visible'
  );
  await evaluate(
    cdp,
    sessionId,
    `(() => {
      const input = document.querySelector('[data-testid="tenant-member-profile-display-name"]');
      const setter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value')?.set;
      setter.call(input, 'FAIL-DEPENDENCY');
      input.dispatchEvent(new Event('input', { bubbles: true }));
      input.dispatchEvent(new Event('change', { bubbles: true }));
      return true;
    })()`
  );
  await waitForButtonEnabledByTestId(
    cdp,
    sessionId,
    'tenant-member-profile-confirm',
    10000,
    'tenant user profile confirm should be enabled before dependency failure submission'
  );
  await evaluate(
    cdp,
    sessionId,
    `(() => { document.querySelector('[data-testid="tenant-member-profile-confirm"]').click(); return true; })()`
  );
  await waitForRequest(
    api.responses,
    (response) =>
      response.method === 'PATCH'
      && response.path.includes('/tenant/users/membership-tenant-101-admin/profile')
      && response.status === 503,
    8000,
    'tenant user profile dependency failure should be observable'
  );
  await evaluate(
    cdp,
    sessionId,
    `(() => {
      const nameInput = document.querySelector('[data-testid="tenant-member-profile-display-name"]');
      const deptInput = document.querySelector('[data-testid="tenant-member-profile-department-name"]');
      const setter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value')?.set;
      setter.call(nameInput, '组织管理员（更新）');
      nameInput.dispatchEvent(new Event('input', { bubbles: true }));
      nameInput.dispatchEvent(new Event('change', { bubbles: true }));
      setter.call(deptInput, '运营一部');
      deptInput.dispatchEvent(new Event('input', { bubbles: true }));
      deptInput.dispatchEvent(new Event('change', { bubbles: true }));
      return true;
    })()`
  );
  await waitForButtonEnabledByTestId(
    cdp,
    sessionId,
    'tenant-member-profile-confirm',
    10000,
    'tenant user profile confirm should be enabled before retry submission'
  );
  await evaluate(
    cdp,
    sessionId,
    `(() => { document.querySelector('[data-testid="tenant-member-profile-confirm"]').click(); return true; })()`
  );
  await waitForRequest(
    api.responses,
    (response) =>
      response.method === 'PATCH'
      && response.path.includes('/tenant/users/membership-tenant-101-admin/profile')
      && response.status === 200,
    8000,
    'tenant user profile update should succeed after retry'
  );
  await waitForCondition(
    cdp,
    sessionId,
    `(() => !document.querySelector('[data-testid="tenant-member-detail-drawer"]'))()`,
    5000,
    'tenant user profile save should not auto-open detail drawer'
  );
  await waitForCondition(
    cdp,
    sessionId,
    `(() => !document.querySelector('[data-testid="tenant-menu-account-matrix"]'))()`,
    8000,
    'tenant account matrix menu should stay hidden before account permissions are granted'
  );

  await evaluate(
    cdp,
    sessionId,
    `(() => { document.querySelector('[data-testid="tenant-member-profile-membership-tenant-101-admin"]').click(); return true; })()`
  );
  await waitForCondition(
    cdp,
    sessionId,
    `Boolean(document.querySelector('[data-testid="tenant-member-profile-role-ids"]'))`,
    8000,
    'tenant user edit modal should be visible for role update'
  );
  await evaluate(
    cdp,
    sessionId,
    `(() => {
      const select = document.querySelector('[data-testid="tenant-member-profile-role-ids"]');
      const trigger = select?.querySelector('.ant-select-selector') || select;
      trigger?.dispatchEvent(new MouseEvent('mousedown', { bubbles: true }));
      return Boolean(trigger);
    })()`
  );
  await waitForCondition(
    cdp,
    sessionId,
    `(() => {
      const targetOption = [...document.querySelectorAll('.ant-select-item-option')]
        .find((node) => String(node.textContent || '').includes('组织角色治理'));
      return Boolean(targetOption);
    })()`,
    8000,
    'tenant user role select should expose role option'
  );
  await evaluate(
    cdp,
    sessionId,
    `(() => {
      const targetOption = [...document.querySelectorAll('.ant-select-item-option')]
        .find((node) => String(node.textContent || '').includes('组织角色治理'));
      targetOption?.dispatchEvent(new MouseEvent('mousedown', { bubbles: true }));
      targetOption?.click();
      return Boolean(targetOption);
    })()`
  );
  const tenantOptionsRefreshCountBeforeRoleAssignment = api.requests.filter(
    (request) => request.method === 'GET' && request.path === '/auth/tenant/options'
  ).length;
  await waitForButtonEnabledByTestId(
    cdp,
    sessionId,
    'tenant-member-profile-confirm',
    10000,
    'tenant user profile confirm should be enabled before role assignment submission'
  );
  await evaluate(
    cdp,
    sessionId,
    `(() => { document.querySelector('[data-testid="tenant-member-profile-confirm"]').click(); return true; })()`
  );
  await waitForRequest(
    api.requests,
    (request) =>
      request.method === 'PUT'
      && request.path.includes('/tenant/users/membership-tenant-101-admin/roles'),
    8000,
    'tenant user edit should submit role replacement request'
  );
  await waitForRequest(
    api.responses,
    (response) =>
      response.method === 'PUT'
      && response.path.includes('/tenant/users/membership-tenant-101-admin/roles')
      && response.status === 200,
    8000,
    'tenant user roles replace request should return success before permission refresh'
  );
  await waitForRequest(
    api.requests,
    (request) =>
      request.method === 'GET'
      && request.path === '/auth/tenant/options'
      && api.requests.filter(
        (entry) => entry.method === 'GET' && entry.path === '/auth/tenant/options'
      ).length > tenantOptionsRefreshCountBeforeRoleAssignment,
    12000,
    'tenant permission refresh should call /auth/tenant/options after role assignment'
  );
  await waitForCondition(
    cdp,
    sessionId,
    `(() => {
      const membersModule = document.querySelector('[data-testid="tenant-members-module"]');
      const roleTab = document.querySelector('[data-testid="tenant-tab-roles"]');
      return Boolean(membersModule) && Boolean(roleTab);
    })()`,
    15000,
    'tenant permission panel should converge immediately after role assignment'
  );
  await waitForCondition(
    cdp,
    sessionId,
    `(() => {
      const customerMenu = document.querySelector('[data-testid="tenant-menu-customer-management"]');
      const accountMenu = document.querySelector('[data-testid="tenant-menu-account-matrix"]');
      if (!customerMenu || !accountMenu) {
        return false;
      }
      return Boolean(customerMenu.compareDocumentPosition(accountMenu) & Node.DOCUMENT_POSITION_FOLLOWING);
    })()`,
    10000,
    'customer management menu should appear before account matrix menu'
  );
  await evaluate(
    cdp,
    sessionId,
    `(() => { document.querySelector('[data-testid="tenant-menu-customer-management"]')?.click(); return true; })()`
  );
  await waitForCondition(
    cdp,
    sessionId,
    `Boolean(document.querySelector('[data-testid="tenant-tab-customer-profile"]'))`,
    8000,
    'customer profile submenu item should be visible after expanding customer management menu'
  );
  await evaluate(
    cdp,
    sessionId,
    `(() => { document.querySelector('[data-testid="tenant-tab-customer-profile"]')?.click(); return true; })()`
  );
  await waitForCondition(
    cdp,
    sessionId,
    `Boolean(document.querySelector('[data-testid="tenant-customers-module"]'))`,
    10000,
    'customer profile module should be visible'
  );
  await waitForCondition(
    cdp,
    sessionId,
    `(() => {
      const tabMy = document.querySelector('[data-testid="tenant-customer-tab-my"]');
      const tabAssist = document.querySelector('[data-testid="tenant-customer-tab-assist"]');
      const tabAll = document.querySelector('[data-testid="tenant-customer-tab-all"]');
      return Boolean(tabMy) && Boolean(tabAssist) && Boolean(tabAll);
    })()`,
    10000,
    'customer scope tabs should be visible according to permissions'
  );
  await evaluate(
    cdp,
    sessionId,
    `(() => {
      document.querySelector('[data-testid="tenant-customer-tab-all"]')?.click();
      return true;
    })()`
  );
  await waitForCondition(
    cdp,
    sessionId,
    `Boolean(document.querySelector('[data-testid="tenant-customer-id-customer-tenant-101-1"]'))`,
    10000,
    'customer list should render initial records'
  );
  await evaluate(
    cdp,
    sessionId,
    `(() => {
      document.querySelector('[data-testid="tenant-customer-create-open"]')?.click();
      return true;
    })()`
  );
  await waitForCondition(
    cdp,
    sessionId,
    `Boolean(document.querySelector('[data-testid="tenant-customer-create-account-id"]'))`,
    10000,
    'customer create modal should be visible'
  );
  await evaluate(
    cdp,
    sessionId,
    `(() => {
      const setter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value')?.set;
      const accountSelect = document.querySelector('[data-testid="tenant-customer-create-account-id"]');
      const accountTrigger = accountSelect?.querySelector('.ant-select-selector') || accountSelect;
      const sourceSelect = document.querySelector('[data-testid="tenant-customer-create-source"]');
      const sourceTrigger = sourceSelect?.querySelector('.ant-select-selector') || sourceSelect;
      const wechatInput = document.querySelector('[data-testid="tenant-customer-create-wechat-id"]');
      const nicknameInput = document.querySelector('[data-testid="tenant-customer-create-nickname"]');

      accountTrigger?.dispatchEvent(new MouseEvent('mousedown', { bubbles: true }));
      accountTrigger?.dispatchEvent(new MouseEvent('click', { bubbles: true }));
      return Boolean(accountTrigger && sourceTrigger && wechatInput && nicknameInput);
    })()`
  );
  await waitForCondition(
    cdp,
    sessionId,
    `(() => {
      const option = [...document.querySelectorAll('.ant-select-item-option')]
        .find((node) => String(node.textContent || '').includes('管理员主号'));
      return Boolean(option);
    })()`,
    10000,
    'customer create account selector should expose account option'
  );
  await evaluate(
    cdp,
    sessionId,
    `(() => {
      const option = [...document.querySelectorAll('.ant-select-item-option')]
        .find((node) => String(node.textContent || '').includes('管理员主号'));
      option?.dispatchEvent(new MouseEvent('mousedown', { bubbles: true }));
      option?.click();
      return Boolean(option);
    })()`
  );
  await evaluate(
    cdp,
    sessionId,
    `(() => {
      const setter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value')?.set;
      const sourceSelect = document.querySelector('[data-testid="tenant-customer-create-source"]');
      const sourceTrigger = sourceSelect?.querySelector('.ant-select-selector') || sourceSelect;
      const wechatInput = document.querySelector('[data-testid="tenant-customer-create-wechat-id"]');
      const nicknameInput = document.querySelector('[data-testid="tenant-customer-create-nickname"]');
      setter.call(wechatInput, 'wx_customer_101_new');
      wechatInput.dispatchEvent(new Event('input', { bubbles: true }));
      wechatInput.dispatchEvent(new Event('change', { bubbles: true }));
      setter.call(nicknameInput, '客户新增甲');
      nicknameInput.dispatchEvent(new Event('input', { bubbles: true }));
      nicknameInput.dispatchEvent(new Event('change', { bubbles: true }));
      sourceTrigger?.dispatchEvent(new MouseEvent('mousedown', { bubbles: true }));
      sourceTrigger?.dispatchEvent(new MouseEvent('click', { bubbles: true }));
      return true;
    })()`
  );
  await waitForCondition(
    cdp,
    sessionId,
    `(() => {
      const option = [...document.querySelectorAll('.ant-select-item-option')]
        .find((node) => String(node.textContent || '').includes('地推'));
      return Boolean(option);
    })()`,
    10000,
    'customer create source selector should expose source option'
  );
  await evaluate(
    cdp,
    sessionId,
    `(() => {
      const option = [...document.querySelectorAll('.ant-select-item-option')]
        .find((node) => String(node.textContent || '').includes('地推'));
      option?.dispatchEvent(new MouseEvent('mousedown', { bubbles: true }));
      option?.click();
      return Boolean(option);
    })()`
  );
  await waitForButtonEnabledByTestId(
    cdp,
    sessionId,
    'tenant-customer-create-confirm',
    10000,
    'tenant customer create confirm should be enabled before submission'
  );
  await evaluate(
    cdp,
    sessionId,
    `(() => { document.querySelector('[data-testid="tenant-customer-create-confirm"]')?.click(); return true; })()`
  );
  await waitForRequest(
    api.requests,
    (request) => request.path === '/tenant/customers' && request.method === 'POST',
    10000,
    'tenant customer create request should reach API stub'
  );
  await waitForCondition(
    cdp,
    sessionId,
    `Boolean(document.querySelector('[data-testid="tenant-customer-id-customer-tenant-101-3"]'))`,
    10000,
    'customer list should render newly created customer'
  );
  await evaluate(
    cdp,
    sessionId,
    `(() => {
      const row = document.querySelector('[data-row-key="customer-tenant-101-3"]');
      row?.click();
      return Boolean(row);
    })()`
  );
  await waitForCondition(
    cdp,
    sessionId,
    `Boolean(document.querySelector('[data-testid="tenant-customer-detail-drawer"]'))`,
    10000,
    'customer row click should open detail drawer'
  );
  await evaluate(
    cdp,
    sessionId,
    `(() => { document.querySelector('[data-testid="tenant-customer-detail-edit-basic"]')?.click(); return true; })()`
  );
  await waitForCondition(
    cdp,
    sessionId,
    `Boolean(document.querySelector('[data-testid="tenant-customer-basic-source"]'))`,
    8000,
    'customer basic edit modal should be visible'
  );
  await evaluate(
    cdp,
    sessionId,
    `(() => {
      const sourceSelect = document.querySelector('[data-testid="tenant-customer-basic-source"]');
      const sourceTrigger = sourceSelect?.querySelector('.ant-select-selector') || sourceSelect;
      sourceTrigger?.dispatchEvent(new MouseEvent('mousedown', { bubbles: true }));
      sourceTrigger?.dispatchEvent(new MouseEvent('click', { bubbles: true }));
      return Boolean(sourceTrigger);
    })()`
  );
  await waitForCondition(
    cdp,
    sessionId,
    `(() => {
      const option = [...document.querySelectorAll('.ant-select-item-option')]
        .find((node) => String(node.textContent || '').includes('裂变'));
      return Boolean(option);
    })()`,
    8000,
    'customer basic source selector should expose fission option'
  );
  await evaluate(
    cdp,
    sessionId,
    `(() => {
      const option = [...document.querySelectorAll('.ant-select-item-option')]
        .find((node) => String(node.textContent || '').includes('裂变'));
      option?.dispatchEvent(new MouseEvent('mousedown', { bubbles: true }));
      option?.click();
      return Boolean(option);
    })()`
  );
  await evaluate(
    cdp,
    sessionId,
    `(() => { document.querySelector('[data-testid="tenant-customer-basic-confirm"]')?.click(); return true; })()`
  );
  await waitForRequest(
    api.requests,
    (request) => request.path === '/tenant/customers/customer-tenant-101-3/basic' && request.method === 'PATCH',
    10000,
    'tenant customer basic edit request should reach API stub'
  );
  await waitForCondition(
    cdp,
    sessionId,
    `(() => {
      const drawer = document.querySelector('[data-testid="tenant-customer-detail-drawer"]');
      return Boolean(drawer && String(drawer.textContent || '').includes('裂变'));
    })()`,
    10000,
    'customer detail drawer should reflect updated source'
  );
  await evaluate(
    cdp,
    sessionId,
    `(() => { document.querySelector('[data-testid="tenant-customer-detail-edit-realname"]')?.click(); return true; })()`
  );
  await waitForCondition(
    cdp,
    sessionId,
    `Boolean(document.querySelector('[data-testid="tenant-customer-realname-name"]'))`,
    8000,
    'customer realname edit modal should be visible'
  );
  await evaluate(
    cdp,
    sessionId,
    `(() => {
      const setter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value')?.set;
      const nameInput = document.querySelector('[data-testid="tenant-customer-realname-name"]');
      const schoolInput = document.querySelector('[data-testid="tenant-customer-realname-school"]');
      setter.call(nameInput, '王五');
      nameInput.dispatchEvent(new Event('input', { bubbles: true }));
      nameInput.dispatchEvent(new Event('change', { bubbles: true }));
      setter.call(schoolInput, '第三中学');
      schoolInput.dispatchEvent(new Event('input', { bubbles: true }));
      schoolInput.dispatchEvent(new Event('change', { bubbles: true }));
      return true;
    })()`
  );
  await evaluate(
    cdp,
    sessionId,
    `(() => { document.querySelector('[data-testid="tenant-customer-realname-confirm"]')?.click(); return true; })()`
  );
  await waitForRequest(
    api.requests,
    (request) => request.path === '/tenant/customers/customer-tenant-101-3/realname' && request.method === 'PATCH',
    10000,
    'tenant customer realname edit request should reach API stub'
  );
  await waitForCondition(
    cdp,
    sessionId,
    `(() => {
      const drawer = document.querySelector('[data-testid="tenant-customer-detail-drawer"]');
      return Boolean(drawer && String(drawer.textContent || '').includes('王五') && String(drawer.textContent || '').includes('第三中学'));
    })()`,
    10000,
    'customer detail drawer should reflect updated realname information'
  );
  await evaluate(
    cdp,
    sessionId,
    `(() => {
      const drawer = document.querySelector('[data-testid="tenant-customer-detail-drawer"]');
      const timelineTab = [...(drawer?.querySelectorAll('.ant-tabs-tab') || [])]
        .find((tab) => String(tab.textContent || '').includes('操作记录'));
      timelineTab?.click();
      return Boolean(timelineTab);
    })()`
  );
  await waitForCondition(
    cdp,
    sessionId,
    `Boolean(document.querySelector('[data-testid="tenant-customer-log-0"]'))`,
    10000,
    'customer operation timeline should render entries'
  );
  await evaluate(
    cdp,
    sessionId,
    `(() => {
      document.querySelector('.ant-drawer .ant-drawer-close')?.click();
      return true;
    })()`
  );

  await waitForCondition(
    cdp,
    sessionId,
    `Boolean(document.querySelector('[data-testid="tenant-menu-account-matrix"]'))`,
    10000,
    'tenant account management menu should become visible after account permissions are granted'
  );
  await evaluate(
    cdp,
    sessionId,
    `(() => { document.querySelector('[data-testid="tenant-menu-account-matrix"]')?.click(); return true; })()`
  );
  await waitForCondition(
    cdp,
    sessionId,
    `Boolean(document.querySelector('[data-testid="tenant-tab-accounts"]'))`,
    8000,
    'tenant account submenu item should be visible after expanding account matrix menu'
  );
  await evaluate(
    cdp,
    sessionId,
    `(() => { document.querySelector('[data-testid="tenant-tab-accounts"]')?.click(); return true; })()`
  );
  await waitForCondition(
    cdp,
    sessionId,
    `Boolean(document.querySelector('[data-testid="tenant-accounts-module"]'))`,
    10000,
    'tenant account management module should be visible'
  );
  await waitForCondition(
    cdp,
    sessionId,
    `Boolean(document.querySelector('[data-testid="tenant-account-id-account-tenant-101-1"]'))`,
    10000,
    'tenant account list should render initial records'
  );
  await evaluate(
    cdp,
    sessionId,
    `(() => { document.querySelector('[data-testid="tenant-account-create-open"]')?.click(); return true; })()`
  );
  await waitForCondition(
    cdp,
    sessionId,
    `Boolean(document.querySelector('[data-testid="tenant-account-edit-wechat-id"]'))`,
    8000,
    'tenant account create modal should be visible'
  );
  await evaluate(
    cdp,
    sessionId,
    `(() => {
      const setter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value')?.set;
      const wechatInput = document.querySelector('[data-testid="tenant-account-edit-wechat-id"]');
      const nicknameInput = document.querySelector('[data-testid="tenant-account-edit-nickname"]');
      const ownerSelect = document.querySelector('[data-testid="tenant-account-edit-owner-membership-id"]');
      const ownerTrigger = ownerSelect?.querySelector('.ant-select-selector') || ownerSelect;
      setter.call(wechatInput, 'wx_tenant_101_new');
      wechatInput.dispatchEvent(new Event('input', { bubbles: true }));
      wechatInput.dispatchEvent(new Event('change', { bubbles: true }));
      setter.call(nicknameInput, '新建账号甲');
      nicknameInput.dispatchEvent(new Event('input', { bubbles: true }));
      nicknameInput.dispatchEvent(new Event('change', { bubbles: true }));
      ownerTrigger?.dispatchEvent(new MouseEvent('mousedown', { bubbles: true }));
      ownerTrigger?.dispatchEvent(new MouseEvent('click', { bubbles: true }));
      return true;
    })()`
  );
  await waitForCondition(
    cdp,
    sessionId,
    `(() => {
      return Boolean(document.querySelector('.ant-select-item-option'));
    })()`,
    12000,
    'tenant account owner selector should expose owner option'
  );
  await waitForCondition(
    cdp,
    sessionId,
    `(() => {
      const optionTexts = Array.from(
        document.querySelectorAll('.ant-select-item-option .ant-select-item-option-content')
      ).map((node) => String(node.textContent || '').trim()).filter(Boolean);
      if (optionTexts.length < 1) {
        return false;
      }
      const hasPhoneLabel = optionTexts.some((text) => /\\d{11}/.test(text));
      const hasMembershipIdLabel = optionTexts.some((text) => text.includes('membership-'));
      const hasDisabledMemberLabel = optionTexts.some((text) => text.includes('组织管理员（更新）'));
      return hasPhoneLabel && !hasMembershipIdLabel && !hasDisabledMemberLabel;
    })()`,
    12000,
    'tenant account owner options should use phone labels and only include active members'
  );
  await evaluate(
    cdp,
    sessionId,
    `(() => {
      const ownerOption = document.querySelector('.ant-select-item-option');
      ownerOption?.dispatchEvent(new MouseEvent('mousedown', { bubbles: true }));
      ownerOption?.click();
      return Boolean(ownerOption);
    })()`
  );
  await waitForButtonEnabledByTestId(
    cdp,
    sessionId,
    'tenant-account-create-confirm',
    10000,
    'tenant account create confirm should be enabled before submission'
  );
  await evaluate(
    cdp,
    sessionId,
    `(() => { document.querySelector('[data-testid="tenant-account-create-confirm"]')?.click(); return true; })()`
  );
  await waitForRequest(
    api.requests,
    (request) => request.path === '/tenant/accounts' && request.method === 'POST',
    10000,
    'tenant account create request should reach API stub'
  );
  await waitForCondition(
    cdp,
    sessionId,
    `Boolean(document.querySelector('[data-testid="tenant-account-id-account-tenant-101-3"]'))`,
    10000,
    'tenant account list should render newly created account'
  );
  await evaluate(
    cdp,
    sessionId,
    `(() => { document.querySelector('[data-testid="tenant-account-edit-account-tenant-101-3"]')?.click(); return true; })()`
  );
  await waitForCondition(
    cdp,
    sessionId,
    `Boolean(document.querySelector('[data-testid="tenant-account-edit-confirm"]'))`,
    8000,
    'tenant account edit modal should be visible'
  );
  await evaluate(
    cdp,
    sessionId,
    `(() => {
      const setter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value')?.set;
      const nicknameInput = document.querySelector('[data-testid="tenant-account-edit-nickname"]');
      setter.call(nicknameInput, '新建账号甲-已编辑');
      nicknameInput.dispatchEvent(new Event('input', { bubbles: true }));
      nicknameInput.dispatchEvent(new Event('change', { bubbles: true }));
      return true;
    })()`
  );
  await waitForButtonEnabledByTestId(
    cdp,
    sessionId,
    'tenant-account-edit-confirm',
    10000,
    'tenant account edit confirm should be enabled before submission'
  );
  await evaluate(
    cdp,
    sessionId,
    `(() => { document.querySelector('[data-testid="tenant-account-edit-confirm"]')?.click(); return true; })()`
  );
  await waitForRequest(
    api.requests,
    (request) => request.path === '/tenant/accounts/account-tenant-101-3' && request.method === 'PATCH',
    10000,
    'tenant account edit request should reach API stub'
  );
  await waitForRequest(
    api.responses,
    (response) => response.path === '/tenant/accounts/account-tenant-101-3' && response.method === 'PATCH' && response.status === 200,
    10000,
    'tenant account edit request should succeed'
  );
  await waitForCondition(
    cdp,
    sessionId,
    `(() => {
      const row = document.querySelector('[data-row-key="account-tenant-101-3"]');
      return Boolean(row && String(row.textContent || '').includes('新建账号甲-已编辑'));
    })()`,
    10000,
    'tenant account row should reflect edited nickname'
  );
  await evaluate(
    cdp,
    sessionId,
    `(() => { document.querySelector('[data-testid="tenant-account-status-account-tenant-101-3"]')?.click(); return true; })()`
  );
  await waitForRequest(
    api.requests,
    (request) => request.path === '/tenant/accounts/account-tenant-101-3/status' && request.method === 'PATCH',
    10000,
    'tenant account status toggle request should reach API stub'
  );
  await waitForRequest(
    api.responses,
    (response) => response.path === '/tenant/accounts/account-tenant-101-3/status' && response.method === 'PATCH' && response.status === 200,
    10000,
    'tenant account status toggle request should succeed'
  );
  await waitForCondition(
    cdp,
    sessionId,
    `(() => {
      const row = document.querySelector('[data-row-key="account-tenant-101-3"]');
      return Boolean(row && String(row.textContent || '').includes('禁用'));
    })()`,
    10000,
    'tenant account row should reflect disabled status after toggle'
  );
  await waitForCondition(
    cdp,
    sessionId,
    `(() => {
      const drawer = document.querySelector('[data-testid="tenant-account-detail-drawer"]');
      if (drawer) {
        return true;
      }
      const row = document.querySelector('[data-row-key="account-tenant-101-3"]');
      const accountIdCell = row?.querySelector('[data-testid="tenant-account-id-account-tenant-101-3"]');
      accountIdCell?.dispatchEvent(new MouseEvent('click', { bubbles: true }));
      row?.dispatchEvent(new MouseEvent('click', { bubbles: true }));
      return false;
    })()`,
    10000,
    'tenant account row click should open detail drawer'
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
    `(() => { document.querySelector('[data-testid="tenant-tab-roles"]').click(); return true; })()`
  );
  await waitForCondition(
    cdp,
    sessionId,
    `Boolean(document.querySelector('[data-testid="tenant-roles-module"]'))`,
    8000,
    'tenant role module should be visible'
  );
  await evaluate(
    cdp,
    sessionId,
    `(() => {
      const expandButton = [...document.querySelectorAll('[data-testid="tenant-roles-module"] button')]
        .find((button) => String(button.textContent || '').includes('展开'));
      expandButton?.click();
      return true;
    })()`
  );
  await waitForCondition(
    cdp,
    sessionId,
    `Boolean(document.querySelector('[data-testid="tenant-role-filter-name"]'))`,
    8000,
    'tenant role filter name field should be available'
  );

  await evaluate(
    cdp,
    sessionId,
    `(() => {
      const codeInput = document.querySelector('[data-testid="tenant-role-filter-code"]');
      const nameInput = document.querySelector('[data-testid="tenant-role-filter-name"]');
      const setter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value')?.set;
      setter.call(codeInput, 'TENANT_USER_MANAGEMENT');
      codeInput.dispatchEvent(new Event('input', { bubbles: true }));
      codeInput.dispatchEvent(new Event('change', { bubbles: true }));
      setter.call(nameInput, '');
      nameInput.dispatchEvent(new Event('input', { bubbles: true }));
      nameInput.dispatchEvent(new Event('change', { bubbles: true }));
      document.querySelector('[data-testid="tenant-roles-module"] button[type="submit"]')?.click();
      return true;
    })()`
  );
  await waitForCondition(
    cdp,
    sessionId,
    `(() => {
      const hasUserManagement = Boolean(document.querySelector('[data-row-key="tenant_user_management"]'));
      const hasRoleManagementAdmin = Boolean(document.querySelector('[data-row-key="tenant_role_management_admin"]'));
      return hasUserManagement && !hasRoleManagementAdmin;
    })()`,
    8000,
    'tenant role code exact filter should keep only matched code'
  );
  await evaluate(
    cdp,
    sessionId,
    `(() => {
      const codeInput = document.querySelector('[data-testid="tenant-role-filter-code"]');
      const nameInput = document.querySelector('[data-testid="tenant-role-filter-name"]');
      const setter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value')?.set;
      setter.call(codeInput, '');
      codeInput.dispatchEvent(new Event('input', { bubbles: true }));
      codeInput.dispatchEvent(new Event('change', { bubbles: true }));
      setter.call(nameInput, '角色');
      nameInput.dispatchEvent(new Event('input', { bubbles: true }));
      nameInput.dispatchEvent(new Event('change', { bubbles: true }));
      document.querySelector('[data-testid="tenant-roles-module"] button[type="submit"]')?.click();
      return true;
    })()`
  );
  await waitForCondition(
    cdp,
    sessionId,
    `(() => {
      const hasUserManagement = Boolean(document.querySelector('[data-row-key="tenant_user_management"]'));
      const hasRoleManagementAdmin = Boolean(document.querySelector('[data-row-key="tenant_role_management_admin"]'));
      return !hasUserManagement && hasRoleManagementAdmin;
    })()`,
    8000,
    'tenant role name fuzzy filter should keep matched rows'
  );
  await evaluate(
    cdp,
    sessionId,
    `(() => {
      const codeInput = document.querySelector('[data-testid="tenant-role-filter-code"]');
      const nameInput = document.querySelector('[data-testid="tenant-role-filter-name"]');
      const setter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value')?.set;
      setter.call(codeInput, '');
      codeInput.dispatchEvent(new Event('input', { bubbles: true }));
      codeInput.dispatchEvent(new Event('change', { bubbles: true }));
      setter.call(nameInput, '');
      nameInput.dispatchEvent(new Event('input', { bubbles: true }));
      nameInput.dispatchEvent(new Event('change', { bubbles: true }));
      document.querySelector('[data-testid="tenant-roles-module"] button[type="submit"]')?.click();
      return true;
    })()`
  );
  await waitForCondition(
    cdp,
    sessionId,
    `(() => Boolean(document.querySelector('[data-testid="tenant-role-edit-tenant_role_management_admin"]')))()`,
    8000,
    'tenant role filters reset should recover full role list'
  );
  await waitForCondition(
    cdp,
    sessionId,
    `(() => !document.querySelector('[data-testid="tenant-role-delete-tenant_user_management"]'))()`,
    8000,
    'active tenant role should not show delete action'
  );
  await evaluate(
    cdp,
    sessionId,
    `(() => { document.querySelector('[data-testid="tenant-role-status-tenant_role_management_admin"]')?.click(); return true; })()`
  );
  await waitForRequest(
    api.requests,
    (request) =>
      request.method === 'PATCH'
      && request.path.includes('/tenant/roles/tenant_role_management_admin')
      && request.body?.status === 'disabled',
    8000,
    'tenant role status update should allow disabling non-system roles'
  );
  await evaluate(
    cdp,
    sessionId,
    `(() => {
      const select = document.querySelector('[data-testid="tenant-role-filter-status"]');
      const trigger = select?.querySelector('.ant-select-selector') || select;
      trigger?.dispatchEvent(new MouseEvent('mousedown', { bubbles: true }));
      return Boolean(trigger);
    })()`
  );
  await waitForCondition(
    cdp,
    sessionId,
    `(() => {
      const option = [...document.querySelectorAll('.ant-select-item-option')]
        .find((node) => String(node.textContent || '').includes('禁用'));
      return Boolean(option);
    })()`,
    8000,
    'tenant role status option disabled should be visible'
  );
  await evaluate(
    cdp,
    sessionId,
    `(() => {
      const option = [...document.querySelectorAll('.ant-select-item-option')]
        .find((node) => String(node.textContent || '').includes('禁用'));
      option?.dispatchEvent(new MouseEvent('mousedown', { bubbles: true }));
      option?.click();
      document.querySelector('[data-testid="tenant-roles-module"] button[type="submit"]')?.click();
      return true;
    })()`
  );
  await waitForCondition(
    cdp,
    sessionId,
    `(() => {
      const hasUserManagement = Boolean(document.querySelector('[data-row-key="tenant_user_management"]'));
      const hasRoleManagementAdmin = Boolean(document.querySelector('[data-row-key="tenant_role_management_admin"]'));
      return !hasUserManagement && hasRoleManagementAdmin;
    })()`,
    8000,
    'tenant role status filter should keep only disabled roles'
  );
  await waitForCondition(
    cdp,
    sessionId,
    `(() => Boolean(document.querySelector('[data-testid="tenant-role-delete-tenant_role_management_admin"]')))()`,
    8000,
    'disabled tenant role should show delete action'
  );
  await evaluate(
    cdp,
    sessionId,
    `(() => {
      const select = document.querySelector('[data-testid="tenant-role-filter-status"]');
      const trigger = select?.querySelector('.ant-select-selector') || select;
      trigger?.dispatchEvent(new MouseEvent('mousedown', { bubbles: true }));
      return Boolean(trigger);
    })()`
  );
  await waitForCondition(
    cdp,
    sessionId,
    `(() => {
      const option = [...document.querySelectorAll('.ant-select-item-option')]
        .find((node) => String(node.textContent || '').includes('全部'));
      return Boolean(option);
    })()`,
    8000,
    'tenant role status option all should be visible'
  );
  await evaluate(
    cdp,
    sessionId,
    `(() => {
      const option = [...document.querySelectorAll('.ant-select-item-option')]
        .find((node) => String(node.textContent || '').includes('全部'));
      option?.dispatchEvent(new MouseEvent('mousedown', { bubbles: true }));
      option?.click();
      document.querySelector('[data-testid="tenant-roles-module"] button[type="submit"]')?.click();
      return true;
    })()`
  );
  await waitForCondition(
    cdp,
    sessionId,
    `(() => Boolean(document.querySelector('[data-testid="tenant-role-edit-tenant_owner"]')))()`,
    8000,
    'tenant role status filter reset should recover protected role row'
  );
  await evaluate(
    cdp,
    sessionId,
    `(() => {
      const row = document.querySelector('[data-row-key="tenant_user_management"]');
      row?.focus();
      row?.dispatchEvent(new KeyboardEvent('keydown', { key: 'Enter', bubbles: true }));
      return true;
    })()`
  );
  await waitForCondition(
    cdp,
    sessionId,
    `Boolean(document.querySelector('[data-testid="tenant-role-detail-drawer"]'))`,
    8000,
    'tenant role row keyboard enter should open detail drawer'
  );
  await evaluate(
    cdp,
    sessionId,
    `(() => {
      document.querySelector('.ant-drawer .ant-drawer-close')?.click();
      return true;
    })()`
  );
  await waitForCondition(
    cdp,
    sessionId,
    `(() => !document.querySelector('[data-testid="tenant-role-detail-drawer"]'))()`,
    8000,
    'tenant role detail drawer should close after keyboard-open check'
  );
  await evaluate(
    cdp,
    sessionId,
    `(() => { document.querySelector('[data-testid="tenant-role-edit-tenant_owner"]')?.click(); return true; })()`
  );
  await waitForCondition(
    cdp,
    sessionId,
    `(() => {
      const modal = document.querySelector('[data-testid="tenant-role-edit-name"]');
      const drawer = document.querySelector('[data-testid="tenant-role-detail-drawer"]');
      return Boolean(modal) && !drawer;
    })()`,
    8000,
    'tenant role edit action should open modal without triggering row drawer'
  );
  await evaluate(
    cdp,
    sessionId,
    `(() => {
      document.querySelector('.ant-modal .ant-modal-close')?.click();
      return true;
    })()`
  );
  await waitForCondition(
    cdp,
    sessionId,
    `(() => !document.querySelector('[data-testid="tenant-role-edit-name"]'))()`,
    8000,
    'tenant role edit modal should close after cancel'
  );
  await evaluate(
    cdp,
    sessionId,
    `(() => { document.querySelector('[data-testid="tenant-role-delete-tenant_role_management_admin"]')?.click(); return true; })()`
  );
  await waitForCondition(
    cdp,
    sessionId,
    `(() => {
      const popconfirm = document.querySelector('.ant-popconfirm-buttons');
      const drawer = document.querySelector('[data-testid="tenant-role-detail-drawer"]');
      return Boolean(popconfirm) && !drawer;
    })()`,
    8000,
    'tenant role delete action should open confirm without triggering row drawer'
  );
  await evaluate(
    cdp,
    sessionId,
    `(() => {
      const cancel = document.querySelector('.ant-popconfirm-buttons .ant-btn-default');
      cancel?.click();
      return true;
    })()`
  );

  await evaluate(
    cdp,
    sessionId,
    `(() => { document.querySelector('[data-testid="tenant-role-create-open"]').click(); return true; })()`
  );
  await waitForCondition(
    cdp,
    sessionId,
    `Boolean(document.querySelector('[data-testid="tenant-role-edit-code"]'))`,
    8000,
    'tenant role create modal should be visible'
  );
  await evaluate(
    cdp,
    sessionId,
    `(() => {
      const setter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value')?.set;
      const code = document.querySelector('[data-testid="tenant-role-edit-code"]');
      const name = document.querySelector('[data-testid="tenant-role-edit-name"]');
      setter.call(code, 'TENANT_OPS_AUDITOR');
      code.dispatchEvent(new Event('input', { bubbles: true }));
      code.dispatchEvent(new Event('change', { bubbles: true }));
      setter.call(name, '组织运维审计');
      name.dispatchEvent(new Event('input', { bubbles: true }));
      name.dispatchEvent(new Event('change', { bubbles: true }));
      return true;
    })()`
  );
  await waitForButtonEnabledByTestId(
    cdp,
    sessionId,
    'tenant-role-create-confirm',
    10000,
    'tenant role create confirm should be enabled before submission'
  );
  await evaluate(
    cdp,
    sessionId,
    `(() => { document.querySelector('[data-testid="tenant-role-create-confirm"]').click(); return true; })()`
  );
  await waitForRequest(
    api.requests,
    (request) => request.path === '/tenant/roles' && request.method === 'POST',
    12000,
    'tenant role create request should reach API stub'
  );

  await evaluate(
    cdp,
    sessionId,
    `(() => { document.querySelector('[data-testid="tenant-role-edit-tenant_owner"]').click(); return true; })()`
  );
  await waitForCondition(
    cdp,
    sessionId,
    `Boolean(document.querySelector('[data-testid="tenant-role-edit-name"]'))`,
    8000,
    'tenant protected role edit modal should be visible'
  );
  await evaluate(
    cdp,
    sessionId,
    `(() => {
      const input = document.querySelector('[data-testid="tenant-role-edit-name"]');
      const setter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value')?.set;
      setter.call(input, '组织负责人（编辑尝试）');
      input.dispatchEvent(new Event('input', { bubbles: true }));
      input.dispatchEvent(new Event('change', { bubbles: true }));
      return true;
    })()`
  );
  await evaluate(
    cdp,
    sessionId,
    `(() => { document.querySelector('[data-testid="tenant-role-edit-confirm"]').click(); return true; })()`
  );
  await waitForRequest(
    api.responses,
    (response) =>
      response.method === 'PATCH'
      && response.path.includes('/tenant/roles/tenant_owner')
      && response.status === 403
      && response.body?.error_code === 'TROLE-403-SYSTEM-ROLE-PROTECTED',
    8000,
    'protected tenant role update should surface backend 403 semantics'
  );
  await evaluate(
    cdp,
    sessionId,
    `(() => {
      document.querySelector('.ant-modal .ant-modal-close')?.click();
      return true;
    })()`
  );

  await evaluate(
    cdp,
    sessionId,
    `(() => {
      const row = document.querySelector('[data-row-key="tenant_user_management"]');
      if (!row) {
        return false;
      }
      row.click();
      return true;
    })()`
  );
  await waitForCondition(
    cdp,
    sessionId,
    `Boolean(document.querySelector('[data-testid="tenant-role-permission-tree"]'))`,
    8000,
    'tenant role permission tree should be visible in drawer'
  );
  await waitForCondition(
    cdp,
    sessionId,
    `(() => {
      const tree = document.querySelector('[data-testid="tenant-role-permission-tree"]');
      if (!tree) {
        return false;
      }
      const nodes = Array.from(tree.querySelectorAll('.ant-tree-treenode'))
        .map((node) => {
          const ariaLevel = Number(node.getAttribute('aria-level') || 0);
          const fallbackLevel = node.querySelectorAll('.ant-tree-indent-unit').length + 1;
          return {
            title: String(node.querySelector('.ant-tree-title')?.textContent || '').trim(),
            level: ariaLevel > 0 ? ariaLevel : fallbackLevel
          };
        })
        .filter((node) => Boolean(node.title));
      if (nodes.length < 3) {
        return false;
      }
      const accountMatrixNodeIndex = nodes.findIndex((node) => node.title === '账号矩阵');
      const settingsNodeIndex = nodes.findIndex((node) => node.title === '设置');
      if (accountMatrixNodeIndex < 0 || settingsNodeIndex < 0 || accountMatrixNodeIndex > settingsNodeIndex) {
        return false;
      }
      const rootLevel = nodes[accountMatrixNodeIndex].level;
      if (rootLevel < 1 || nodes[settingsNodeIndex].level !== rootLevel) {
        return false;
      }
      const accountManagementNodeIndex = nodes.findIndex(
        (node) => node.title === '账号管理' && node.level === rootLevel + 1
      );
      if (accountManagementNodeIndex < 0) {
        return false;
      }
      let parentRootNodeIndex = -1;
      for (let index = accountManagementNodeIndex - 1; index >= 0; index -= 1) {
        if (nodes[index].level === rootLevel) {
          parentRootNodeIndex = index;
          break;
        }
      }
      return parentRootNodeIndex === accountMatrixNodeIndex;
    })()`,
    8000,
    'tenant role permission tree should place account menu under account matrix before settings'
  );
  await waitForCondition(
    cdp,
    sessionId,
    `(() => !document.querySelector('[data-testid="tenant-role-permission-save"]'))()`,
    8000,
    'tenant role detail drawer should hide permission save action'
  );

  const screenshot = await cdp.send('Page.captureScreenshot', { format: 'png' }, sessionId);
  screenshotPath = join(evidenceDir, `chrome-tenant-management-${timestamp}.png`);
  writeFileSync(screenshotPath, Buffer.from(screenshot.data, 'base64'));

  const tenantLoginRequest = api.requests.find(
    (request) => request.path === '/auth/login' && request.body?.entry_domain === 'tenant'
  );
  assert.deepEqual(tenantLoginRequest?.body, {
    phone: '13800000021',
    password: 'Passw0rd!',
    entry_domain: 'tenant'
  });

  const createUserRequest = api.requests.find(
    (request) => request.path === '/tenant/users' && request.method === 'POST'
  );
  assert.equal(createUserRequest?.body?.phone, '13800000029');
  const createUserProfileRequest = api.requests.find(
    (request) =>
      request.method === 'PATCH'
      && request.path.includes('/tenant/users/membership-tenant-101-3/profile')
  );
  assert.equal(createUserProfileRequest?.body?.display_name, '新建成员甲');
  assert.equal(createUserProfileRequest?.body?.department_name, null);

  const replaceRolesRequest = [...api.requests].reverse().find(
    (request) =>
      request.method === 'PUT'
      && request.path.includes('/tenant/users/membership-tenant-101-admin/roles')
  );
  assert.deepEqual(replaceRolesRequest?.body?.role_ids?.sort(), ['tenant_role_management_admin', 'tenant_user_management']);

  const createCustomerRequest = api.requests.find(
    (request) => request.path === '/tenant/customers' && request.method === 'POST'
  );
  assert.equal(createCustomerRequest?.body?.account_id, 'account-tenant-101-1');
  assert.equal(createCustomerRequest?.body?.wechat_id, 'wx_customer_101_new');
  assert.equal(createCustomerRequest?.body?.nickname, '客户新增甲');
  assert.equal(createCustomerRequest?.body?.source, 'ground');

  const updateCustomerBasicRequest = api.requests.find(
    (request) => request.path === '/tenant/customers/customer-tenant-101-3/basic' && request.method === 'PATCH'
  );
  assert.equal(updateCustomerBasicRequest?.body?.source, 'fission');

  const updateCustomerRealnameRequest = api.requests.find(
    (request) => request.path === '/tenant/customers/customer-tenant-101-3/realname' && request.method === 'PATCH'
  );
  assert.equal(updateCustomerRealnameRequest?.body?.real_name, '王五');
  assert.equal(updateCustomerRealnameRequest?.body?.school, '第三中学');

  const tenantWriteRequests = api.requests.filter(
    (request) =>
      request.path.startsWith('/tenant/')
      && ['POST', 'PATCH', 'PUT', 'DELETE'].includes(request.method)
  );
  assert.ok(tenantWriteRequests.length >= 7, 'tenant management flow should trigger multiple tenant write operations');
  for (const request of tenantWriteRequests) {
    const idempotencyKey = String(request.headers?.['idempotency-key'] || '');
    assert.ok(
      idempotencyKey.length > 0,
      `tenant write request should carry Idempotency-Key: ${request.method} ${request.path}`
    );
  }

  const reportPath = join(evidenceDir, `chrome-tenant-management-${timestamp}.json`);
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
          tenant_member_filtering: true,
          tenant_member_pagination: true,
          tenant_member_create_modal: true,
          tenant_member_status_modal: true,
          tenant_member_profile_failure_and_retry: true,
          tenant_member_roles_assignment: true,
          tenant_customer_management_create_and_edit: true,
          tenant_account_management_create_and_detail: true,
          tenant_write_idempotency_keys: true,
          tenant_permission_context_refresh: true,
          tenant_role_create_modal: true,
          tenant_protected_role_guard: true,
          tenant_permission_tree_save: true
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
