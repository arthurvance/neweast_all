const test = require('node:test');
const assert = require('node:assert/strict');
const http = require('node:http');
const net = require('node:net');
const { spawn } = require('node:child_process');
const { existsSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } = require('node:fs');
const { once } = require('node:events');
const { join, resolve } = require('node:path');
const { tmpdir } = require('node:os');

const WORKSPACE_ROOT = resolve(__dirname, '../../..');
const CHROME_BIN_CANDIDATES = [
  process.env.CHROME_BIN,
  '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome',
  '/usr/bin/google-chrome',
  '/usr/bin/chromium-browser',
  '/usr/bin/chromium'
].filter(Boolean);

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
    otp_code: '123456'
  });
  assert.match(
    String(await evaluate(cdp, sessionId, `document.querySelector('[data-testid="message-global"]')?.textContent || ''`)),
    /验证码错误或已失效.*请稍后重试/
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
          otp_send_countdown_on_success: true,
          otp_send_cooldown_429: true,
          otp_send_rate_limit_headers: true,
          otp_rate_limit_countdown_recovery: true,
          otp_login_failure_semantics: true
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
