#!/usr/bin/env node
const { existsSync, mkdirSync, readdirSync, readFileSync, statSync, writeFileSync } = require('node:fs');
const { dirname, isAbsolute, join, resolve } = require('node:path');
const { spawnSync } = require('node:child_process');

const now = new Date();
const timestamp = now.toISOString().replace(/[:.]/g, '-');
const reportDir = 'artifacts/smoke';
const chromeRegressionDir = 'artifacts/chrome-regression';
const allowSkipWhenDockerUnavailable =
  String(process.env.SMOKE_ALLOW_DOCKER_UNAVAILABLE || 'false').toLowerCase() === 'true';
const composeUpMaxAttempts = Math.max(1, Number(process.env.SMOKE_DOCKER_COMPOSE_UP_ATTEMPTS || 3));
const composeUpRetryDelayMs = Math.max(
  1000,
  Number(process.env.SMOKE_DOCKER_COMPOSE_UP_RETRY_DELAY_MS || 5000)
);
const requireChromeEvidenceNotBeforeMs = Math.max(
  0,
  Number(process.env.SMOKE_REQUIRE_CHROME_EVIDENCE_NOT_BEFORE_MS || 0)
);
mkdirSync(reportDir, { recursive: true });

const getLatestChromeRegressionArtifact = (targetDir = chromeRegressionDir) => {
  if (!existsSync(targetDir)) {
    return null;
  }

  const candidates = readdirSync(targetDir)
    .filter((name) => /^chrome-regression-.*\.json$/.test(name))
    .map((name) => ({
      path: join(targetDir, name),
      mtimeMs: statSync(join(targetDir, name)).mtimeMs
    }))
    .sort((a, b) => b.mtimeMs - a.mtimeMs);

  if (candidates.length === 0) {
    return null;
  }

  const latest = candidates[0];
  let parsed = {};
  try {
    parsed = JSON.parse(readFileSync(latest.path, 'utf8'));
  } catch (_error) {
    parsed = {};
  }

  return {
    report: latest.path,
    mtimeMs: latest.mtimeMs,
    generated_at: parsed.generated_at || null,
    screenshots: Array.isArray(parsed.screenshots) ? parsed.screenshots : []
  };
};

const normalizeExitStatus = (status, signal) => {
  if (typeof status === 'number') {
    return status;
  }
  if (typeof signal === 'string' && signal.length > 0) {
    return 1;
  }
  return 1;
};

const runCommand = (command, args, env = process.env) => {
  const result = spawnSync(command, args, {
    stdio: 'pipe',
    encoding: 'utf8',
    env
  });

  return {
    status: normalizeExitStatus(result.status, result.signal),
    signal: result.signal || null,
    stdout: result.stdout || '',
    stderr: result.stderr || ''
  };
};

const resolveChromeEvidence = (
  notBeforeMs = 0,
  evidenceProvider = getLatestChromeRegressionArtifact
) => {
  const chromeEvidence = evidenceProvider();
  if (!chromeEvidence) {
    throw new Error(
      'Missing Chrome regression evidence in artifacts/chrome-regression. Run `pnpm --dir apps/web run smoke` first.'
    );
  }

  if (Number(notBeforeMs) > 0 && chromeEvidence.mtimeMs < Number(notBeforeMs)) {
    throw new Error(
      `Stale Chrome regression evidence detected (${chromeEvidence.report}). Run web smoke in this session before workspace smoke.`
    );
  }

  const screenshots = Array.isArray(chromeEvidence.screenshots)
    ? chromeEvidence.screenshots
    : [];
  if (screenshots.length === 0) {
    throw new Error(
      `Chrome regression evidence must include at least one screenshot: ${chromeEvidence.report}`
    );
  }

  for (const screenshot of screenshots) {
    const screenshotPath = isAbsolute(screenshot)
      ? screenshot
      : resolve(dirname(chromeEvidence.report), screenshot);
    if (!existsSync(screenshotPath)) {
      throw new Error(`Chrome regression screenshot is missing: ${screenshotPath}`);
    }

    const screenshotStats = statSync(screenshotPath);
    if (screenshotStats.size <= 0) {
      throw new Error(`Chrome regression screenshot is empty: ${screenshotPath}`);
    }
  }

  return chromeEvidence;
};

const waitForUrl = async (url, timeoutMs) => {
  const started = Date.now();
  let lastError = 'unknown';

  while (Date.now() - started < timeoutMs) {
    try {
      const response = await fetch(url);
      if (response.ok) {
        return response;
      }
      lastError = `HTTP ${response.status}`;
    } catch (error) {
      lastError = error.message;
    }
    await new Promise((resolveDelay) => setTimeout(resolveDelay, 1000));
  }

  throw new Error(`Timeout waiting for ${url}: ${lastError}`);
};

const sleep = (ms) => new Promise((resolveDelay) => setTimeout(resolveDelay, ms));

const isTransientComposeUpFailure = (output) => {
  const normalized = output.toLowerCase();
  return (
    normalized.includes('tls handshake timeout') ||
    normalized.includes('i/o timeout') ||
    normalized.includes('connection reset by peer') ||
    normalized.includes('temporary failure') ||
    normalized.includes('service unavailable') ||
    normalized.includes('toomanyrequests')
  );
};

const runDockerSmoke = async (artifacts) => {
  let composeUp = null;
  for (let attempt = 1; attempt <= composeUpMaxAttempts; attempt += 1) {
    composeUp = runCommand('docker', ['compose', 'up', '-d', '--build']);
    artifacts.steps.push({
      step: `docker compose up -d --build (attempt ${attempt}/${composeUpMaxAttempts})`,
      ...composeUp
    });

    if (composeUp.status === 0) {
      break;
    }

    const output = `${composeUp.stderr}\n${composeUp.stdout}`;
    const unavailable =
      output.includes('Cannot connect to the Docker daemon') ||
      output.includes('docker daemon') ||
      output.includes('Is the docker daemon running');

    if (unavailable) {
      return { skipped: true, reason: output.trim() };
    }

    const transientFailure = isTransientComposeUpFailure(output);
    if (!transientFailure || attempt === composeUpMaxAttempts) {
      throw new Error(`docker compose up failed: ${output}`);
    }

    const composeDown = runCommand('docker', ['compose', 'down', '--remove-orphans']);
    artifacts.steps.push({
      step: `docker compose down --remove-orphans (after failed attempt ${attempt})`,
      ...composeDown
    });
    await sleep(composeUpRetryDelayMs * attempt);
  }

  const migrationRun = runCommand('docker', [
    'compose',
    'exec',
    '-T',
    'api',
    'node',
    'apps/api/scripts/migrate-baseline.js'
  ]);
  artifacts.steps.push({ step: 'docker compose exec -T api migrate-baseline', ...migrationRun });
  if (migrationRun.status !== 0) {
    throw new Error(`migration failed: ${migrationRun.stderr || migrationRun.stdout}`);
  }

  const apiHealthResponse = await waitForUrl('http://127.0.0.1:3000/health', 120000);
  const apiHealth = await apiHealthResponse.json();

  const webSmokeResponse = await waitForUrl('http://127.0.0.1:4173/smoke', 120000);
  const webSmoke = await webSmokeResponse.json();

  const passed =
    apiHealthResponse.status === 200 &&
    apiHealth.ok === true &&
    apiHealth.dependencies?.db?.ok === true &&
    apiHealth.dependencies?.redis?.ok === true &&
    webSmokeResponse.status === 200 &&
    webSmoke.ok === true;

  artifacts.execution_mode = 'docker-compose';
  artifacts.api_status = apiHealthResponse.status;
  artifacts.api_payload = apiHealth;
  artifacts.web_status = webSmokeResponse.status;
  artifacts.web_payload = webSmoke;

  const composeDown = runCommand('docker', ['compose', 'down']);
  artifacts.steps.push({ step: 'docker compose down', ...composeDown });

  return { skipped: false, passed };
};

const run = async () => {
  const chromeEvidence = resolveChromeEvidence(requireChromeEvidenceNotBeforeMs);

  const artifacts = {
    generated_at: now.toISOString(),
    chain: 'web -> api -> db/redis',
    chrome_regression: chromeEvidence,
    steps: []
  };

  const dockerResult = await runDockerSmoke(artifacts);
  
  if (dockerResult.skipped) {
    artifacts.execution_mode = 'docker-compose';
    artifacts.skipped = true;
    artifacts.passed = false;
    artifacts.skip_reason = dockerResult.reason;

    writeFileSync(join(reportDir, `smoke-${timestamp}.json`), JSON.stringify(artifacts, null, 2));

    if (allowSkipWhenDockerUnavailable) {
      console.warn('Smoke skipped: Docker environment unavailable.');
      console.warn(`Reason: ${dockerResult.reason}`);
      console.warn(`Report: ${join(reportDir, `smoke-${timestamp}.json`)}`);
      return;
    }

    throw new Error(`Smoke failed: Docker environment unavailable. Reason: ${dockerResult.reason}`);
  }

  const passed = dockerResult.passed;
  artifacts.passed = passed;

  writeFileSync(join(reportDir, `smoke-${timestamp}.json`), JSON.stringify(artifacts, null, 2));
  writeFileSync(
    join(reportDir, `smoke-${timestamp}.log`),
    [
      `mode=${artifacts.execution_mode || 'unknown'}`,
      `api_status=${artifacts.api_status}`,
      `web_status=${artifacts.web_status}`,
      `request_id=${artifacts.web_payload?.request_id || artifacts.api_payload?.request_id || 'n/a'}`,
      `passed=${passed}`
    ].join('\n') + '\n'
  );

  if (!passed) {
    throw new Error('Smoke validation failed');
  }

  console.log(`Smoke passed. Report: ${join(reportDir, `smoke-${timestamp}.json`)}`);
};

if (require.main === module) {
  run().catch((error) => {
    const failure = {
      generated_at: now.toISOString(),
      passed: false,
      error: error.message
    };
    writeFileSync(join(reportDir, `smoke-${timestamp}.json`), JSON.stringify(failure, null, 2));
    process.stderr.write(`${error.message}\n`);
    process.exit(1);
  });
}

module.exports = {
  getLatestChromeRegressionArtifact,
  normalizeExitStatus,
  resolveChromeEvidence
};
