#!/usr/bin/env node
const { mkdirSync, writeFileSync } = require('node:fs');
const { join } = require('node:path');
const { spawnSync } = require('node:child_process');

const now = new Date();
const timestamp = now.toISOString().replace(/[:.]/g, '-');
const reportDir = 'artifacts/smoke';
mkdirSync(reportDir, { recursive: true });

const runCommand = (command, args, env = process.env) => {
  const result = spawnSync(command, args, {
    stdio: 'pipe',
    encoding: 'utf8',
    env
  });

  return {
    status: result.status || 0,
    stdout: result.stdout || '',
    stderr: result.stderr || ''
  };
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

const runDockerSmoke = async (artifacts) => {
  const composeUp = runCommand('docker', ['compose', 'up', '-d', '--build']);
  artifacts.steps.push({ step: 'docker compose up -d --build', ...composeUp });

  if (composeUp.status !== 0) {
    const output = `${composeUp.stderr}\n${composeUp.stdout}`;
    const unavailable =
      output.includes('Cannot connect to the Docker daemon') ||
      output.includes('docker daemon') ||
      output.includes('Is the docker daemon running');

    if (unavailable) {
      return { skipped: true, reason: output.trim() };
    }

    throw new Error(`docker compose up failed: ${output}`);
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
  const artifacts = {
    generated_at: now.toISOString(),
    chain: 'web -> api -> db/redis',
    steps: []
  };

  const dockerResult = await runDockerSmoke(artifacts);
  
  if (dockerResult.skipped) {
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
