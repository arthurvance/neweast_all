#!/usr/bin/env node
const {
  existsSync,
  lstatSync,
  mkdirSync,
  readdirSync,
  readFileSync,
  realpathSync,
  statSync,
  writeFileSync
} = require('node:fs');
const { spawnSync } = require('node:child_process');
const { randomUUID } = require('node:crypto');
const {
  basename,
  dirname,
  isAbsolute,
  join,
  relative,
  resolve
} = require('node:path');

const resolveWorkspaceRoot = (cwd = __dirname) => {
  const fallbackRoot = resolve(__dirname, '..');
  const result = spawnSync('git', ['rev-parse', '--show-toplevel'], {
    cwd,
    encoding: 'utf8'
  });
  if (typeof result.status === 'number' && result.status === 0) {
    const resolved = String(result.stdout || '').trim();
    if (resolved) {
      return resolved;
    }
  }
  return fallbackRoot;
};

const WORKSPACE_ROOT = resolveWorkspaceRoot();
const DEFAULT_SMOKE_DIR = resolve(WORKSPACE_ROOT, 'artifacts/smoke');
const DEFAULT_CHROME_DIR = resolve(WORKSPACE_ROOT, 'artifacts/chrome-regression');
const DEFAULT_OUTPUT_DIR = resolve(WORKSPACE_ROOT, 'artifacts/release-gates');
const DEFAULT_EVIDENCE_STALE_WINDOW_MS = 6 * 60 * 60 * 1000;
const MAX_EVIDENCE_FUTURE_SKEW_MS = 5 * 60 * 1000;
const COMMAND_MAX_BUFFER_BYTES = 200 * 1024 * 1024;
const ISO_TIMESTAMP_WITH_TIMEZONE_PATTERN = /^(?:\d{4}-\d{2}-\d{2})T(?:\d{2}:\d{2}:\d{2})(?:\.\d{1,9})?(?:[Zz]|[+-]\d{2}:\d{2})$/;
const CONSISTENCY_BLOCKING_REASON_PATTERN = /missing_latest_compatibility_check|latest_compatibility_incompatible|baseline_version_mismatch|candidate_status_invalid/;
const SMOKE_REPORT_FILE_PATTERN = /^smoke-.*\.json$/;
const CHROME_REPORT_FILE_PATTERN = /^chrome-regression-.*\.json$/;
const CHROME_SCREENSHOT_FILE_PATTERN = /^chrome-regression-.*\.png$/;

const DEFAULT_GROUP_DEFINITIONS = Object.freeze([
  Object.freeze({
    id: 'lint',
    name: 'Lint & Permission Contract',
    blocking: true,
    fr_mapping: Object.freeze(['FR48', 'FR49', 'FR50', 'FR77']),
    checks: Object.freeze([
      Object.freeze({
        id: 'lint.workspace',
        name: 'Workspace lint',
        command: 'pnpm nx lint'
      })
    ])
  }),
  Object.freeze({
    id: 'build',
    name: 'Build Integrity',
    blocking: true,
    fr_mapping: Object.freeze(['FR48', 'FR72']),
    checks: Object.freeze([
      Object.freeze({
        id: 'build.workspace',
        name: 'Workspace build',
        command: 'pnpm nx build'
      })
    ])
  }),
  Object.freeze({
    id: 'test',
    name: 'Automated Regression Tests',
    blocking: true,
    fr_mapping: Object.freeze(['FR48', 'FR49', 'FR50', 'FR51', 'FR52', 'FR53', 'FR54', 'FR72', 'FR73', 'FR77', 'FR78', 'FR79']),
    checks: Object.freeze([
      Object.freeze({
        id: 'test.workspace',
        name: 'Workspace test',
        command: 'pnpm nx test'
      })
    ])
  }),
  Object.freeze({
    id: 'integration-contract-consistency',
    name: 'Integration Contract Consistency',
    blocking: true,
    fr_mapping: Object.freeze(['FR41', 'FR58']),
    checks: Object.freeze([
      Object.freeze({
        id: 'integration-contract-consistency.api',
        name: 'Integration contract consistency check',
        command: 'pnpm --dir apps/api check:integration-contract-consistency'
      })
    ])
  }),
  Object.freeze({
    id: 'smoke',
    name: 'Smoke & Evidence Chain',
    blocking: true,
    fr_mapping: Object.freeze(['FR48', 'FR52', 'FR53', 'FR54', 'FR72', 'FR73', 'FR77', 'FR78', 'FR79']),
    checks: Object.freeze([
      Object.freeze({
        id: 'smoke.workspace',
        name: 'Workspace smoke',
        command: 'pnpm nx smoke'
      })
    ])
  })
]);

const toRelativePath = (inputPath) => {
  if (!inputPath) {
    return '';
  }
  if (!isAbsolute(inputPath)) {
    return inputPath.replace(/\\/g, '/');
  }
  const rel = relative(WORKSPACE_ROOT, inputPath);
  if (!rel || rel === '') {
    return '.';
  }
  if (rel.startsWith('..')) {
    return inputPath.replace(/\\/g, '/');
  }
  return rel.replace(/\\/g, '/');
};

const normalizeExitStatus = (status, signal) => {
  if (typeof status === 'number') {
    return status;
  }
  if (signal) {
    return 1;
  }
  return 1;
};

const resolveStaleWindowMs = (rawValue) => {
  const parsed = Number(rawValue);
  if (!Number.isFinite(parsed)) {
    return DEFAULT_EVIDENCE_STALE_WINDOW_MS;
  }
  return Math.max(60 * 1000, parsed);
};

const resolveShellExecutable = (env = process.env) => {
  const preferredShell = String(env.RELEASE_GATE_SHELL || '').trim();
  if (preferredShell) {
    return preferredShell;
  }
  const envShell = String(env.SHELL || '').trim();
  if (envShell) {
    return envShell;
  }
  return 'sh';
};

const resolveShellArgs = (shellExecutable, command) => {
  const executableName = String(shellExecutable || '')
    .trim()
    .split(/[\\/]/)
    .pop()
    .toLowerCase()
    .replace(/\.exe$/, '');
  if (['bash', 'zsh', 'ksh', 'mksh', 'pdksh'].includes(executableName)) {
    return ['-lc', command];
  }
  return ['-c', command];
};

const runCommand = (command, env = process.env) => {
  const startedAtMs = Date.now();
  const shell = resolveShellExecutable(env);
  const spawnOptions = {
    cwd: WORKSPACE_ROOT,
    env,
    encoding: 'utf8',
    maxBuffer: COMMAND_MAX_BUFFER_BYTES
  };
  const execute = (commandName) => spawnSync(
    commandName,
    resolveShellArgs(commandName, command),
    spawnOptions
  );
  let result = execute(shell);
  if (result.error && result.error.code === 'ENOENT' && shell !== 'sh') {
    result = execute('sh');
  }
  const endedAtMs = Date.now();
  const status = normalizeExitStatus(result.status, result.signal);
  const stdout = result.stdout || '';
  const stderrParts = [];
  if (result.stderr) {
    stderrParts.push(result.stderr);
  }
  if (result.error && result.error.message) {
    stderrParts.push(`spawn-error: ${result.error.message}`);
  }
  const stderr = stderrParts.join('\n');
  if (stdout) {
    process.stdout.write(stdout);
  }
  if (stderr) {
    process.stderr.write(stderr);
  }
  return {
    status,
    signal: result.signal || null,
    stdout,
    stderr,
    duration_ms: endedAtMs - startedAtMs
  };
};

const buildOutputExcerpt = (stdout, stderr) => {
  const combined = `${stdout || ''}\n${stderr || ''}`.trim();
  if (!combined) {
    return '';
  }
  const lines = combined.split('\n');
  const excerptLines = lines.slice(Math.max(0, lines.length - 40));
  const excerpt = excerptLines.join('\n');
  if (excerpt.length <= 4000) {
    return excerpt;
  }
  return `...${excerpt.slice(excerpt.length - 4000)}`;
};

const parseJsonSafelyFromString = (value) => {
  try {
    return JSON.parse(value);
  } catch (_error) {
    return null;
  }
};

const parseConsistencyGateReportFromOutput = (output) => {
  const text = String(output || '').trim();
  if (!text) {
    return null;
  }
  const isConsistencyGateReport = (candidate) =>
    candidate
    && typeof candidate === 'object'
    && Array.isArray(candidate.checks)
    && (
      candidate.gate === 'integration-contract-consistency'
      || Object.prototype.hasOwnProperty.call(candidate, 'blocking')
    );
  const direct = parseJsonSafelyFromString(text);
  if (isConsistencyGateReport(direct)) {
    return direct;
  }

  const lines = text.split('\n');
  for (let start = lines.length - 1; start >= 0; start -= 1) {
    if (!String(lines[start] || '').trim().startsWith('{')) {
      continue;
    }
    const candidate = parseJsonSafelyFromString(lines.slice(start).join('\n'));
    if (isConsistencyGateReport(candidate)) {
      return candidate;
    }
  }
  return null;
};

const isConsistencyRuntimeCheck = (check = {}) =>
  String(check.id || check.check_id || '').trim().toLowerCase() === 'consistency.runtime';

const isConsistencyBlockedCheck = (check = {}) => {
  const checkId = String(check.id || check.check_id || '').trim().toLowerCase();
  if (checkId === 'consistency.runtime') {
    return false;
  }
  if (checkId && !checkId.startsWith('consistency.')) {
    return false;
  }
  const status = Number(check.status);
  const detail = String(check.detail || '').toLowerCase();
  return status === 409 || CONSISTENCY_BLOCKING_REASON_PATTERN.test(detail);
};

const classifyFailureReason = (groupId, output) => {
  const normalized = String(output || '').toLowerCase();
  if (groupId === 'lint') {
    if (normalized.includes('route-permissions') || normalized.includes('permission')) {
      return 'permission-contract-check-failed';
    }
    return 'lint-check-failed';
  }
  if (groupId === 'build') {
    if (normalized.includes('typescript') || normalized.includes('error ts')) {
      return 'build-typescript-failed';
    }
    if (normalized.includes('vite') || normalized.includes('rollup')) {
      return 'build-bundle-failed';
    }
    return 'build-check-failed';
  }
  if (groupId === 'test') {
    if (normalized.includes('failing tests') || normalized.includes('not ok')) {
      return 'test-failures-detected';
    }
    return 'test-check-failed';
  }
  if (groupId === 'integration-contract-consistency') {
    const parsedReport = parseConsistencyGateReportFromOutput(output);
    if (parsedReport) {
      const failedChecks = parsedReport.checks.filter((check) => {
        if (!check || typeof check !== 'object') {
          return true;
        }
        const passedFlag = check.passed;
        const status = String(check.status || '').toLowerCase();
        const explicitlyPassed = passedFlag === true || status === 'passed';
        return !explicitlyPassed;
      });
      if (failedChecks.some((check) => isConsistencyRuntimeCheck(check))) {
        return 'integration-contract-consistency-check-failed';
      }
      if (
        failedChecks.length > 0
        && failedChecks.every((check) => isConsistencyBlockedCheck(check))
      ) {
        return 'integration-contract-consistency-blocked';
      }
      return 'integration-contract-consistency-check-failed';
    }
    if (normalized.includes('consistency.runtime')) {
      return 'integration-contract-consistency-check-failed';
    }
    if (CONSISTENCY_BLOCKING_REASON_PATTERN.test(normalized)) {
      return 'integration-contract-consistency-blocked';
    }
    return 'integration-contract-consistency-check-failed';
  }
  if (groupId === 'smoke') {
    if (normalized.includes('docker environment unavailable')) {
      return 'smoke-docker-unavailable';
    }
    if (normalized.includes('stale chrome regression evidence')) {
      return 'stale-chrome-evidence';
    }
    if (normalized.includes('missing chrome regression evidence')) {
      return 'missing-chrome-evidence';
    }
    return 'smoke-check-failed';
  }
  return 'command-failed';
};

const readLatestArtifact = (targetDir, filePattern) => {
  if (!existsSync(targetDir)) {
    return null;
  }
  const candidates = readdirSync(targetDir)
    .filter((entry) => filePattern.test(entry))
    .map((entry) => {
      const fullPath = join(targetDir, entry);
      let stats = null;
      try {
        stats = statSync(fullPath);
      } catch (_error) {
        return null;
      }
      if (!stats.isFile()) {
        return null;
      }
      return {
        path: fullPath,
        mtimeMs: stats.mtimeMs
      };
    })
    .filter(Boolean)
    .sort((left, right) => {
      if (right.mtimeMs !== left.mtimeMs) {
        return right.mtimeMs - left.mtimeMs;
      }
      return right.path.localeCompare(left.path);
    });

  if (candidates.length === 0) {
    return null;
  }
  return candidates[0];
};

const readJsonSafely = (filePath) => {
  try {
    const raw = readFileSync(filePath, 'utf8');
    return JSON.parse(raw);
  } catch (_error) {
    return null;
  }
};

const parseGeneratedAtMs = (rawValue) => {
  if (typeof rawValue !== 'string' || rawValue.trim().length === 0) {
    return null;
  }
  const normalized = rawValue.trim();
  if (!ISO_TIMESTAMP_WITH_TIMEZONE_PATTERN.test(normalized)) {
    return null;
  }
  const parsed = Date.parse(normalized);
  if (!Number.isFinite(parsed)) {
    return null;
  }
  return parsed;
};

const addIssue = (issues, reason, details) => {
  const issue = {
    check_id: 'smoke.evidence',
    reason,
    details: String(details || '')
  };
  const key = `${issue.reason}:${issue.details}`;
  const exists = issues.some((candidate) => `${candidate.reason}:${candidate.details}` === key);
  if (!exists) {
    issues.push(issue);
  }
};

const collectRequestIds = (smokePayload) => {
  const requestIds = new Set();
  const capture = (value) => {
    if (Array.isArray(value)) {
      for (const item of value) {
        capture(item);
      }
      return;
    }
    if (typeof value === 'string') {
      const normalized = value.trim();
      if (normalized.length > 0) {
        requestIds.add(normalized);
      }
    }
  };
  const isRequestIdKey = (key) => {
    const normalized = String(key || '').trim().toLowerCase();
    if (!normalized) {
      return false;
    }
    if (normalized === 'request_id' || normalized === 'requestid') {
      return true;
    }
    if (normalized === 'request_ids' || normalized === 'requestids') {
      return true;
    }
    if (normalized.endsWith('_request_id') || normalized.endsWith('requestid')) {
      return true;
    }
    return false;
  };
  const collectFromNode = (value, depth = 0) => {
    if (depth > 12 || value === null || value === undefined) {
      return;
    }
    if (Array.isArray(value)) {
      for (const item of value) {
        collectFromNode(item, depth + 1);
      }
      return;
    }
    if (typeof value !== 'object') {
      return;
    }
    for (const [key, nestedValue] of Object.entries(value)) {
      if (isRequestIdKey(key)) {
        capture(nestedValue);
      }
      collectFromNode(nestedValue, depth + 1);
    }
  };
  collectFromNode(smokePayload);

  return Array.from(requestIds).sort();
};

const resolvePossiblyRelativePath = (rawPath, referenceFilePath) => {
  if (typeof rawPath !== 'string' || rawPath.trim().length === 0) {
    return null;
  }
  if (isAbsolute(rawPath)) {
    return rawPath;
  }
  if (referenceFilePath) {
    return resolve(dirname(referenceFilePath), rawPath);
  }
  return resolve(WORKSPACE_ROOT, rawPath);
};

const resolveRealPathSafe = (inputPath) => {
  try {
    return realpathSync(inputPath);
  } catch (_error) {
    return null;
  }
};

const isRegularFile = (inputPath) => {
  try {
    return lstatSync(inputPath).isFile();
  } catch (_error) {
    return false;
  }
};

const isPathInsideDirectory = (targetPath, baseDir) => {
  if (!targetPath || !baseDir) {
    return false;
  }
  const resolvedTarget = resolve(targetPath);
  const resolvedBase = resolve(baseDir);
  const realTarget = resolveRealPathSafe(resolvedTarget);
  const realBase = resolveRealPathSafe(resolvedBase);
  if ((realTarget && !realBase) || (!realTarget && realBase)) {
    return false;
  }
  const normalizedTarget = realTarget || resolvedTarget;
  const normalizedBase = realBase || resolvedBase;
  if (normalizedTarget === normalizedBase) {
    return true;
  }
  const rel = relative(normalizedBase, normalizedTarget);
  if (!rel) {
    return true;
  }
  return !rel.startsWith('..') && !isAbsolute(rel);
};

const collectEvidenceInputs = ({
  smokeDir = DEFAULT_SMOKE_DIR,
  chromeDir = DEFAULT_CHROME_DIR,
  runStartedAtMs = 0,
  nowMs = Date.now(),
  staleWindowMs = DEFAULT_EVIDENCE_STALE_WINDOW_MS,
  expectedRunId = null
} = {}) => {
  const issues = [];
  const evidencePathSet = new Set();
  const resolvedChromeDir = resolve(chromeDir);
  let smokeReportPath = null;
  let chromeReportPath = null;

  const latestSmoke = readLatestArtifact(smokeDir, SMOKE_REPORT_FILE_PATTERN);
  if (!latestSmoke) {
    addIssue(
      issues,
      'missing-smoke-evidence',
      `No smoke report found in ${toRelativePath(smokeDir)}`
    );
    return {
      smoke_report: null,
      chrome_report: null,
      evidence_paths: [],
      request_ids: [],
      issues
    };
  }

  smokeReportPath = latestSmoke.path;
  evidencePathSet.add(toRelativePath(smokeReportPath));
  if (!isPathInsideDirectory(smokeReportPath, smokeDir)) {
    addIssue(
      issues,
      'invalid-smoke-evidence',
      `Latest smoke report resolves outside ${toRelativePath(smokeDir)}: ${toRelativePath(smokeReportPath)}`
    );
    return {
      smoke_report: toRelativePath(smokeReportPath),
      chrome_report: null,
      evidence_paths: Array.from(evidencePathSet).sort(),
      request_ids: [],
      issues
    };
  }

  if (latestSmoke.mtimeMs < runStartedAtMs) {
    addIssue(
      issues,
      'stale-smoke-evidence',
      `Latest smoke report predates current run: ${toRelativePath(smokeReportPath)}`
    );
  }
  if (nowMs - latestSmoke.mtimeMs > staleWindowMs) {
    addIssue(
      issues,
      'stale-smoke-evidence',
      `Latest smoke report exceeds stale window (${staleWindowMs}ms): ${toRelativePath(smokeReportPath)}`
    );
  }

  const smokeLogPath = smokeReportPath.replace(/\.json$/, '.log');
  if (existsSync(smokeLogPath)) {
    evidencePathSet.add(toRelativePath(smokeLogPath));
  }

  const smokePayload = readJsonSafely(smokeReportPath);
  if (!smokePayload) {
    addIssue(
      issues,
      'invalid-smoke-evidence',
      `Unable to parse smoke report JSON: ${toRelativePath(smokeReportPath)}`
    );
  } else {
    const smokeGeneratedAtMs = parseGeneratedAtMs(smokePayload.generated_at);
    if (smokeGeneratedAtMs === null) {
      addIssue(
        issues,
        'invalid-smoke-evidence',
        `Smoke report has invalid generated_at: ${toRelativePath(smokeReportPath)}`
      );
    } else {
      if (smokeGeneratedAtMs < runStartedAtMs) {
        addIssue(
          issues,
          'stale-smoke-evidence',
          `Smoke report generated_at predates current run: ${toRelativePath(smokeReportPath)}`
        );
      }
      if (nowMs - smokeGeneratedAtMs > staleWindowMs) {
        addIssue(
          issues,
          'stale-smoke-evidence',
          `Smoke report generated_at exceeds stale window (${staleWindowMs}ms): ${toRelativePath(smokeReportPath)}`
        );
      }
      if (smokeGeneratedAtMs > nowMs + MAX_EVIDENCE_FUTURE_SKEW_MS) {
        addIssue(
          issues,
          'invalid-smoke-evidence',
          `Smoke report generated_at is in the future: ${toRelativePath(smokeReportPath)}`
        );
      }
    }

    if (smokePayload.passed !== true) {
      const details = [
        `Smoke report indicates passed=${String(smokePayload.passed)}`,
        smokePayload.skipped === true ? 'skipped=true' : '',
        typeof smokePayload.skip_reason === 'string' && smokePayload.skip_reason.trim().length > 0
          ? `skip_reason=${smokePayload.skip_reason.trim()}`
          : '',
        typeof smokePayload.error === 'string' && smokePayload.error.trim().length > 0
          ? `error=${smokePayload.error.trim()}`
          : ''
      ]
        .filter(Boolean)
        .join('; ');
      addIssue(
        issues,
        smokePayload.skipped === true ? 'smoke-report-skipped' : 'smoke-report-failed',
        details
      );
    }

    if (typeof expectedRunId === 'string' && expectedRunId.trim().length > 0) {
      const payloadRunId = typeof smokePayload.release_gate_run_id === 'string'
        ? smokePayload.release_gate_run_id.trim()
        : '';
      if (!payloadRunId) {
        addIssue(
          issues,
          'invalid-smoke-evidence',
          `Smoke report missing release_gate_run_id: ${toRelativePath(smokeReportPath)}`
        );
      } else if (payloadRunId !== expectedRunId.trim()) {
        addIssue(
          issues,
          'invalid-smoke-evidence',
          `Smoke report release_gate_run_id mismatch (expected ${expectedRunId.trim()}, got ${payloadRunId}): ${toRelativePath(smokeReportPath)}`
        );
      }
    }
  }

  const requestIds = smokePayload ? collectRequestIds(smokePayload) : [];

  const referencedChromeRawPath = typeof smokePayload?.chrome_regression?.report === 'string'
    ? smokePayload.chrome_regression.report.trim()
    : '';
  const referencedChromeReport = resolvePossiblyRelativePath(
    referencedChromeRawPath,
    smokeReportPath
  );
  let latestChrome = null;
  let suppressChromeFallback = false;
  if (!smokePayload) {
    suppressChromeFallback = true;
  } else if (!referencedChromeRawPath) {
    suppressChromeFallback = true;
    addIssue(
      issues,
      'missing-chrome-evidence',
      `Smoke report missing chrome_regression.report reference: ${toRelativePath(smokeReportPath)}`
    );
  }
  if (referencedChromeReport) {
    if (existsSync(referencedChromeReport)) {
      if (!isPathInsideDirectory(referencedChromeReport, resolvedChromeDir)) {
        suppressChromeFallback = true;
        addIssue(
          issues,
          'invalid-chrome-evidence',
          `Smoke report references chrome report outside ${toRelativePath(chromeDir)}: ${String(referencedChromeRawPath)}`
        );
      } else {
        const reportStats = statSync(referencedChromeReport);
        if (!reportStats.isFile()) {
          suppressChromeFallback = true;
          addIssue(
            issues,
            'invalid-chrome-evidence',
            `Smoke report references chrome report that is not a regular file: ${String(referencedChromeRawPath)}`
          );
        } else if (!CHROME_REPORT_FILE_PATTERN.test(basename(referencedChromeReport))) {
          suppressChromeFallback = true;
          addIssue(
            issues,
            'invalid-chrome-evidence',
            `Smoke report references chrome report with unexpected filename pattern: ${String(referencedChromeRawPath)}`
          );
        } else {
          latestChrome = {
            path: referencedChromeReport,
            mtimeMs: reportStats.mtimeMs
          };
        }
      }
    } else {
      suppressChromeFallback = true;
      addIssue(
        issues,
        'missing-chrome-evidence',
        `Smoke report references missing chrome report: ${String(referencedChromeRawPath)}`
      );
    }
  }

  if (!latestChrome) {
    if (!suppressChromeFallback) {
      addIssue(
        issues,
        'missing-chrome-evidence',
        `No chrome regression report found in ${toRelativePath(chromeDir)}`
      );
    }
  } else {
    chromeReportPath = latestChrome.path;
    evidencePathSet.add(toRelativePath(chromeReportPath));

    if (latestChrome.mtimeMs < runStartedAtMs) {
      addIssue(
        issues,
        'stale-chrome-evidence',
        `Latest chrome report predates current run: ${toRelativePath(chromeReportPath)}`
      );
    }
    if (nowMs - latestChrome.mtimeMs > staleWindowMs) {
      addIssue(
        issues,
        'stale-chrome-evidence',
        `Latest chrome report exceeds stale window (${staleWindowMs}ms): ${toRelativePath(chromeReportPath)}`
      );
    }

    const chromePayload = readJsonSafely(chromeReportPath);
    if (!chromePayload) {
      addIssue(
        issues,
        'invalid-chrome-evidence',
        `Unable to parse chrome report JSON: ${toRelativePath(chromeReportPath)}`
      );
    } else {
      const chromeGeneratedAtMs = parseGeneratedAtMs(chromePayload.generated_at);
      if (chromeGeneratedAtMs === null) {
        addIssue(
          issues,
          'invalid-chrome-evidence',
          `Chrome report has invalid generated_at: ${toRelativePath(chromeReportPath)}`
        );
      } else {
        if (chromeGeneratedAtMs < runStartedAtMs) {
          addIssue(
            issues,
            'stale-chrome-evidence',
            `Chrome report generated_at predates current run: ${toRelativePath(chromeReportPath)}`
          );
        }
        if (nowMs - chromeGeneratedAtMs > staleWindowMs) {
          addIssue(
            issues,
            'stale-chrome-evidence',
            `Chrome report generated_at exceeds stale window (${staleWindowMs}ms): ${toRelativePath(chromeReportPath)}`
          );
        }
        if (chromeGeneratedAtMs > nowMs + MAX_EVIDENCE_FUTURE_SKEW_MS) {
          addIssue(
            issues,
            'invalid-chrome-evidence',
            `Chrome report generated_at is in the future: ${toRelativePath(chromeReportPath)}`
          );
        }
      }

      const screenshots = Array.isArray(chromePayload.screenshots)
        ? chromePayload.screenshots
        : [];
      if (screenshots.length === 0) {
        addIssue(
          issues,
          'invalid-chrome-evidence',
          `Chrome report has no screenshots: ${toRelativePath(chromeReportPath)}`
        );
      }
      for (const screenshotRawPath of screenshots) {
        const screenshotPath = resolvePossiblyRelativePath(screenshotRawPath, chromeReportPath);
        if (!screenshotPath || !existsSync(screenshotPath)) {
          addIssue(
            issues,
            'missing-chrome-screenshot',
            `Screenshot does not exist: ${String(screenshotRawPath)}`
          );
          continue;
        }
        if (!isPathInsideDirectory(screenshotPath, resolvedChromeDir)) {
          addIssue(
            issues,
            'invalid-chrome-evidence',
            `Screenshot path is outside ${toRelativePath(chromeDir)}: ${String(screenshotRawPath)}`
          );
          continue;
        }
        if (!CHROME_SCREENSHOT_FILE_PATTERN.test(basename(screenshotPath))) {
          addIssue(
            issues,
            'invalid-chrome-evidence',
            `Screenshot path has unexpected filename pattern: ${String(screenshotRawPath)}`
          );
          continue;
        }
        const screenshotStats = statSync(screenshotPath);
        if (!isRegularFile(screenshotPath)) {
          addIssue(
            issues,
            'invalid-chrome-evidence',
            `Screenshot is not a regular file: ${String(screenshotRawPath)}`
          );
          continue;
        }
        if (screenshotStats.size <= 0) {
          addIssue(
            issues,
            'empty-chrome-screenshot',
            `Screenshot is empty: ${toRelativePath(screenshotPath)}`
          );
        }
        evidencePathSet.add(toRelativePath(screenshotPath));
      }
    }
  }

  return {
    smoke_report: smokeReportPath ? toRelativePath(smokeReportPath) : null,
    chrome_report: chromeReportPath ? toRelativePath(chromeReportPath) : null,
    evidence_paths: Array.from(evidencePathSet).sort(),
    request_ids: requestIds,
    issues
  };
};

const attachEvidenceChecks = (groupResults, evidence) => {
  const updated = groupResults.map((group) => ({
    ...group,
    checks: Array.isArray(group.checks) ? [...group.checks] : []
  }));
  const smokeGroup = updated.find((group) => group.group_id === 'smoke');
  if (!smokeGroup) {
    return updated;
  }

  if (evidence.issues.length === 0) {
    smokeGroup.checks.push({
      check_id: 'smoke.evidence',
      check_name: 'Smoke/Chrome evidence validation',
      status: 'passed',
      exit_code: 0,
      duration_ms: 0,
      failure_reason: null,
      output_excerpt: '',
      evidence_paths: evidence.evidence_paths,
      request_ids: evidence.request_ids
    });
    return updated;
  }

  for (const issue of evidence.issues) {
    smokeGroup.checks.push({
      check_id: issue.check_id,
      check_name: 'Smoke/Chrome evidence validation',
      status: 'failed',
      exit_code: 1,
      duration_ms: 0,
      failure_reason: issue.reason,
      output_excerpt: issue.details,
      evidence_paths: evidence.evidence_paths,
      request_ids: evidence.request_ids
    });
  }

  smokeGroup.status = smokeGroup.checks.every((check) => check.status === 'passed')
    ? 'passed'
    : 'failed';

  return updated;
};

const buildReleaseGateReport = ({
  runId,
  generatedAt,
  gitSha,
  groupResults,
  evidence
}) => {
  const normalizedGroups = (Array.isArray(groupResults) ? groupResults : []).map((group) => {
    const checks = Array.isArray(group.checks) ? group.checks : [];
    const failedChecksInGroup = checks.filter((check) => check.status !== 'passed');
    const status = failedChecksInGroup.length > 0
      ? 'failed'
      : (group.status === 'failed' ? 'failed' : 'passed');
    return {
      group_id: group.group_id || group.id,
      group_name: group.group_name || group.name,
      blocking: Boolean(group.blocking),
      fr_mapping: Array.isArray(group.fr_mapping) ? [...group.fr_mapping] : [],
      status,
      checks: checks.map((check) => ({
        check_id: check.check_id || check.id,
        check_name: check.check_name || check.name,
        status: check.status,
        exit_code: typeof check.exit_code === 'number' ? check.exit_code : null,
        duration_ms: typeof check.duration_ms === 'number' ? check.duration_ms : 0,
        failure_reason: check.failure_reason || null,
        output_excerpt: check.output_excerpt || '',
        evidence_paths: Array.isArray(check.evidence_paths) ? [...check.evidence_paths] : [],
        request_ids: Array.isArray(check.request_ids) ? [...check.request_ids] : []
      }))
    };
  });

  const failedChecks = [];
  const allEvidencePaths = new Set(Array.isArray(evidence?.evidence_paths) ? evidence.evidence_paths : []);
  const allRequestIds = new Set(Array.isArray(evidence?.request_ids) ? evidence.request_ids : []);
  let totalChecks = 0;

  for (const group of normalizedGroups) {
    for (const check of group.checks) {
      totalChecks += 1;
      for (const evidencePath of check.evidence_paths) {
        allEvidencePaths.add(evidencePath);
      }
      for (const requestId of check.request_ids) {
        allRequestIds.add(requestId);
      }
      if (check.status === 'passed') {
        continue;
      }
      failedChecks.push({
        group_id: group.group_id,
        group_name: group.group_name,
        check_id: check.check_id,
        check_name: check.check_name,
        reason: check.failure_reason || 'check-failed',
        exit_code: check.exit_code,
        duration_ms: check.duration_ms,
        output_excerpt: check.output_excerpt || '',
        evidence_paths: check.evidence_paths,
        request_ids: check.request_ids
      });
    }
  }

  const blocking = normalizedGroups.some(
    (group) => group.blocking && group.status === 'failed'
  );
  const passedGroups = normalizedGroups.filter((group) => group.status === 'passed').length;
  const failedGroups = normalizedGroups.filter((group) => group.status !== 'passed').length;

  return {
    schema_version: '1.0.0',
    run_id: runId,
    generated_at: generatedAt,
    git_sha: gitSha,
    groups: normalizedGroups,
    blocking,
    failed_checks: failedChecks,
    evidence_paths: Array.from(allEvidencePaths).sort(),
    request_ids: Array.from(allRequestIds).sort(),
    summary: {
      total_groups: normalizedGroups.length,
      passed_groups: passedGroups,
      failed_groups: failedGroups,
      total_checks: totalChecks,
      failed_checks: failedChecks.length
    }
  };
};

const renderMarkdownSummary = (report) => {
  const lines = [
    '# Release Gate Grouped Report',
    '',
    `- run_id: \`${report.run_id}\``,
    `- generated_at: \`${report.generated_at}\``,
    `- git_sha: \`${report.git_sha}\``,
    `- blocking: \`${report.blocking}\``,
    `- groups: \`${report.summary.passed_groups}/${report.summary.total_groups}\` passed`,
    `- checks: \`${report.summary.total_checks - report.summary.failed_checks}/${report.summary.total_checks}\` passed`,
    ''
  ];

  lines.push('## Group Breakdown');
  lines.push('');
  lines.push('| Group | Status | Blocking | FR Mapping |');
  lines.push('| --- | --- | --- | --- |');
  for (const group of report.groups) {
    lines.push(
      `| ${group.group_id} | ${group.status} | ${group.blocking} | ${(group.fr_mapping || []).join(', ')} |`
    );
  }
  lines.push('');

  lines.push('## Failed Checks');
  lines.push('');
  if (report.failed_checks.length === 0) {
    lines.push('- None');
  } else {
    for (const failure of report.failed_checks) {
      lines.push(
        `- \`${failure.group_id}\` / \`${failure.check_id}\`: ${failure.reason}`
      );
    }
  }
  lines.push('');

  lines.push('## Evidence Paths');
  lines.push('');
  if (report.evidence_paths.length === 0) {
    lines.push('- None');
  } else {
    for (const evidencePath of report.evidence_paths) {
      lines.push(`- \`${evidencePath}\``);
    }
  }
  lines.push('');

  lines.push('## Request IDs');
  lines.push('');
  if (report.request_ids.length === 0) {
    lines.push('- None');
  } else {
    for (const requestId of report.request_ids) {
      lines.push(`- \`${requestId}\``);
    }
  }
  lines.push('');

  lines.push('## Per-Check Details');
  lines.push('');
  for (const group of report.groups) {
    lines.push(`### ${group.group_id}`);
    if (!Array.isArray(group.checks) || group.checks.length === 0) {
      lines.push('- No checks recorded');
      lines.push('');
      continue;
    }
    for (const check of group.checks) {
      lines.push(`- \`${check.check_id}\` (${check.status})`);
      if (check.failure_reason) {
        lines.push(`  reason: ${check.failure_reason}`);
      }
      if (typeof check.exit_code === 'number') {
        lines.push(`  exit_code: ${check.exit_code}`);
      }
      if (check.duration_ms > 0) {
        lines.push(`  duration_ms: ${check.duration_ms}`);
      }
      if (Array.isArray(check.evidence_paths) && check.evidence_paths.length > 0) {
        lines.push(`  evidence: ${check.evidence_paths.join(', ')}`);
      }
      if (Array.isArray(check.request_ids) && check.request_ids.length > 0) {
        lines.push(`  request_ids: ${check.request_ids.join(', ')}`);
      }
    }
    lines.push('');
  }

  return lines.join('\n');
};

const getGitSha = () => {
  const result = spawnSync('git', ['rev-parse', '--short', 'HEAD'], {
    cwd: WORKSPACE_ROOT,
    encoding: 'utf8'
  });
  if (typeof result.status === 'number' && result.status === 0) {
    return String(result.stdout || '').trim() || 'unknown';
  }
  return 'unknown';
};

const timestampToken = (date = new Date()) => date.toISOString().replace(/[:.]/g, '-');

const writeReportArtifacts = (report, markdown, outputDir = DEFAULT_OUTPUT_DIR) => {
  mkdirSync(outputDir, { recursive: true });
  const token = timestampToken(new Date(report.generated_at));
  const jsonPath = join(outputDir, `release-gate-report-${token}.json`);
  const markdownPath = join(outputDir, `release-gate-report-${token}.md`);
  writeFileSync(jsonPath, `${JSON.stringify(report, null, 2)}\n`);
  writeFileSync(markdownPath, `${markdown}\n`);
  return {
    jsonPath,
    markdownPath
  };
};

const executeGateChecks = (groupDefinitions, commandEnvironment) => {
  const groupResults = [];

  for (const groupDefinition of groupDefinitions) {
    console.log(`\n=== [${groupDefinition.id}] ${groupDefinition.name} ===`);
    const checks = [];
    for (const check of groupDefinition.checks) {
      console.log(`> ${check.command}`);
      const result = runCommand(check.command, commandEnvironment);
      const status = result.status === 0 ? 'passed' : 'failed';
      const outputExcerpt = buildOutputExcerpt(result.stdout, result.stderr);
      checks.push({
        check_id: check.id,
        check_name: check.name,
        status,
        exit_code: result.status,
        duration_ms: result.duration_ms,
        failure_reason:
          status === 'passed'
            ? null
            : classifyFailureReason(groupDefinition.id, outputExcerpt),
        output_excerpt: outputExcerpt,
        evidence_paths: [],
        request_ids: []
      });
    }

    const groupStatus = checks.every((check) => check.status === 'passed')
      ? 'passed'
      : 'failed';

    groupResults.push({
      group_id: groupDefinition.id,
      group_name: groupDefinition.name,
      blocking: Boolean(groupDefinition.blocking),
      fr_mapping: [...groupDefinition.fr_mapping],
      status: groupStatus,
      checks
    });
  }

  return groupResults;
};

const runReleaseGateReport = () => {
  const runId = randomUUID();
  const runStartedAtMs = Date.now();
  const generatedAt = new Date(runStartedAtMs).toISOString();
  const gitSha = getGitSha();
  const staleWindowMs = resolveStaleWindowMs(
    process.env.RELEASE_GATE_EVIDENCE_STALE_WINDOW_MS || DEFAULT_EVIDENCE_STALE_WINDOW_MS
  );

  const commandEnvironment = {
    ...process.env,
    RELEASE_GATE_RUN_ID: runId
  };

  const groupResults = executeGateChecks(DEFAULT_GROUP_DEFINITIONS, commandEnvironment);
  const evidence = collectEvidenceInputs({
    smokeDir: DEFAULT_SMOKE_DIR,
    chromeDir: DEFAULT_CHROME_DIR,
    runStartedAtMs,
    nowMs: Date.now(),
    staleWindowMs,
    expectedRunId: runId
  });
  const groupResultsWithEvidence = attachEvidenceChecks(groupResults, evidence);
  const report = buildReleaseGateReport({
    runId,
    generatedAt,
    gitSha,
    groupResults: groupResultsWithEvidence,
    evidence
  });
  const markdown = renderMarkdownSummary(report);
  const artifactPaths = writeReportArtifacts(report, markdown, DEFAULT_OUTPUT_DIR);

  console.log(`\nRelease gate report JSON: ${toRelativePath(artifactPaths.jsonPath)}`);
  console.log(`Release gate report Markdown: ${toRelativePath(artifactPaths.markdownPath)}`);
  if (report.blocking) {
    console.error('Release gate blocking=true (at least one blocking group failed).');
    return 1;
  }
  console.log('Release gate blocking=false (all blocking groups passed).');
  return 0;
};

if (require.main === module) {
  try {
    const status = runReleaseGateReport();
    process.exit(status);
  } catch (error) {
    const generatedAt = new Date().toISOString();
    const report = {
      schema_version: '1.0.0',
      run_id: randomUUID(),
      generated_at: generatedAt,
      git_sha: getGitSha(),
      groups: [],
      blocking: true,
      failed_checks: [
        {
          group_id: 'release-gate',
          group_name: 'Release Gate Aggregator',
          check_id: 'release-gate.runtime',
          check_name: 'release gate runtime',
          reason: 'release-gate-runtime-failure',
          exit_code: 1,
          duration_ms: 0,
          evidence_paths: [],
          request_ids: []
        }
      ],
      evidence_paths: [],
      request_ids: [],
      summary: {
        total_groups: 0,
        passed_groups: 0,
        failed_groups: 0,
        total_checks: 1,
        failed_checks: 1
      },
      runtime_error: String(error && error.message ? error.message : error)
    };
    const markdown = renderMarkdownSummary(report);
    const artifactPaths = writeReportArtifacts(report, markdown, DEFAULT_OUTPUT_DIR);
    process.stderr.write(`${report.runtime_error}\n`);
    process.stderr.write(`Failure report JSON: ${toRelativePath(artifactPaths.jsonPath)}\n`);
    process.stderr.write(`Failure report Markdown: ${toRelativePath(artifactPaths.markdownPath)}\n`);
    process.exit(1);
  }
}

module.exports = {
  DEFAULT_GROUP_DEFINITIONS,
  buildReleaseGateReport,
  buildOutputExcerpt,
  classifyFailureReason,
  collectEvidenceInputs,
  parseGeneratedAtMs,
  renderMarkdownSummary,
  resolveShellArgs,
  resolveShellExecutable,
  resolveStaleWindowMs,
  resolveWorkspaceRoot,
  runReleaseGateReport,
  timestampToken
};
