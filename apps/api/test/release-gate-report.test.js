const test = require('node:test');
const assert = require('node:assert/strict');
const { existsSync, mkdtempSync, mkdirSync, symlinkSync, utimesSync, writeFileSync } = require('node:fs');
const { join, resolve } = require('node:path');
const { tmpdir } = require('node:os');
const {
  DEFAULT_GROUP_DEFINITIONS,
  buildReleaseGateReport,
  collectEvidenceInputs,
  parseGeneratedAtMs,
  renderMarkdownSummary,
  resolveShellArgs,
  resolveShellExecutable,
  resolveWorkspaceRoot,
  resolveStaleWindowMs
} = require('../../../tools/release-gate-report');

test('default group definitions include required capability groups in stable order', () => {
  const groupIds = DEFAULT_GROUP_DEFINITIONS.map((group) => group.id);
  assert.deepEqual(groupIds, ['lint', 'build', 'test', 'smoke']);
});

test('resolveWorkspaceRoot resolves repository root from nested directories', () => {
  const root = resolveWorkspaceRoot(__dirname);
  assert.equal(typeof root, 'string');
  assert.ok(root.length > 0);
  assert.equal(existsSync(join(root, 'tools', 'release-gate-report.js')), true);
});

test('resolveShellExecutable prefers explicit override then falls back to shell env and sh', () => {
  assert.equal(
    resolveShellExecutable({
      RELEASE_GATE_SHELL: '/bin/bash',
      SHELL: '/bin/zsh'
    }),
    '/bin/bash'
  );
  assert.equal(resolveShellExecutable({ SHELL: '/bin/zsh' }), '/bin/zsh');
  assert.equal(resolveShellExecutable({}), 'sh');
});

test('resolveShellArgs uses -c for minimal shells and -lc for login-capable shells', () => {
  assert.deepEqual(resolveShellArgs('/bin/sh', 'echo hello'), ['-c', 'echo hello']);
  assert.deepEqual(resolveShellArgs('/usr/bin/dash', 'echo hello'), ['-c', 'echo hello']);
  assert.deepEqual(resolveShellArgs('/bin/bash', 'echo hello'), ['-lc', 'echo hello']);
  assert.deepEqual(resolveShellArgs('C:\\Program Files\\Git\\bin\\bash.exe', 'echo hello'), ['-lc', 'echo hello']);
  assert.deepEqual(resolveShellArgs('/usr/bin/fish', 'echo hello'), ['-c', 'echo hello']);
});

test('parseGeneratedAtMs validates timezone-aware ISO timestamps and rejects ambiguous values', () => {
  assert.equal(parseGeneratedAtMs('2026-02-21T00:00:00.000Z'), Date.parse('2026-02-21T00:00:00.000Z'));
  assert.equal(parseGeneratedAtMs('2026-02-21T00:00:00.000z'), Date.parse('2026-02-21T00:00:00.000z'));
  assert.equal(parseGeneratedAtMs('2026-02-21T00:00:00.123456Z'), Date.parse('2026-02-21T00:00:00.123456Z'));
  assert.equal(parseGeneratedAtMs('2026-02-21T08:00:00+08:00'), Date.parse('2026-02-21T08:00:00+08:00'));
  assert.equal(parseGeneratedAtMs('2026-02-21 00:00:00'), null);
  assert.equal(parseGeneratedAtMs('2026-02-21T00:00:00'), null);
  assert.equal(parseGeneratedAtMs('invalid-date'), null);
  assert.equal(parseGeneratedAtMs(''), null);
});

test('buildReleaseGateReport sets blocking=true when a blocking group fails', () => {
  const report = buildReleaseGateReport({
    runId: 'run-123',
    generatedAt: '2026-02-21T00:00:00.000Z',
    gitSha: 'abc1234',
    groupResults: [
      {
        group_id: 'lint',
        group_name: 'Lint',
        blocking: true,
        status: 'passed',
        fr_mapping: ['FR48'],
        checks: []
      },
      {
        group_id: 'smoke',
        group_name: 'Smoke',
        blocking: true,
        status: 'failed',
        fr_mapping: ['FR48', 'FR72'],
        checks: [
          {
            check_id: 'smoke.workspace',
            check_name: 'pnpm nx smoke',
            status: 'failed',
            exit_code: 1,
            duration_ms: 1234,
            failure_reason: 'smoke-validation-failed',
            output_excerpt: 'Smoke validation failed',
            evidence_paths: ['artifacts/smoke/smoke-1.json'],
            request_ids: ['req-smoke-1']
          }
        ]
      }
    ],
    evidence: {
      evidence_paths: ['artifacts/smoke/smoke-1.json'],
      request_ids: ['req-smoke-1'],
      issues: []
    }
  });

  assert.equal(report.blocking, true);
  assert.equal(report.failed_checks.length, 1);
  assert.equal(report.failed_checks[0].group_id, 'smoke');
  assert.equal(report.failed_checks[0].check_id, 'smoke.workspace');
});

test('buildReleaseGateReport keeps blocking=false when all blocking groups pass', () => {
  const report = buildReleaseGateReport({
    runId: 'run-124',
    generatedAt: '2026-02-21T00:00:00.000Z',
    gitSha: 'def5678',
    groupResults: [
      {
        group_id: 'lint',
        group_name: 'Lint',
        blocking: true,
        status: 'passed',
        fr_mapping: ['FR48'],
        checks: [
          {
            check_id: 'lint.workspace',
            check_name: 'pnpm nx lint',
            status: 'passed',
            exit_code: 0,
            duration_ms: 2000,
            failure_reason: null,
            output_excerpt: '',
            evidence_paths: [],
            request_ids: []
          }
        ]
      },
      {
        group_id: 'smoke',
        group_name: 'Smoke',
        blocking: true,
        status: 'passed',
        fr_mapping: ['FR48', 'FR72'],
        checks: [
          {
            check_id: 'smoke.workspace',
            check_name: 'pnpm nx smoke',
            status: 'passed',
            exit_code: 0,
            duration_ms: 3000,
            failure_reason: null,
            output_excerpt: '',
            evidence_paths: ['artifacts/smoke/smoke-1.json'],
            request_ids: ['req-smoke-1']
          }
        ]
      }
    ],
    evidence: {
      evidence_paths: ['artifacts/smoke/smoke-1.json'],
      request_ids: ['req-smoke-1'],
      issues: []
    }
  });

  assert.equal(report.blocking, false);
  assert.equal(report.failed_checks.length, 0);
  assert.equal(report.summary.failed_checks, 0);
});

test('buildReleaseGateReport forces group failure when any check fails even if group status is marked passed', () => {
  const report = buildReleaseGateReport({
    runId: 'run-125',
    generatedAt: '2026-02-21T00:00:00.000Z',
    gitSha: 'ghi9012',
    groupResults: [
      {
        group_id: 'smoke',
        group_name: 'Smoke',
        blocking: true,
        status: 'passed',
        fr_mapping: ['FR48'],
        checks: [
          {
            check_id: 'smoke.workspace',
            check_name: 'pnpm nx smoke',
            status: 'passed',
            exit_code: 0,
            duration_ms: 1000,
            failure_reason: null,
            output_excerpt: '',
            evidence_paths: ['artifacts/smoke/smoke-1.json'],
            request_ids: []
          },
          {
            check_id: 'smoke.evidence',
            check_name: 'Smoke/Chrome evidence validation',
            status: 'failed',
            exit_code: 1,
            duration_ms: 0,
            failure_reason: 'missing-chrome-evidence',
            output_excerpt: 'No chrome report found',
            evidence_paths: ['artifacts/smoke/smoke-1.json'],
            request_ids: []
          }
        ]
      }
    ],
    evidence: {
      evidence_paths: ['artifacts/smoke/smoke-1.json'],
      request_ids: [],
      issues: [
        {
          check_id: 'smoke.evidence',
          reason: 'missing-chrome-evidence',
          details: 'No chrome report found'
        }
      ]
    }
  });

  assert.equal(report.groups[0].status, 'failed');
  assert.equal(report.blocking, true);
  assert.equal(report.failed_checks[0].output_excerpt, 'No chrome report found');
});

test('collectEvidenceInputs returns fail-closed issue when smoke evidence is missing', () => {
  const tempRoot = mkdtempSync(join(tmpdir(), 'release-gate-evidence-missing-'));
  const smokeDir = join(tempRoot, 'smoke');
  const chromeDir = join(tempRoot, 'chrome-regression');
  mkdirSync(smokeDir, { recursive: true });
  mkdirSync(chromeDir, { recursive: true });

  const evidence = collectEvidenceInputs({
    smokeDir,
    chromeDir,
    runStartedAtMs: Date.parse('2026-02-21T00:00:00.000Z'),
    nowMs: Date.parse('2026-02-21T00:30:00.000Z'),
    staleWindowMs: 30 * 60 * 1000
  });

  assert.equal(evidence.issues.length, 1);
  assert.match(evidence.issues[0].reason, /missing-smoke-evidence/);
});

test('collectEvidenceInputs extracts request IDs from latest smoke report', () => {
  const tempRoot = mkdtempSync(join(tmpdir(), 'release-gate-evidence-request-ids-'));
  const smokeDir = join(tempRoot, 'smoke');
  const chromeDir = join(tempRoot, 'chrome-regression');
  mkdirSync(smokeDir, { recursive: true });
  mkdirSync(chromeDir, { recursive: true });

  const chromeJsonPath = join(chromeDir, 'chrome-regression-2026-02-21T00-00-00-000Z.json');
  const chromePngPath = join(chromeDir, 'chrome-regression-2026-02-21T00-00-00-000Z.png');
  writeFileSync(
    chromeJsonPath,
    JSON.stringify({
      generated_at: '2026-02-21T00:00:01.000Z',
      screenshots: [chromePngPath]
    })
  );
  writeFileSync(chromePngPath, Buffer.from('png-binary'));

  const smokeJsonPath = join(smokeDir, 'smoke-2026-02-21T00-00-00-000Z.json');
  writeFileSync(
    smokeJsonPath,
    JSON.stringify({
      generated_at: '2026-02-21T00:00:02.000Z',
      passed: true,
      chrome_regression: {
        report: chromeJsonPath
      },
      api_payload: {
        request_id: 'req-api-1'
      },
      web_payload: {
        request_id: 'req-web-1'
      },
      online_drill: {
        create_request_id: 'req-create-1',
        disable_request_id: 'req-disable-1',
        enable_request_id: 'req-enable-1'
      },
      steps: [
        { request_id: 'req-step-1' },
        { meta: { nested_request_id: 'req-step-2' } }
      ],
      telemetry: {
        requestId: 'req-camel-1',
        request_ids: ['req-array-1', 'req-array-2'],
        nested: {
          trace_requestid: 'req-trace-1'
        }
      }
    })
  );

  const evidence = collectEvidenceInputs({
    smokeDir,
    chromeDir,
    runStartedAtMs: Date.parse('2026-02-21T00:00:00.000Z'),
    nowMs: Date.parse('2026-02-21T00:00:20.000Z'),
    staleWindowMs: 30 * 60 * 1000
  });

  assert.equal(evidence.issues.length, 0);
  assert.deepEqual(evidence.request_ids, [
    'req-api-1',
    'req-array-1',
    'req-array-2',
    'req-camel-1',
    'req-create-1',
    'req-disable-1',
    'req-enable-1',
    'req-step-1',
    'req-step-2',
    'req-trace-1',
    'req-web-1'
  ]);
});

test('collectEvidenceInputs fails closed when expected run id is provided but smoke report misses release_gate_run_id', () => {
  const tempRoot = mkdtempSync(join(tmpdir(), 'release-gate-evidence-missing-run-id-'));
  const smokeDir = join(tempRoot, 'smoke');
  const chromeDir = join(tempRoot, 'chrome-regression');
  mkdirSync(smokeDir, { recursive: true });
  mkdirSync(chromeDir, { recursive: true });

  const chromeJsonPath = join(chromeDir, 'chrome-regression-2026-02-21T00-00-00-000Z.json');
  const chromePngPath = join(chromeDir, 'chrome-regression-2026-02-21T00-00-00-000Z.png');
  writeFileSync(
    chromeJsonPath,
    JSON.stringify({
      generated_at: '2026-02-21T00:00:01.000Z',
      screenshots: [chromePngPath]
    })
  );
  writeFileSync(chromePngPath, Buffer.from('png-binary'));

  const smokeJsonPath = join(smokeDir, 'smoke-2026-02-21T00-00-00-000Z.json');
  writeFileSync(
    smokeJsonPath,
    JSON.stringify({
      generated_at: '2026-02-21T00:00:02.000Z',
      passed: true,
      chrome_regression: {
        report: chromeJsonPath
      }
    })
  );

  const evidence = collectEvidenceInputs({
    smokeDir,
    chromeDir,
    runStartedAtMs: 0,
    nowMs: Date.parse('2026-02-21T00:01:00.000Z'),
    staleWindowMs: 10 * 60 * 1000,
    expectedRunId: 'gate-run-123'
  });

  assert.ok(evidence.issues.some((issue) => issue.reason === 'invalid-smoke-evidence'));
  assert.ok(evidence.issues.some((issue) => /missing release_gate_run_id/.test(issue.details)));
});

test('collectEvidenceInputs fails closed when smoke release_gate_run_id mismatches expected run id', () => {
  const tempRoot = mkdtempSync(join(tmpdir(), 'release-gate-evidence-run-id-mismatch-'));
  const smokeDir = join(tempRoot, 'smoke');
  const chromeDir = join(tempRoot, 'chrome-regression');
  mkdirSync(smokeDir, { recursive: true });
  mkdirSync(chromeDir, { recursive: true });

  const chromeJsonPath = join(chromeDir, 'chrome-regression-2026-02-21T00-00-00-000Z.json');
  const chromePngPath = join(chromeDir, 'chrome-regression-2026-02-21T00-00-00-000Z.png');
  writeFileSync(
    chromeJsonPath,
    JSON.stringify({
      generated_at: '2026-02-21T00:00:01.000Z',
      screenshots: [chromePngPath]
    })
  );
  writeFileSync(chromePngPath, Buffer.from('png-binary'));

  const smokeJsonPath = join(smokeDir, 'smoke-2026-02-21T00-00-00-000Z.json');
  writeFileSync(
    smokeJsonPath,
    JSON.stringify({
      generated_at: '2026-02-21T00:00:02.000Z',
      release_gate_run_id: 'gate-run-other',
      passed: true,
      chrome_regression: {
        report: chromeJsonPath
      }
    })
  );

  const evidence = collectEvidenceInputs({
    smokeDir,
    chromeDir,
    runStartedAtMs: 0,
    nowMs: Date.parse('2026-02-21T00:01:00.000Z'),
    staleWindowMs: 10 * 60 * 1000,
    expectedRunId: 'gate-run-123'
  });

  assert.ok(evidence.issues.some((issue) => issue.reason === 'invalid-smoke-evidence'));
  assert.ok(evidence.issues.some((issue) => /release_gate_run_id mismatch/.test(issue.details)));
});

test('collectEvidenceInputs marks stale smoke/chrome evidence as blocking issues', () => {
  const tempRoot = mkdtempSync(join(tmpdir(), 'release-gate-evidence-stale-'));
  const smokeDir = join(tempRoot, 'smoke');
  const chromeDir = join(tempRoot, 'chrome-regression');
  mkdirSync(smokeDir, { recursive: true });
  mkdirSync(chromeDir, { recursive: true });

  const chromeJsonPath = join(chromeDir, 'chrome-regression-2026-02-21T00-00-00-000Z.json');
  const chromePngPath = join(chromeDir, 'chrome-regression-2026-02-21T00-00-00-000Z.png');
  writeFileSync(
    chromeJsonPath,
    JSON.stringify({
      generated_at: '2026-02-21T00:00:01.000Z',
      screenshots: [chromePngPath]
    })
  );
  writeFileSync(chromePngPath, Buffer.from('png-binary'));

  const smokeJsonPath = join(smokeDir, 'smoke-2026-02-21T00-00-00-000Z.json');
  writeFileSync(
    smokeJsonPath,
    JSON.stringify({
      generated_at: '2026-02-21T00:00:02.000Z',
      chrome_regression: {
        report: chromeJsonPath
      }
    })
  );

  const evidence = collectEvidenceInputs({
    smokeDir,
    chromeDir,
    runStartedAtMs: Date.now() + 60_000,
    nowMs: Date.now() + 120_000,
    staleWindowMs: 60_000
  });

  const reasons = evidence.issues.map((issue) => issue.reason);
  assert.ok(reasons.includes('stale-smoke-evidence'));
  assert.ok(reasons.includes('stale-chrome-evidence'));
});

test('collectEvidenceInputs marks stale evidence when generated_at predates run even if files are fresh', () => {
  const tempRoot = mkdtempSync(join(tmpdir(), 'release-gate-evidence-generated-at-stale-'));
  const smokeDir = join(tempRoot, 'smoke');
  const chromeDir = join(tempRoot, 'chrome-regression');
  mkdirSync(smokeDir, { recursive: true });
  mkdirSync(chromeDir, { recursive: true });

  const chromeJsonPath = join(chromeDir, 'chrome-regression-2026-02-21T00-00-00-000Z.json');
  const chromePngPath = join(chromeDir, 'chrome-regression-2026-02-21T00-00-00-000Z.png');
  writeFileSync(
    chromeJsonPath,
    JSON.stringify({
      generated_at: '2026-02-21T00:00:00.000Z',
      screenshots: [chromePngPath]
    })
  );
  writeFileSync(chromePngPath, Buffer.from('png-binary'));

  const smokeJsonPath = join(smokeDir, 'smoke-2026-02-21T00-00-00-000Z.json');
  writeFileSync(
    smokeJsonPath,
    JSON.stringify({
      generated_at: '2026-02-21T00:00:00.000Z',
      chrome_regression: {
        report: chromeJsonPath
      }
    })
  );

  const evidence = collectEvidenceInputs({
    smokeDir,
    chromeDir,
    runStartedAtMs: Date.parse('2026-02-21T01:00:00.000Z'),
    nowMs: Date.parse('2026-02-21T01:05:00.000Z'),
    staleWindowMs: 10 * 60 * 1000
  });

  const reasons = evidence.issues.map((issue) => issue.reason);
  assert.ok(reasons.includes('stale-smoke-evidence'));
  assert.ok(reasons.includes('stale-chrome-evidence'));
});

test('collectEvidenceInputs fails closed when smoke generated_at is unexpectedly in the future', () => {
  const tempRoot = mkdtempSync(join(tmpdir(), 'release-gate-evidence-smoke-future-'));
  const smokeDir = join(tempRoot, 'smoke');
  const chromeDir = join(tempRoot, 'chrome-regression');
  mkdirSync(smokeDir, { recursive: true });
  mkdirSync(chromeDir, { recursive: true });

  const chromeJsonPath = join(chromeDir, 'chrome-regression-2026-02-21T00-00-00-000Z.json');
  const chromePngPath = join(chromeDir, 'chrome-regression-2026-02-21T00-00-00-000Z.png');
  writeFileSync(
    chromeJsonPath,
    JSON.stringify({
      generated_at: '2026-02-21T00:00:02.000Z',
      screenshots: [chromePngPath]
    })
  );
  writeFileSync(chromePngPath, Buffer.from('png-binary'));

  const smokeJsonPath = join(smokeDir, 'smoke-2026-02-21T00-00-00-000Z.json');
  writeFileSync(
    smokeJsonPath,
    JSON.stringify({
      generated_at: '2026-02-21T00:20:00.000Z',
      passed: true,
      chrome_regression: {
        report: chromeJsonPath
      }
    })
  );

  const evidence = collectEvidenceInputs({
    smokeDir,
    chromeDir,
    runStartedAtMs: Date.parse('2026-02-21T00:00:00.000Z'),
    nowMs: Date.parse('2026-02-21T00:01:00.000Z'),
    staleWindowMs: 30 * 60 * 1000
  });

  assert.ok(evidence.issues.some((issue) => issue.reason === 'invalid-smoke-evidence'));
});

test('collectEvidenceInputs fails closed when chrome generated_at is unexpectedly in the future', () => {
  const tempRoot = mkdtempSync(join(tmpdir(), 'release-gate-evidence-chrome-future-'));
  const smokeDir = join(tempRoot, 'smoke');
  const chromeDir = join(tempRoot, 'chrome-regression');
  mkdirSync(smokeDir, { recursive: true });
  mkdirSync(chromeDir, { recursive: true });

  const chromeJsonPath = join(chromeDir, 'chrome-regression-2026-02-21T00-00-00-000Z.json');
  const chromePngPath = join(chromeDir, 'chrome-regression-2026-02-21T00-00-00-000Z.png');
  writeFileSync(
    chromeJsonPath,
    JSON.stringify({
      generated_at: '2026-02-21T00:20:00.000Z',
      screenshots: [chromePngPath]
    })
  );
  writeFileSync(chromePngPath, Buffer.from('png-binary'));

  const smokeJsonPath = join(smokeDir, 'smoke-2026-02-21T00-00-00-000Z.json');
  writeFileSync(
    smokeJsonPath,
    JSON.stringify({
      generated_at: '2026-02-21T00:00:02.000Z',
      passed: true,
      chrome_regression: {
        report: chromeJsonPath
      }
    })
  );

  const evidence = collectEvidenceInputs({
    smokeDir,
    chromeDir,
    runStartedAtMs: Date.parse('2026-02-21T00:00:00.000Z'),
    nowMs: Date.parse('2026-02-21T00:01:00.000Z'),
    staleWindowMs: 30 * 60 * 1000
  });

  assert.ok(evidence.issues.some((issue) => issue.reason === 'invalid-chrome-evidence'));
});

test('collectEvidenceInputs fails closed when smoke report marks passed=false', () => {
  const tempRoot = mkdtempSync(join(tmpdir(), 'release-gate-evidence-smoke-failed-'));
  const smokeDir = join(tempRoot, 'smoke');
  const chromeDir = join(tempRoot, 'chrome-regression');
  mkdirSync(smokeDir, { recursive: true });
  mkdirSync(chromeDir, { recursive: true });

  const chromeJsonPath = join(chromeDir, 'chrome-regression-2026-02-21T00-00-00-000Z.json');
  const chromePngPath = join(chromeDir, 'chrome-regression-2026-02-21T00-00-00-000Z.png');
  writeFileSync(
    chromeJsonPath,
    JSON.stringify({
      generated_at: '2026-02-21T00:00:01.000Z',
      screenshots: [chromePngPath]
    })
  );
  writeFileSync(chromePngPath, Buffer.from('png-binary'));

  const smokeJsonPath = join(smokeDir, 'smoke-2026-02-21T00-00-00-000Z.json');
  writeFileSync(
    smokeJsonPath,
    JSON.stringify({
      generated_at: '2026-02-21T00:00:02.000Z',
      passed: false,
      error: 'Smoke validation failed',
      chrome_regression: {
        report: chromeJsonPath
      }
    })
  );

  const evidence = collectEvidenceInputs({
    smokeDir,
    chromeDir,
    runStartedAtMs: 0,
    nowMs: Date.parse('2026-02-21T00:01:00.000Z'),
    staleWindowMs: 10 * 60 * 1000
  });

  assert.ok(evidence.issues.some((issue) => issue.reason === 'smoke-report-failed'));
});

test('collectEvidenceInputs fails closed when smoke report is skipped', () => {
  const tempRoot = mkdtempSync(join(tmpdir(), 'release-gate-evidence-smoke-skipped-'));
  const smokeDir = join(tempRoot, 'smoke');
  const chromeDir = join(tempRoot, 'chrome-regression');
  mkdirSync(smokeDir, { recursive: true });
  mkdirSync(chromeDir, { recursive: true });

  const chromeJsonPath = join(chromeDir, 'chrome-regression-2026-02-21T00-00-00-000Z.json');
  const chromePngPath = join(chromeDir, 'chrome-regression-2026-02-21T00-00-00-000Z.png');
  writeFileSync(
    chromeJsonPath,
    JSON.stringify({
      generated_at: '2026-02-21T00:00:01.000Z',
      screenshots: [chromePngPath]
    })
  );
  writeFileSync(chromePngPath, Buffer.from('png-binary'));

  const smokeJsonPath = join(smokeDir, 'smoke-2026-02-21T00-00-00-000Z.json');
  writeFileSync(
    smokeJsonPath,
    JSON.stringify({
      generated_at: '2026-02-21T00:00:02.000Z',
      passed: false,
      skipped: true,
      skip_reason: 'Docker environment unavailable',
      chrome_regression: {
        report: chromeJsonPath
      }
    })
  );

  const evidence = collectEvidenceInputs({
    smokeDir,
    chromeDir,
    runStartedAtMs: 0,
    nowMs: Date.parse('2026-02-21T00:01:00.000Z'),
    staleWindowMs: 10 * 60 * 1000
  });

  assert.ok(evidence.issues.some((issue) => issue.reason === 'smoke-report-skipped'));
});

test('collectEvidenceInputs fails closed when smoke generated_at is invalid', () => {
  const tempRoot = mkdtempSync(join(tmpdir(), 'release-gate-evidence-invalid-generated-at-'));
  const smokeDir = join(tempRoot, 'smoke');
  const chromeDir = join(tempRoot, 'chrome-regression');
  mkdirSync(smokeDir, { recursive: true });
  mkdirSync(chromeDir, { recursive: true });

  const chromeJsonPath = join(chromeDir, 'chrome-regression-2026-02-21T00-00-00-000Z.json');
  const chromePngPath = join(chromeDir, 'chrome-regression-2026-02-21T00-00-00-000Z.png');
  writeFileSync(
    chromeJsonPath,
    JSON.stringify({
      generated_at: '2026-02-21T00:00:01.000Z',
      screenshots: [chromePngPath]
    })
  );
  writeFileSync(chromePngPath, Buffer.from('png-binary'));

  const smokeJsonPath = join(smokeDir, 'smoke-2026-02-21T00-00-00-000Z.json');
  writeFileSync(
    smokeJsonPath,
    JSON.stringify({
      generated_at: 'not-a-date',
      chrome_regression: {
        report: chromeJsonPath
      }
    })
  );

  const evidence = collectEvidenceInputs({
    smokeDir,
    chromeDir,
    runStartedAtMs: 0,
    nowMs: Date.now(),
    staleWindowMs: 10 * 365 * 24 * 60 * 60 * 1000
  });

  assert.ok(evidence.issues.some((issue) => issue.reason === 'invalid-smoke-evidence'));
});

test('collectEvidenceInputs fails closed when smoke references missing chrome report even if another chrome report exists', () => {
  const tempRoot = mkdtempSync(join(tmpdir(), 'release-gate-evidence-missing-referenced-chrome-'));
  const smokeDir = join(tempRoot, 'smoke');
  const chromeDir = join(tempRoot, 'chrome-regression');
  mkdirSync(smokeDir, { recursive: true });
  mkdirSync(chromeDir, { recursive: true });

  const fallbackChromeJsonPath = join(chromeDir, 'chrome-regression-2026-02-21T00-00-01-000Z.json');
  const fallbackChromePngPath = join(chromeDir, 'chrome-regression-2026-02-21T00-00-01-000Z.png');
  writeFileSync(
    fallbackChromeJsonPath,
    JSON.stringify({
      generated_at: '2026-02-21T00:00:01.000Z',
      screenshots: [fallbackChromePngPath]
    })
  );
  writeFileSync(fallbackChromePngPath, Buffer.from('png-binary'));

  const missingReferencedChromePath = join(chromeDir, 'chrome-regression-2026-02-21T00-00-00-000Z.json');
  const smokeJsonPath = join(smokeDir, 'smoke-2026-02-21T00-00-00-000Z.json');
  writeFileSync(
    smokeJsonPath,
    JSON.stringify({
      generated_at: '2026-02-21T00:00:02.000Z',
      chrome_regression: {
        report: missingReferencedChromePath
      }
    })
  );

  const evidence = collectEvidenceInputs({
    smokeDir,
    chromeDir,
    runStartedAtMs: 0,
    nowMs: Date.parse('2026-02-21T00:01:00.000Z'),
    staleWindowMs: 10 * 60 * 1000
  });

  assert.equal(evidence.chrome_report, null);
  const missingChromeIssues = evidence.issues.filter(
    (issue) => issue.reason === 'missing-chrome-evidence'
  );
  assert.equal(missingChromeIssues.length, 1);
  assert.match(missingChromeIssues[0].details, /references missing chrome report/);
});

test('collectEvidenceInputs fails closed when smoke references chrome report outside configured chrome directory', () => {
  const tempRoot = mkdtempSync(join(tmpdir(), 'release-gate-evidence-outside-chrome-dir-'));
  const smokeDir = join(tempRoot, 'smoke');
  const chromeDir = join(tempRoot, 'chrome-regression');
  mkdirSync(smokeDir, { recursive: true });
  mkdirSync(chromeDir, { recursive: true });

  const externalChromeJsonPath = join(tempRoot, 'external-chrome-report.json');
  const externalChromePngPath = join(tempRoot, 'external-chrome-report.png');
  writeFileSync(
    externalChromeJsonPath,
    JSON.stringify({
      generated_at: '2026-02-21T00:00:01.000Z',
      screenshots: [externalChromePngPath]
    })
  );
  writeFileSync(externalChromePngPath, Buffer.from('png-binary'));

  const smokeJsonPath = join(smokeDir, 'smoke-2026-02-21T00-00-00-000Z.json');
  writeFileSync(
    smokeJsonPath,
    JSON.stringify({
      generated_at: '2026-02-21T00:00:02.000Z',
      passed: true,
      chrome_regression: {
        report: externalChromeJsonPath
      }
    })
  );

  const evidence = collectEvidenceInputs({
    smokeDir,
    chromeDir,
    runStartedAtMs: 0,
    nowMs: Date.parse('2026-02-21T00:01:00.000Z'),
    staleWindowMs: 10 * 60 * 1000
  });

  assert.equal(evidence.chrome_report, null);
  assert.ok(evidence.issues.some((issue) => issue.reason === 'invalid-chrome-evidence'));
});

test('collectEvidenceInputs fails closed when smoke references chrome report symlink escaping configured directory', () => {
  const tempRoot = mkdtempSync(join(tmpdir(), 'release-gate-evidence-outside-chrome-symlink-'));
  const smokeDir = join(tempRoot, 'smoke');
  const chromeDir = join(tempRoot, 'chrome-regression');
  mkdirSync(smokeDir, { recursive: true });
  mkdirSync(chromeDir, { recursive: true });

  const externalChromePngPath = join(tempRoot, 'external-linked-chrome-report.png');
  writeFileSync(externalChromePngPath, Buffer.from('png-binary'));
  const externalChromeJsonPath = join(tempRoot, 'external-linked-chrome-report.json');
  writeFileSync(
    externalChromeJsonPath,
    JSON.stringify({
      generated_at: '2026-02-21T00:00:01.000Z',
      screenshots: [externalChromePngPath]
    })
  );
  const linkedChromeJsonPath = join(chromeDir, 'chrome-regression-linked.json');
  symlinkSync(externalChromeJsonPath, linkedChromeJsonPath);

  const smokeJsonPath = join(smokeDir, 'smoke-2026-02-21T00-00-00-000Z.json');
  writeFileSync(
    smokeJsonPath,
    JSON.stringify({
      generated_at: '2026-02-21T00:00:02.000Z',
      passed: true,
      chrome_regression: {
        report: linkedChromeJsonPath
      }
    })
  );

  const evidence = collectEvidenceInputs({
    smokeDir,
    chromeDir,
    runStartedAtMs: 0,
    nowMs: Date.parse('2026-02-21T00:01:00.000Z'),
    staleWindowMs: 10 * 60 * 1000
  });

  assert.equal(evidence.chrome_report, null);
  assert.ok(evidence.issues.some((issue) => issue.reason === 'invalid-chrome-evidence'));
});

test('collectEvidenceInputs fails closed when smoke references chrome report with unexpected filename pattern', () => {
  const tempRoot = mkdtempSync(join(tmpdir(), 'release-gate-evidence-invalid-chrome-filename-'));
  const smokeDir = join(tempRoot, 'smoke');
  const chromeDir = join(tempRoot, 'chrome-regression');
  mkdirSync(smokeDir, { recursive: true });
  mkdirSync(chromeDir, { recursive: true });

  const customChromeJsonPath = join(chromeDir, 'custom-report.json');
  const customChromePngPath = join(chromeDir, 'custom-report.png');
  writeFileSync(
    customChromeJsonPath,
    JSON.stringify({
      generated_at: '2026-02-21T00:00:01.000Z',
      screenshots: [customChromePngPath]
    })
  );
  writeFileSync(customChromePngPath, Buffer.from('png-binary'));

  const smokeJsonPath = join(smokeDir, 'smoke-2026-02-21T00-00-00-000Z.json');
  writeFileSync(
    smokeJsonPath,
    JSON.stringify({
      generated_at: '2026-02-21T00:00:02.000Z',
      passed: true,
      chrome_regression: {
        report: customChromeJsonPath
      }
    })
  );

  const evidence = collectEvidenceInputs({
    smokeDir,
    chromeDir,
    runStartedAtMs: 0,
    nowMs: Date.parse('2026-02-21T00:01:00.000Z'),
    staleWindowMs: 10 * 60 * 1000
  });

  assert.equal(evidence.chrome_report, null);
  const invalidIssues = evidence.issues.filter((issue) => issue.reason === 'invalid-chrome-evidence');
  assert.equal(invalidIssues.length, 1);
  assert.match(invalidIssues[0].details, /unexpected filename pattern/);
});

test('collectEvidenceInputs fails closed when latest smoke evidence symlink escapes configured smoke directory', () => {
  const tempRoot = mkdtempSync(join(tmpdir(), 'release-gate-evidence-outside-smoke-symlink-'));
  const smokeDir = join(tempRoot, 'smoke');
  const chromeDir = join(tempRoot, 'chrome-regression');
  mkdirSync(smokeDir, { recursive: true });
  mkdirSync(chromeDir, { recursive: true });

  const externalSmokeJsonPath = join(tempRoot, 'external-smoke-report.json');
  writeFileSync(
    externalSmokeJsonPath,
    JSON.stringify({
      generated_at: '2026-02-21T00:00:02.000Z',
      passed: true
    })
  );
  const linkedSmokeJsonPath = join(smokeDir, 'smoke-2026-02-21T00-00-00-000Z.json');
  symlinkSync(externalSmokeJsonPath, linkedSmokeJsonPath);

  const evidence = collectEvidenceInputs({
    smokeDir,
    chromeDir,
    runStartedAtMs: 0,
    nowMs: Date.parse('2026-02-21T00:01:00.000Z'),
    staleWindowMs: 10 * 60 * 1000
  });

  assert.equal(evidence.smoke_report, resolve(linkedSmokeJsonPath).replace(/\\/g, '/'));
  assert.equal(evidence.chrome_report, null);
  assert.ok(evidence.issues.some((issue) => issue.reason === 'invalid-smoke-evidence'));
});

test('collectEvidenceInputs fails closed when smoke report omits chrome reference even if chrome evidence exists', () => {
  const tempRoot = mkdtempSync(join(tmpdir(), 'release-gate-evidence-missing-chrome-reference-'));
  const smokeDir = join(tempRoot, 'smoke');
  const chromeDir = join(tempRoot, 'chrome-regression');
  mkdirSync(smokeDir, { recursive: true });
  mkdirSync(chromeDir, { recursive: true });

  const smokeJsonPath = join(smokeDir, 'smoke-2026-02-21T00-00-00-000Z.json');
  writeFileSync(
    smokeJsonPath,
    JSON.stringify({
      generated_at: '2026-02-21T00:00:02.000Z',
      passed: true
    })
  );

  const chromePngPath = join(chromeDir, 'chrome-regression-2026-02-21T00-00-00-000Z.png');
  writeFileSync(chromePngPath, Buffer.from('png-binary'));
  const chromeJsonPath = join(chromeDir, 'chrome-regression-2026-02-21T00-00-00-000Z.json');
  writeFileSync(
    chromeJsonPath,
    JSON.stringify({
      generated_at: '2026-02-21T00:00:01.000Z',
      screenshots: [chromePngPath]
    })
  );

  const evidence = collectEvidenceInputs({
    smokeDir,
    chromeDir,
    runStartedAtMs: 0,
    nowMs: Date.parse('2026-02-21T00:01:00.000Z'),
    staleWindowMs: 10 * 60 * 1000
  });

  assert.equal(evidence.chrome_report, null);
  assert.ok(evidence.issues.some((issue) => issue.reason === 'missing-chrome-evidence'));
  assert.ok(evidence.issues.some((issue) => /missing chrome_regression\.report reference/.test(issue.details)));
});

test('collectEvidenceInputs fails closed when chrome screenshot is missing', () => {
  const tempRoot = mkdtempSync(join(tmpdir(), 'release-gate-evidence-broken-screenshot-'));
  const smokeDir = join(tempRoot, 'smoke');
  const chromeDir = join(tempRoot, 'chrome-regression');
  mkdirSync(smokeDir, { recursive: true });
  mkdirSync(chromeDir, { recursive: true });

  const missingScreenshotPath = join(chromeDir, 'chrome-regression-2026-02-21T00-00-00-000Z.png');
  const chromeJsonPath = join(chromeDir, 'chrome-regression-2026-02-21T00-00-00-000Z.json');
  writeFileSync(
    chromeJsonPath,
    JSON.stringify({
      generated_at: '2026-02-21T00:00:01.000Z',
      screenshots: [missingScreenshotPath]
    })
  );

  const smokeJsonPath = join(smokeDir, 'smoke-2026-02-21T00-00-00-000Z.json');
  writeFileSync(
    smokeJsonPath,
    JSON.stringify({
      generated_at: '2026-02-21T00:00:02.000Z',
      chrome_regression: {
        report: chromeJsonPath
      }
    })
  );

  const evidence = collectEvidenceInputs({
    smokeDir,
    chromeDir,
    runStartedAtMs: 0,
    nowMs: Date.now(),
    staleWindowMs: 10 * 60 * 1000
  });

  assert.ok(evidence.issues.some((issue) => issue.reason === 'missing-chrome-screenshot'));
});

test('collectEvidenceInputs fails closed when chrome screenshot path points outside configured chrome directory', () => {
  const tempRoot = mkdtempSync(join(tmpdir(), 'release-gate-evidence-outside-screenshot-'));
  const smokeDir = join(tempRoot, 'smoke');
  const chromeDir = join(tempRoot, 'chrome-regression');
  mkdirSync(smokeDir, { recursive: true });
  mkdirSync(chromeDir, { recursive: true });

  const externalScreenshotPath = join(tempRoot, 'external-screenshot.png');
  writeFileSync(externalScreenshotPath, Buffer.from('png-binary'));

  const chromeJsonPath = join(chromeDir, 'chrome-regression-2026-02-21T00-00-00-000Z.json');
  writeFileSync(
    chromeJsonPath,
    JSON.stringify({
      generated_at: '2026-02-21T00:00:01.000Z',
      screenshots: [externalScreenshotPath]
    })
  );

  const smokeJsonPath = join(smokeDir, 'smoke-2026-02-21T00-00-00-000Z.json');
  writeFileSync(
    smokeJsonPath,
    JSON.stringify({
      generated_at: '2026-02-21T00:00:02.000Z',
      passed: true,
      chrome_regression: {
        report: chromeJsonPath
      }
    })
  );

  const evidence = collectEvidenceInputs({
    smokeDir,
    chromeDir,
    runStartedAtMs: 0,
    nowMs: Date.parse('2026-02-21T00:01:00.000Z'),
    staleWindowMs: 10 * 60 * 1000
  });

  assert.ok(evidence.issues.some((issue) => issue.reason === 'invalid-chrome-evidence'));
});

test('collectEvidenceInputs fails closed when chrome screenshot symlink points outside configured chrome directory', () => {
  const tempRoot = mkdtempSync(join(tmpdir(), 'release-gate-evidence-outside-screenshot-symlink-'));
  const smokeDir = join(tempRoot, 'smoke');
  const chromeDir = join(tempRoot, 'chrome-regression');
  mkdirSync(smokeDir, { recursive: true });
  mkdirSync(chromeDir, { recursive: true });

  const externalScreenshotPath = join(tempRoot, 'external-screenshot-target.png');
  writeFileSync(externalScreenshotPath, Buffer.from('png-binary'));
  const linkedScreenshotPath = join(chromeDir, 'chrome-regression-linked.png');
  symlinkSync(externalScreenshotPath, linkedScreenshotPath);

  const chromeJsonPath = join(chromeDir, 'chrome-regression-2026-02-21T00-00-00-000Z.json');
  writeFileSync(
    chromeJsonPath,
    JSON.stringify({
      generated_at: '2026-02-21T00:00:01.000Z',
      screenshots: [linkedScreenshotPath]
    })
  );

  const smokeJsonPath = join(smokeDir, 'smoke-2026-02-21T00-00-00-000Z.json');
  writeFileSync(
    smokeJsonPath,
    JSON.stringify({
      generated_at: '2026-02-21T00:00:02.000Z',
      passed: true,
      chrome_regression: {
        report: chromeJsonPath
      }
    })
  );

  const evidence = collectEvidenceInputs({
    smokeDir,
    chromeDir,
    runStartedAtMs: 0,
    nowMs: Date.parse('2026-02-21T00:01:00.000Z'),
    staleWindowMs: 10 * 60 * 1000
  });

  assert.ok(evidence.issues.some((issue) => issue.reason === 'invalid-chrome-evidence'));
});

test('collectEvidenceInputs fails closed when chrome screenshot path is a directory', () => {
  const tempRoot = mkdtempSync(join(tmpdir(), 'release-gate-evidence-directory-screenshot-'));
  const smokeDir = join(tempRoot, 'smoke');
  const chromeDir = join(tempRoot, 'chrome-regression');
  mkdirSync(smokeDir, { recursive: true });
  mkdirSync(chromeDir, { recursive: true });

  const screenshotDirectoryPath = join(chromeDir, 'chrome-regression-as-directory.png');
  mkdirSync(screenshotDirectoryPath, { recursive: true });

  const chromeJsonPath = join(chromeDir, 'chrome-regression-2026-02-21T00-00-00-000Z.json');
  writeFileSync(
    chromeJsonPath,
    JSON.stringify({
      generated_at: '2026-02-21T00:00:01.000Z',
      screenshots: [screenshotDirectoryPath]
    })
  );

  const smokeJsonPath = join(smokeDir, 'smoke-2026-02-21T00-00-00-000Z.json');
  writeFileSync(
    smokeJsonPath,
    JSON.stringify({
      generated_at: '2026-02-21T00:00:02.000Z',
      passed: true,
      chrome_regression: {
        report: chromeJsonPath
      }
    })
  );

  const evidence = collectEvidenceInputs({
    smokeDir,
    chromeDir,
    runStartedAtMs: 0,
    nowMs: Date.parse('2026-02-21T00:01:00.000Z'),
    staleWindowMs: 10 * 60 * 1000
  });

  assert.ok(evidence.issues.some((issue) => issue.reason === 'invalid-chrome-evidence'));
  assert.ok(evidence.issues.some((issue) => /not a regular file/.test(issue.details)));
});

test('collectEvidenceInputs fails closed when chrome screenshot filename does not follow expected contract', () => {
  const tempRoot = mkdtempSync(join(tmpdir(), 'release-gate-evidence-invalid-screenshot-filename-'));
  const smokeDir = join(tempRoot, 'smoke');
  const chromeDir = join(tempRoot, 'chrome-regression');
  mkdirSync(smokeDir, { recursive: true });
  mkdirSync(chromeDir, { recursive: true });

  const customScreenshotPath = join(chromeDir, 'custom-screenshot.png');
  writeFileSync(customScreenshotPath, Buffer.from('png-binary'));
  const chromeJsonPath = join(chromeDir, 'chrome-regression-2026-02-21T00-00-00-000Z.json');
  writeFileSync(
    chromeJsonPath,
    JSON.stringify({
      generated_at: '2026-02-21T00:00:01.000Z',
      screenshots: [customScreenshotPath]
    })
  );

  const smokeJsonPath = join(smokeDir, 'smoke-2026-02-21T00-00-00-000Z.json');
  writeFileSync(
    smokeJsonPath,
    JSON.stringify({
      generated_at: '2026-02-21T00:00:02.000Z',
      passed: true,
      chrome_regression: {
        report: chromeJsonPath
      }
    })
  );

  const evidence = collectEvidenceInputs({
    smokeDir,
    chromeDir,
    runStartedAtMs: 0,
    nowMs: Date.parse('2026-02-21T00:01:00.000Z'),
    staleWindowMs: 10 * 60 * 1000
  });

  assert.ok(evidence.issues.some((issue) => issue.reason === 'invalid-chrome-evidence'));
  assert.ok(evidence.issues.some((issue) => /unexpected filename pattern/.test(issue.details)));
});

test('collectEvidenceInputs deterministically chooses latest smoke report when mtimes are identical', () => {
  const tempRoot = mkdtempSync(join(tmpdir(), 'release-gate-evidence-deterministic-order-'));
  const smokeDir = join(tempRoot, 'smoke');
  const chromeDir = join(tempRoot, 'chrome-regression');
  mkdirSync(smokeDir, { recursive: true });
  mkdirSync(chromeDir, { recursive: true });

  const chromeJsonPathA = join(chromeDir, 'chrome-regression-2026-02-21T00-00-00-000Z.json');
  const chromePngPathA = join(chromeDir, 'chrome-regression-2026-02-21T00-00-00-000Z.png');
  writeFileSync(chromeJsonPathA, JSON.stringify({
    generated_at: '2026-02-21T00:00:02.000Z',
    screenshots: [chromePngPathA]
  }));
  writeFileSync(chromePngPathA, Buffer.from('png-binary'));

  const chromeJsonPathB = join(chromeDir, 'chrome-regression-2026-02-21T00-00-01-000Z.json');
  const chromePngPathB = join(chromeDir, 'chrome-regression-2026-02-21T00-00-01-000Z.png');
  writeFileSync(chromeJsonPathB, JSON.stringify({
    generated_at: '2026-02-21T00:00:03.000Z',
    screenshots: [chromePngPathB]
  }));
  writeFileSync(chromePngPathB, Buffer.from('png-binary'));

  const smokeJsonPathA = join(smokeDir, 'smoke-2026-02-21T00-00-00-000Z.json');
  writeFileSync(smokeJsonPathA, JSON.stringify({
    generated_at: '2026-02-21T00:00:02.000Z',
    passed: true,
    chrome_regression: {
      report: chromeJsonPathA
    }
  }));

  const smokeJsonPathB = join(smokeDir, 'smoke-2026-02-21T00-00-01-000Z.json');
  writeFileSync(smokeJsonPathB, JSON.stringify({
    generated_at: '2026-02-21T00:00:03.000Z',
    passed: true,
    chrome_regression: {
      report: chromeJsonPathB
    }
  }));

  const sameTimestamp = new Date('2026-02-21T00:02:00.000Z');
  for (const path of [smokeJsonPathA, smokeJsonPathB]) {
    utimesSync(path, sameTimestamp, sameTimestamp);
  }

  const evidence = collectEvidenceInputs({
    smokeDir,
    chromeDir,
    runStartedAtMs: Date.parse('2026-02-21T00:00:00.000Z'),
    nowMs: Date.parse('2026-02-21T00:03:00.000Z'),
    staleWindowMs: 30 * 60 * 1000
  });

  assert.equal(evidence.smoke_report, resolve(smokeJsonPathB).replace(/\\/g, '/'));
});

test('resolveStaleWindowMs falls back to default when env is invalid and clamps to minimum', () => {
  assert.equal(resolveStaleWindowMs('not-a-number'), 6 * 60 * 60 * 1000);
  assert.equal(resolveStaleWindowMs(30_000), 60_000);
  assert.equal(resolveStaleWindowMs(90_000), 90_000);
});

test('renderMarkdownSummary includes grouped failure breakdown', () => {
  const markdown = renderMarkdownSummary({
    run_id: 'run-123',
    generated_at: '2026-02-21T00:00:00.000Z',
    git_sha: 'abc1234',
    blocking: true,
    groups: [
      {
        group_id: 'lint',
        group_name: 'Lint',
        status: 'passed',
        blocking: true,
        fr_mapping: ['FR48'],
        checks: []
      },
      {
        group_id: 'smoke',
        group_name: 'Smoke',
        status: 'failed',
        blocking: true,
        fr_mapping: ['FR48', 'FR72'],
        checks: [
          {
            check_id: 'smoke.workspace',
            check_name: 'pnpm nx smoke',
            status: 'failed',
            failure_reason: 'missing-smoke-evidence',
            evidence_paths: ['artifacts/smoke/smoke-1.json']
          }
        ]
      }
    ],
    failed_checks: [
      {
        group_id: 'smoke',
        check_id: 'smoke.workspace',
        reason: 'missing-smoke-evidence'
      }
    ],
    evidence_paths: ['artifacts/smoke/smoke-1.json'],
    request_ids: ['req-web-1'],
    summary: {
      total_groups: 2,
      passed_groups: 1,
      failed_groups: 1,
      total_checks: 1,
      failed_checks: 1
    }
  });

  assert.match(markdown, /Group Breakdown/);
  assert.match(markdown, /smoke\.workspace/);
  assert.match(markdown, /missing-smoke-evidence/);
});
