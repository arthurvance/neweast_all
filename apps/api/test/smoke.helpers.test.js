const test = require('node:test');
const assert = require('node:assert/strict');
const { mkdtempSync, writeFileSync } = require('node:fs');
const { join } = require('node:path');
const { tmpdir } = require('node:os');
const {
  normalizeExitStatus,
  resolveChromeEvidence
} = require('../../../tools/smoke');

test('normalizeExitStatus does not treat null status as success', () => {
  assert.equal(normalizeExitStatus(null, 'SIGTERM'), 1);
  assert.equal(normalizeExitStatus(undefined, null), 1);
  assert.equal(normalizeExitStatus(0, null), 0);
  assert.equal(normalizeExitStatus(2, null), 2);
});

test('resolveChromeEvidence rejects stale evidence before required timestamp', () => {
  assert.throws(
    () =>
      resolveChromeEvidence(200, () => ({
        report: 'artifacts/chrome-regression/chrome-regression-stale.json',
        mtimeMs: 100,
        generated_at: '2026-02-12T00:00:00.000Z',
        screenshots: []
      })),
    /Stale Chrome regression evidence detected/
  );
});

test('resolveChromeEvidence accepts fresh evidence and returns payload', () => {
  const tempDir = mkdtempSync(join(tmpdir(), 'chrome-evidence-'));
  const screenshotPath = join(tempDir, 'evidence.png');
  writeFileSync(screenshotPath, Buffer.from('png-binary'));

  const evidence = resolveChromeEvidence(200, () => ({
    report: 'artifacts/chrome-regression/chrome-regression-fresh.json',
    mtimeMs: 300,
    generated_at: '2026-02-12T00:00:01.000Z',
    screenshots: [screenshotPath]
  }));

  assert.equal(evidence.report, 'artifacts/chrome-regression/chrome-regression-fresh.json');
  assert.equal(evidence.mtimeMs, 300);
  assert.deepEqual(evidence.screenshots, [screenshotPath]);
});

test('resolveChromeEvidence rejects missing or empty screenshots evidence', () => {
  assert.throws(
    () =>
      resolveChromeEvidence(0, () => ({
        report: 'artifacts/chrome-regression/chrome-regression-empty.json',
        mtimeMs: 300,
        generated_at: '2026-02-12T00:00:01.000Z',
        screenshots: []
      })),
    /at least one screenshot/
  );
});
