const test = require('node:test');
const assert = require('node:assert/strict');
const { createDecipheriv } = require('node:crypto');
const { mkdirSync, mkdtempSync, symlinkSync, utimesSync, writeFileSync } = require('node:fs');
const { join } = require('node:path');
const { tmpdir } = require('node:os');
const {
  buildEncryptedSensitiveConfigValue,
  deriveSensitiveConfigKey,
  getLatestChromeRegressionArtifact,
  normalizeExitStatus,
  resolveSmokeComposeEnvironment,
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
  const reportPath = join(tempDir, 'chrome-regression-fresh.json');
  const screenshotPath = join(tempDir, 'chrome-regression-evidence.png');
  writeFileSync(reportPath, '{}');
  writeFileSync(screenshotPath, Buffer.from('png-binary'));

  const evidence = resolveChromeEvidence(200, () => ({
    report: reportPath,
    mtimeMs: 300,
    generated_at: '2026-02-12T00:00:01.000Z',
    screenshots: [screenshotPath]
  }));

  assert.equal(evidence.report, reportPath);
  assert.equal(evidence.mtimeMs, 300);
  assert.deepEqual(evidence.screenshots, [screenshotPath]);
});

test('resolveChromeEvidence rejects screenshots outside report directory', () => {
  const tempDir = mkdtempSync(join(tmpdir(), 'chrome-evidence-outside-dir-'));
  const reportDir = join(tempDir, 'reports');
  const externalDir = join(tempDir, 'external');
  const reportPath = join(reportDir, 'chrome-regression-2026-02-22T00-00-00-000Z.json');
  const externalScreenshotPath = join(externalDir, 'chrome-regression-outside.png');
  mkdirSync(reportDir, { recursive: true });
  mkdirSync(externalDir, { recursive: true });
  writeFileSync(reportPath, '{}');
  writeFileSync(externalScreenshotPath, Buffer.from('png-binary'));

  assert.throws(
    () =>
      resolveChromeEvidence(0, () => ({
        report: reportPath,
        mtimeMs: Date.now(),
        generated_at: '2026-02-22T00:00:01.000Z',
        screenshots: [externalScreenshotPath]
      })),
    /outside report directory/
  );
});

test('resolveChromeEvidence rejects screenshots with unexpected filename pattern', () => {
  const tempDir = mkdtempSync(join(tmpdir(), 'chrome-evidence-invalid-name-'));
  const reportPath = join(tempDir, 'chrome-regression-2026-02-22T00-00-00-000Z.json');
  const screenshotPath = join(tempDir, 'custom-name.png');
  writeFileSync(reportPath, '{}');
  writeFileSync(screenshotPath, Buffer.from('png-binary'));

  assert.throws(
    () =>
      resolveChromeEvidence(0, () => ({
        report: reportPath,
        mtimeMs: Date.now(),
        generated_at: '2026-02-22T00:00:01.000Z',
        screenshots: [screenshotPath]
      })),
    /filename is invalid/
  );
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

test('getLatestChromeRegressionArtifact chooses latest deterministically when mtimes are identical', () => {
  const tempDir = mkdtempSync(join(tmpdir(), 'chrome-evidence-deterministic-'));
  const reportA = join(tempDir, 'chrome-regression-2026-02-22T00-00-00-000Z.json');
  const reportB = join(tempDir, 'chrome-regression-2026-02-22T00-00-01-000Z.json');
  writeFileSync(reportA, JSON.stringify({ generated_at: '2026-02-22T00:00:00.000Z', screenshots: [] }));
  writeFileSync(reportB, JSON.stringify({ generated_at: '2026-02-22T00:00:01.000Z', screenshots: [] }));

  const sameTimestamp = new Date('2026-02-22T00:05:00.000Z');
  utimesSync(reportA, sameTimestamp, sameTimestamp);
  utimesSync(reportB, sameTimestamp, sameTimestamp);

  const latest = getLatestChromeRegressionArtifact(tempDir);
  assert.equal(latest?.report, reportB);
});

test('getLatestChromeRegressionArtifact ignores broken symlink candidates', () => {
  const tempDir = mkdtempSync(join(tmpdir(), 'chrome-evidence-broken-symlink-'));
  const validReport = join(tempDir, 'chrome-regression-2026-02-22T00-00-00-000Z.json');
  const brokenReport = join(tempDir, 'chrome-regression-2026-02-22T00-00-01-000Z.json');
  writeFileSync(validReport, JSON.stringify({
    generated_at: '2026-02-22T00:00:00.000Z',
    screenshots: []
  }));
  symlinkSync(join(tempDir, 'non-existent-target.json'), brokenReport);

  const latest = getLatestChromeRegressionArtifact(tempDir);
  assert.equal(latest?.report, validReport);
});

test('buildEncryptedSensitiveConfigValue produces decryptable envelope', () => {
  const decryptionKey = 'smoke-sensitive-config-key';
  const plainText = 'InitPass!2026';
  const envelope = buildEncryptedSensitiveConfigValue({
    plainText,
    decryptionKey
  });
  const sections = envelope.split(':');
  assert.equal(sections.length, 5);
  assert.equal(`${sections[0]}:${sections[1]}`, 'enc:v1');
  const derivedKey = deriveSensitiveConfigKey(decryptionKey);
  const iv = Buffer.from(sections[2], 'base64url');
  const authTag = Buffer.from(sections[3], 'base64url');
  const ciphertext = Buffer.from(sections[4], 'base64url');
  const decipher = createDecipheriv('aes-256-gcm', derivedKey, iv);
  decipher.setAuthTag(authTag);
  const decrypted = Buffer.concat([decipher.update(ciphertext), decipher.final()]).toString('utf8');
  assert.equal(decrypted, plainText);
});

test('resolveSmokeComposeEnvironment provisions encrypted password when required', () => {
  const sourceEnv = {
    AUTH_DEFAULT_PASSWORD_ENCRYPTED: '',
    AUTH_SENSITIVE_CONFIG_DECRYPTION_KEY: ''
  };
  const targetDefaultPassword = 'InitPass!2026';
  const resolved = resolveSmokeComposeEnvironment(sourceEnv, {
    forceProvisionConfig: true,
    targetDefaultPassword
  });

  assert.equal(resolved.generatedProvisionConfig, true);
  assert.notEqual(resolved.env.AUTH_DEFAULT_PASSWORD_ENCRYPTED, '');
  assert.notEqual(resolved.env.AUTH_SENSITIVE_CONFIG_DECRYPTION_KEY, '');
  assert.equal(sourceEnv.AUTH_DEFAULT_PASSWORD_ENCRYPTED, '');
  assert.equal(sourceEnv.AUTH_SENSITIVE_CONFIG_DECRYPTION_KEY, '');

  const sections = resolved.env.AUTH_DEFAULT_PASSWORD_ENCRYPTED.split(':');
  const derivedKey = deriveSensitiveConfigKey(resolved.env.AUTH_SENSITIVE_CONFIG_DECRYPTION_KEY);
  const decipher = createDecipheriv(
    'aes-256-gcm',
    derivedKey,
    Buffer.from(sections[2], 'base64url')
  );
  decipher.setAuthTag(Buffer.from(sections[3], 'base64url'));
  const decrypted = Buffer.concat([
    decipher.update(Buffer.from(sections[4], 'base64url')),
    decipher.final()
  ]).toString('utf8');
  assert.equal(decrypted, targetDefaultPassword);
});

test('resolveSmokeComposeEnvironment reuses existing provisioning config when force disabled', () => {
  const sourceEnv = {
    AUTH_DEFAULT_PASSWORD_ENCRYPTED: 'enc:v1:iv:tag:cipher',
    AUTH_SENSITIVE_CONFIG_DECRYPTION_KEY: 'existing-key'
  };
  const resolved = resolveSmokeComposeEnvironment(sourceEnv, {
    forceProvisionConfig: false,
    targetDefaultPassword: 'InitPass!2026'
  });

  assert.equal(resolved.generatedProvisionConfig, false);
  assert.equal(resolved.env.AUTH_DEFAULT_PASSWORD_ENCRYPTED, sourceEnv.AUTH_DEFAULT_PASSWORD_ENCRYPTED);
  assert.equal(
    resolved.env.AUTH_SENSITIVE_CONFIG_DECRYPTION_KEY,
    sourceEnv.AUTH_SENSITIVE_CONFIG_DECRYPTION_KEY
  );
});
