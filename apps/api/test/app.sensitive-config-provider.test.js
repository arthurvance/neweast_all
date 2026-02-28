const test = require('node:test');
const assert = require('node:assert/strict');
const { _internals } = require('../src/app');

const {
  createEnvSensitiveConfigProvider,
  resolveRuntimeAuthStoreFromAuthService,
  DEFAULT_PASSWORD_CONFIG_KEY
} = _internals;

test('createEnvSensitiveConfigProvider prefers runtime active config over env', async () => {
  const provider = createEnvSensitiveConfigProvider(
    { AUTH_DEFAULT_PASSWORD_ENCRYPTED: 'enc:v1:env:tag:value' },
    {
      resolveAuthStore: () => ({
        getSystemSensitiveConfig: async () => ({
          key: DEFAULT_PASSWORD_CONFIG_KEY,
          value: 'enc:v1:runtime:tag:value',
          status: 'active'
        })
      })
    }
  );

  const encrypted = await provider.getEncryptedConfig(DEFAULT_PASSWORD_CONFIG_KEY);
  assert.equal(encrypted, 'enc:v1:runtime:tag:value');
});

test('createEnvSensitiveConfigProvider returns empty when runtime config is disabled', async () => {
  const provider = createEnvSensitiveConfigProvider(
    { AUTH_DEFAULT_PASSWORD_ENCRYPTED: 'enc:v1:env:tag:value' },
    {
      resolveAuthStore: () => ({
        getSystemSensitiveConfig: async () => ({
          key: DEFAULT_PASSWORD_CONFIG_KEY,
          value: 'enc:v1:runtime:tag:value',
          status: 'disabled'
        })
      })
    }
  );

  const encrypted = await provider.getEncryptedConfig(DEFAULT_PASSWORD_CONFIG_KEY);
  assert.equal(encrypted, '');
});

test('createEnvSensitiveConfigProvider returns empty when runtime store lookup fails', async () => {
  const provider = createEnvSensitiveConfigProvider(
    { AUTH_DEFAULT_PASSWORD_ENCRYPTED: 'enc:v1:env:tag:value' },
    {
      resolveAuthStore: () => ({
        getSystemSensitiveConfig: async () => {
          throw new Error('runtime-store-unavailable');
        }
      })
    }
  );

  const encrypted = await provider.getEncryptedConfig(DEFAULT_PASSWORD_CONFIG_KEY);
  assert.equal(encrypted, '');
});

test('createEnvSensitiveConfigProvider returns empty when runtime store is unavailable', async () => {
  const provider = createEnvSensitiveConfigProvider(
    { AUTH_DEFAULT_PASSWORD_ENCRYPTED: 'enc:v1:env:tag:value' },
    {
      resolveAuthStore: () => null
    }
  );

  const encrypted = await provider.getEncryptedConfig(DEFAULT_PASSWORD_CONFIG_KEY);
  assert.equal(encrypted, '');
});

test('resolveRuntimeAuthStoreFromAuthService extracts only compatible runtime stores', () => {
  const compatibleStore = {
    getSystemSensitiveConfig: async () => null
  };
  const compatibleService = {
    _internals: {
      authStore: compatibleStore
    }
  };
  const incompatibleService = {
    _internals: {
      authStore: {}
    }
  };

  assert.equal(
    resolveRuntimeAuthStoreFromAuthService(compatibleService),
    compatibleStore
  );
  assert.equal(
    resolveRuntimeAuthStoreFromAuthService(incompatibleService),
    null
  );
  assert.equal(resolveRuntimeAuthStoreFromAuthService(null), null);
});
