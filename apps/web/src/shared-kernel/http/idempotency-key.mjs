const randomHex = () => {
  if (typeof crypto !== 'undefined' && crypto && typeof crypto.randomUUID === 'function') {
    return crypto.randomUUID().replace(/-/g, '');
  }
  return Math.random().toString(16).slice(2);
};

export const buildIdempotencyKey = (prefix = 'ui-request') =>
  `${String(prefix || 'ui-request').trim()}-${Date.now()}-${randomHex()}`;
