const DEFAULT_START_AT = Date.parse('2026-01-01T00:00:00.000Z');
const DEFAULT_STEP_MS = 1;
const DEFAULT_SEED = 0x5e1f1234;

const normalizeSeed = (seed) => {
  const numericSeed = Number(seed);
  if (!Number.isFinite(numericSeed)) {
    return DEFAULT_SEED;
  }
  const normalized = Math.trunc(numericSeed) >>> 0;
  return normalized === 0 ? DEFAULT_SEED : normalized;
};

const createXorShift32 = (seed) => {
  let state = normalizeSeed(seed);
  return () => {
    state ^= state << 13;
    state ^= state >>> 17;
    state ^= state << 5;
    state >>>= 0;
    return state;
  };
};

export const withDeterministicEnv = async (
  {
    startAt = DEFAULT_START_AT,
    stepMs = DEFAULT_STEP_MS,
    seed = DEFAULT_SEED
  } = {},
  fn
) => {
  if (typeof fn !== 'function') {
    throw new TypeError('fn must be a function');
  }

  let cursor = Number.isFinite(startAt) ? Math.trunc(startAt) : DEFAULT_START_AT;
  const step = Number.isFinite(stepMs) && stepMs > 0 ? Math.trunc(stepMs) : DEFAULT_STEP_MS;
  const nextUint32 = createXorShift32(seed);

  const originalDateNow = Date.now;
  const originalMathRandom = Math.random;
  Date.now = () => {
    const now = cursor;
    cursor += step;
    return now;
  };
  Math.random = () => nextUint32() / 0xffffffff;

  try {
    return await fn();
  } finally {
    Date.now = originalDateNow;
    Math.random = originalMathRandom;
  }
};
