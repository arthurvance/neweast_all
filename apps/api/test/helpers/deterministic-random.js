'use strict';

const DEFAULT_SEED = 0x1a2b3c4d;

const normalizeSeed = (seed) => {
  const numericSeed = Number(seed);
  if (!Number.isFinite(numericSeed)) {
    return DEFAULT_SEED;
  }
  const normalized = Math.trunc(numericSeed) >>> 0;
  return normalized === 0 ? DEFAULT_SEED : normalized;
};

const createDeterministicRandom = ({ seed = DEFAULT_SEED } = {}) => {
  let state = normalizeSeed(seed);
  const initialState = state;

  const nextUint32 = () => {
    state ^= state << 13;
    state ^= state >>> 17;
    state ^= state << 5;
    state >>>= 0;
    return state;
  };

  const next = () => nextUint32() / 0xffffffff;
  const nextInt = (maxExclusive = 1) => {
    const max = Number.isFinite(maxExclusive) && maxExclusive > 0
      ? Math.trunc(maxExclusive)
      : 1;
    return Math.floor(next() * max);
  };
  const nextHex = (bytes = 16) => {
    const length = Number.isFinite(bytes) && bytes > 0 ? Math.trunc(bytes) : 16;
    const chunks = [];
    for (let index = 0; index < length; index += 1) {
      chunks.push(nextInt(256).toString(16).padStart(2, '0'));
    }
    return chunks.join('');
  };

  return {
    next,
    nextInt,
    nextHex,
    reset: () => {
      state = initialState;
    },
    patchMathRandom: () => {
      const originalMathRandom = Math.random;
      Math.random = () => next();
      return () => {
        Math.random = originalMathRandom;
      };
    }
  };
};

module.exports = {
  createDeterministicRandom
};
