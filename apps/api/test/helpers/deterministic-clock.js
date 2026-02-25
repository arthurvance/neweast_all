'use strict';

const DEFAULT_START_AT = '2026-01-01T00:00:00.000Z';
const DEFAULT_STEP_MS = 1;

const toEpoch = (value) => {
  if (typeof value === 'number' && Number.isFinite(value)) {
    return Math.trunc(value);
  }
  const parsed = Date.parse(String(value || DEFAULT_START_AT));
  if (Number.isNaN(parsed)) {
    return Date.parse(DEFAULT_START_AT);
  }
  return parsed;
};

const createDeterministicClock = ({ startAt = DEFAULT_START_AT, stepMs = DEFAULT_STEP_MS } = {}) => {
  const initialEpoch = toEpoch(startAt);
  const step = Number.isFinite(stepMs) && stepMs > 0 ? Math.trunc(stepMs) : DEFAULT_STEP_MS;
  let cursor = initialEpoch;

  const nextEpoch = () => {
    const current = cursor;
    cursor += step;
    return current;
  };

  return {
    nextEpoch,
    nextIso: () => new Date(nextEpoch()).toISOString(),
    peekEpoch: () => cursor,
    peekIso: () => new Date(cursor).toISOString(),
    reset: () => {
      cursor = initialEpoch;
    },
    patchDateNow: () => {
      const originalDateNow = Date.now;
      Date.now = () => nextEpoch();
      return () => {
        Date.now = originalDateNow;
      };
    }
  };
};

module.exports = {
  createDeterministicClock
};
