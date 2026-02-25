const test = require('node:test');
const assert = require('node:assert/strict');
const { createDeterministicClock } = require('./deterministic-clock');
const { createDeterministicRandom } = require('./deterministic-random');
const { stableStringify } = require('./fixture-loader');

test('createDeterministicClock produces stable advancing timestamps', () => {
  const clock = createDeterministicClock({
    startAt: '2026-01-01T00:00:00.000Z',
    stepMs: 10
  });
  assert.equal(clock.nextIso(), '2026-01-01T00:00:00.000Z');
  assert.equal(clock.nextIso(), '2026-01-01T00:00:00.010Z');
  assert.equal(clock.peekIso(), '2026-01-01T00:00:00.020Z');
});

test('createDeterministicRandom yields reproducible sequences for same seed', () => {
  const randomA = createDeterministicRandom({ seed: 42 });
  const randomB = createDeterministicRandom({ seed: 42 });
  const sequenceA = [randomA.next(), randomA.next(), randomA.nextHex(4)];
  const sequenceB = [randomB.next(), randomB.next(), randomB.nextHex(4)];
  assert.deepEqual(sequenceA, sequenceB);
});

test('stableStringify sorts nested object keys deterministically', () => {
  const payload = {
    z: 1,
    a: {
      y: true,
      b: false
    }
  };
  const serialized = stableStringify(payload);
  assert.match(serialized, /\{\n  "a": \{/);
  assert.match(serialized, /"b": false/);
  assert.match(serialized, /"y": true/);
  assert.match(serialized, /"z": 1/);
});
