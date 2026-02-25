import test from 'node:test';
import assert from 'node:assert/strict';
import { withDeterministicEnv } from './deterministic-env.mjs';

test('withDeterministicEnv patches Date.now and Math.random deterministically', async () => {
  await withDeterministicEnv(
    {
      startAt: Date.parse('2026-01-01T00:00:00.000Z'),
      stepMs: 50,
      seed: 123
    },
    async () => {
      const t1 = Date.now();
      const t2 = Date.now();
      const r1 = Math.random();
      const r2 = Math.random();

      assert.equal(t2 - t1, 50);
      assert.notEqual(r1, r2);
      assert.ok(r1 >= 0 && r1 <= 1);
      assert.ok(r2 >= 0 && r2 <= 1);
    }
  );
});
