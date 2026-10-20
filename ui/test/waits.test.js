import test from 'node:test';
import assert from 'node:assert/strict';
import { CLAIM, FINALITY, depositWait, duration } from '../lib/waits.js';

const MINUTE = 60e3;
const sent = 1_800_000_000_000;
const at = (status, minutes) => depositWait({ status, created: sent }, sent + minutes * MINUTE);

test('each waiting status names its stage, timed from sending', () => {
  assert.deepEqual(at('mined', 15), { stage: 'finality', elapsed: 15 * MINUTE, late: false });
  assert.deepEqual(at('finalized', 45), { stage: 'claim', elapsed: 45 * MINUTE, late: false });
  assert.deepEqual(at('claiming', 600), { stage: 'confirm', elapsed: 600 * MINUTE, late: false });
  for (const status of ['submitted', 'claimed', 'failed']) assert.equal(at(status, 600), null, status);
  // A clock behind the journey's creation time gives no negative wait.
  assert.equal(at('mined', -5).elapsed, 0);
});

test('a wait is late only past its stage\'s bound, and the bounds follow the usual ranges', () => {
  assert.ok(FINALITY.from < FINALITY.to && FINALITY.to < FINALITY.late);
  assert.ok(CLAIM.from < CLAIM.to && CLAIM.to < CLAIM.late);
  assert.ok(FINALITY.late < CLAIM.late, 'a deposit is not called late for claiming before it could be late for finality');
  assert.equal(at('mined', FINALITY.late / MINUTE).late, false);
  assert.equal(at('mined', FINALITY.late / MINUTE + 1).late, true);
  assert.equal(at('finalized', CLAIM.late / MINUTE).late, false);
  assert.equal(at('finalized', CLAIM.late / MINUTE + 1).late, true);
  // The claim bound counts from sending, so a deposit finalized late is not given a fresh three hours.
  assert.equal(at('finalized', 4 * 60).late, true);
});

test('durations read as words, to the minute', () => {
  assert.equal(duration(30e3), 'under a minute');
  assert.equal(duration(MINUTE), '1 minute');
  assert.equal(duration(8 * MINUTE + 59e3), '8 minutes');
  assert.equal(duration(60 * MINUTE), '1 hour');
  assert.equal(duration(125 * MINUTE), '2 hours 5 minutes');
  assert.equal(duration(24 * 60 * MINUTE), '1 day');
  assert.equal(duration((3 * 24 + 4) * 60 * MINUTE + 7 * MINUTE), '3 days 4 hours');
});
