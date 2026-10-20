// How long a deposit's waits usually last on this instance, and when the page calls one unusual. These are
// expectations, not promises: nobody runs a prover service for this instance. Every wait is measured from when the
// deposit was sent, so a page closed for a day does not restart a clock when it is opened again.

const MINUTE = 60 * 1000;
const HOUR = 60 * MINUTE;

/**
 * Sepolia finalizes a block about two epochs (2 × 32 slots of 12 s) after it is included, so its `finalized` block
 * passes a deposit 13 to 20 minutes after it is sent while the chain finalizes normally. An hour means finality, or
 * the wallet's view of it, is stalled.
 */
export const FINALITY = { from: 13 * MINUTE, to: 20 * MINUTE, late: HOUR };

/**
 * After finality someone builds an SP1 proof, updates the Liquid state with it and claims the deposit. With the
 * operator at work that takes about half an hour from sending: the Groth16 proof takes about 7 minutes on the
 * operator's host, and the update and the claim each wait for a Liquid block (about a minute). On a slower host
 * the proof alone has taken over an hour. The operator is a person, not a service, so three hours after sending the
 * page says the wait is unusual and lists the ways forward.
 */
export const CLAIM = { from: 30 * MINUTE, to: 2 * HOUR, late: 3 * HOUR };

/** A claim seen on Liquid confirms in the next block, about a minute later. */
export const CONFIRM = { to: 2 * MINUTE };

const STAGES = { mined: 'finality', finalized: 'claim', claiming: 'confirm' };

/**
 * The wait a deposit journey is in at `now` (ms): `stage` is 'finality', 'claim' or 'confirm', `elapsed` the time
 * since it was sent and `late` whether that is past the stage's usual range. Null for a journey that is not
 * waiting on a chain: just sent, claimed or failed.
 */
export function depositWait(j, now) {
  const stage = STAGES[j.status];
  if (!stage) return null;
  const elapsed = Math.max(0, now - j.created);
  const late = stage === 'finality' ? elapsed > FINALITY.late : stage === 'claim' ? elapsed > CLAIM.late : false;
  return { stage, elapsed, late };
}

/** A duration in words, to the minute: "under a minute", "8 minutes", "2 hours 5 minutes", "3 days 4 hours". */
export function duration(ms) {
  const m = Math.floor(ms / MINUTE);
  if (m < 1) return 'under a minute';
  const unit = (n, word) => `${n} ${word}${n === 1 ? '' : 's'}`;
  const d = Math.floor(m / (24 * 60));
  const h = Math.floor(m / 60) % 24;
  const min = m % 60;
  if (d > 0) return h > 0 ? `${unit(d, 'day')} ${unit(h, 'hour')}` : unit(d, 'day');
  if (h > 0) return min > 0 ? `${unit(h, 'hour')} ${unit(min, 'minute')}` : unit(h, 'hour');
  return unit(min, 'minute');
}
