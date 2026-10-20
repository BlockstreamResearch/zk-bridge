// Records and checks vectors/protocol.json. The formulas here are written from the protocol's byte layouts alone,
// independently of every implementation that the file checks.
//
//   node vectors/record.mjs           fill each null output; refuse, writing nothing, if a recorded one differs
//   node vectors/record.mjs --check   recompute every output; exit 1 on any difference or remaining null

import { createHash } from 'node:crypto';
import { readFileSync, writeFileSync } from 'node:fs';

const FILE = new URL('./protocol.json', import.meta.url);

const sha256 = (...parts) => createHash('sha256').update(Buffer.concat(parts)).digest();

/** The `n` bytes of a 0x-prefixed lowercase hex string. */
function bytes(hex, n) {
  if (typeof hex !== 'string' || !/^0x[0-9a-f]*$/.test(hex) || hex.length !== 2 + 2 * n) {
    throw new Error(`${hex} is not ${n} bytes of hex`);
  }

  return Buffer.from(hex.slice(2), 'hex');
}

/** A non-negative integer as `n` big-endian bytes. */
function be(value, n) {
  if (!Number.isSafeInteger(value) || value < 0) {
    throw new Error(`${value} is not a non-negative integer below 2^53`);
  }

  let v = BigInt(value);
  const out = Buffer.alloc(n);
  for (let i = n - 1; i >= 0; i--, v >>= 8n) out[i] = Number(v & 0xffn);
  if (v !== 0n) {
    throw new Error(`${value} does not fit in ${n} bytes`);
  }

  return out;
}

const hex = (b) => '0x' + b.toString('hex');

const doc = JSON.parse(readFileSync(FILE, 'utf8'));

function tag(name) {
  const t = doc.tags[name];
  if (typeof t !== 'string' || !/^liquid-bridge-poc\/[ -~]+$/.test(t)) {
    throw new Error(`tags.${name} is not a liquid-bridge-poc/ ASCII tag`);
  }

  return Buffer.from(t, 'ascii');
}

function burnScript(c) {
  const script = Buffer.concat([
    Buffer.from([0x6a, 0x46]),
    tag('burn'),
    be(c.chain_id, 8),
    bytes(c.escrow, 20),
    bytes(c.recipient, 20),
  ]);
  if (script.length !== 72) {
    throw new Error('a burn script is 72 bytes');
  }

  return script;
}

// A 32-level sparse tree. Unset slots are zero; set slots are SHA256(tags.claimed).
// Keep indices as BigInt so the top bit of the 32-bit deposit index is not signed by JS bitwise operators.
function claimedRoot(indices) {
  if (!Array.isArray(indices)) {
    throw new Error('claimed indices must be an array');
  }

  const zero = [Buffer.alloc(32)];
  for (let height = 0; height < 32; height++) zero.push(sha256(zero[height], zero[height]));

  const set = sha256(tag('claimed'));
  let level = new Map();
  for (const index of indices) {
    if (!Number.isSafeInteger(index) || index < 0 || index >= 2 ** 32) {
      throw new Error(`claimed index ${index} is outside the tree`);
    }
    if (level.has(BigInt(index))) {
      throw new Error(`claimed index ${index} is repeated`);
    }

    level.set(BigInt(index), set);
  }

  for (let height = 0; height < 32; height++) {
    const parents = new Map();
    for (const index of level.keys()) {
      const parent = index >> 1n;
      if (parents.has(parent)) {
        continue;
      }

      const left = level.get(parent << 1n) ?? zero[height];
      const right = level.get((parent << 1n) + 1n) ?? zero[height];
      parents.set(parent, sha256(left, right));
    }
    level = parents;
  }
  return level.get(0n) ?? zero[32];
}

// [section, output field, its value for a case of the section]
const OUTPUTS = [
  ['tag_sha256', 'sha256', (c) => sha256(tag(c.tag))],
  ['lc', 'lc', (c) => sha256(
    sha256(tag('lc')),
    be(c.slot, 8),
    bytes(c.header, 32),
    bytes(c.committee, 32),
  )],
  ['state_hash', 'claimed_root', (c) => claimedRoot(c.indices)],
  ['state_hash', 'state_hash', (c) => sha256(
    sha256(tag('state')),
    bytes(c.lc, 32),
    bytes(c.acc, 32),
    claimedRoot(c.indices),
  )],
  ['claimed_root', 'root', (c) => claimedRoot(c.indices)],
  ['token_blinding', 'a', (c) => sha256(tag('token_blinding_a'), bytes(c.entropy, 32))],
  ['token_blinding', 'b', (c) => sha256(tag('token_blinding_b'), bytes(c.entropy, 32))],
  ['deposit_domain', 'domain', (c) => sha256(tag('deposit'), be(c.chain_id, 32), bytes(c.escrow, 20))],
  ['burn_script', 'script', burnScript],
];

const check = process.argv.includes('--check');
const problems = [];
let filled = 0;

for (const [section, field, value] of OUTPUTS) {
  if (!Array.isArray(doc[section]) || doc[section].length === 0) {
    problems.push(`${section}: no cases`);
    continue;
  }
  doc[section].forEach((c, i) => {
    const where = `${section}[${i}].${field}`;
    const got = hex(value(c));
    if (c[field] === null && !check) {
      c[field] = got;
      filled++;
    } else if (c[field] === null) {
      problems.push(`${where} is not recorded`);
    } else if (c[field] !== got) {
      problems.push(`${where}: the file has ${c[field]}, the formula gives ${got}`);
    }
  });
}

if (problems.length) {
  console.error(problems.join('\n'));
  console.error(check ? 'vectors/protocol.json does not check' : 'nothing written: a recorded output is never overwritten');
  process.exit(1);
}
if (filled) writeFileSync(FILE, JSON.stringify(doc, null, 2) + '\n');
console.log(check ? 'vectors/protocol.json: every output recomputes' : `vectors/protocol.json: ${filled} output(s) recorded`);
