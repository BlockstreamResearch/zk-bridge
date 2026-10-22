import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { existsSync, readFileSync } from 'node:fs';
import { bytesToHex, concat, hexToBytes, utf8 } from '../lib/bytes.js';
import { encodeSegwit } from '../lib/bech32.js';
import { keccak256, selector } from '../lib/hash.js';
import { displayHex, parseHeader, parseTransaction } from '../lib/elements.js';
import {
  batchRef, beaconBlockRoot, beaconRootCall, BURN_TAG, burnDiagnosis, burnOutputs, burnProof, burnRecipient, burnTarget, CHECK_FORK_SIGNATURE, checkForkCalldata, DEPOSIT_TOPIC,
  depositAdmission, depositCalldata, depositEvent, depositRecipient, depositUnits, escrowBurnTarget, ethAddress, explainRevert, forkSlotTime, formatUnits,
  isStandardRecipient, isXOnlyKey, liftY, parseEther, parseForkProof, readBurnScript,
  redeemCalldata, REDEEM_SIGNATURE, REDEEM_TO_SIGNATURE, REDEEMED_TOPIC, redeemToCalldata, relayBatch, SUBMIT_SIGNATURE, submitHeadersCalldata,
} from '../lib/bridge.js';

const sha = (b) => new Uint8Array(createHash('sha256').update(b).digest());
const sha2 = (b) => sha(sha(b));
const G_X = '79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798';
const G_Y = 0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8n;

test('amounts follow BridgeDeposits', () => {
  assert.equal(parseEther('0.001'), 10n ** 15n);
  assert.equal(depositUnits(parseEther('0.001')), 100_000n);
  assert.throws(() => depositUnits(parseEther('0.0009')), /minimum/);
  assert.throws(() => depositUnits(parseEther('0.000000000000000001') + 10n ** 15n), /steps/);
  assert.throws(() => parseEther('1e-3'), /amount/);
  assert.equal(formatUnits(100_000n, 8), '0.001');
  assert.equal(formatUnits(123_456_789n, 8), '1.23456789');
});

test('deposit recipient: the scriptPubKey of an ordinary address, as BridgeDeposits.recipientOf accepts it', () => {
  // Segwit v0 key hash, v0 script hash and Taproot addresses, built here and read back.
  const wpkh = concat([0x00, 0x14], new Uint8Array(20).fill(0x11));
  const wsh = concat([0x00, 0x20], new Uint8Array(32).fill(0x22));
  const tr = concat([0x51, 0x20], hexToBytes(G_X));
  for (const [script, version] of [[wpkh, 0], [wsh, 0], [tr, 1]]) {
    const address = encodeSegwit('tex', version, script.subarray(2));
    const r = depositRecipient(address);
    assert.equal(bytesToHex(r.script), bytesToHex(script));
    assert.equal(r.address, address);
    assert.equal(bytesToHex(depositRecipient(bytesToHex(script)).script), bytesToHex(script), 'the same script in hex');
  }
  // Base58 forms are accepted as raw scripts, without an address to track.
  const p2sh = concat([0xa9, 0x14], new Uint8Array(20).fill(0x33), [0x87]);
  const p2pkh = concat([0x76, 0xa9, 0x14], new Uint8Array(20).fill(0x44), [0x88, 0xac]);
  for (const s of [p2sh, p2pkh]) {
    assert.ok(isStandardRecipient(s));
    assert.equal(depositRecipient('0x' + bytesToHex(s)).address, null);
  }
  // Find an x with no curve point, cross-checked by the square-root route of liftY.
  let x = 1n;
  while (isXOnlyKey(hexToBytes(x.toString(16).padStart(64, '0')))) x++;
  assert.throws(() => liftY(hexToBytes('02' + x.toString(16).padStart(64, '0'))), /not on secp256k1/);
  assert.throws(() => depositRecipient(encodeSegwit('tex', 1, hexToBytes(x.toString(16).padStart(64, '0')))), /not a valid Taproot key/);
  assert.throws(() => depositRecipient(G_X), /bare Taproot key/);
  assert.throws(() => depositRecipient('tlq1qqexample'), /confidential/);
  assert.throws(() => depositRecipient('6a20' + '00'.repeat(32)), /standard wallet script/); // OP_RETURN
  assert.throws(() => depositRecipient(encodeSegwit('tex', 2, new Uint8Array(32))), /standard wallet script/); // future version
  assert.throws(() => depositRecipient(encodeSegwit('ex', 0, new Uint8Array(20))), /prefix/); // Liquid mainnet
  // deposit(bytes): selector, offset 0x20, length, the script padded to a word.
  const w = (hex) => hex.padStart(64, '0');
  assert.equal(depositCalldata(wpkh), selector('deposit(bytes)') + w('20') + w('16') + bytesToHex(wpkh).padEnd(64, '0'));
});

test('the Deposit event decodes from a receipt', () => {
  const escrow = '0x' + '12'.repeat(20);
  const w = (hex) => hex.padStart(64, '0');
  const script = '0014' + '11'.repeat(20);
  const data = '0x' + w('186a0') + 'aa'.repeat(32) + 'bb'.repeat(32) + 'cc'.repeat(32) + w('a0') + w('16') + script.padEnd(64, '0');
  const receipt = { logs: [{ address: escrow, topics: [DEPOSIT_TOPIC, '0x' + w('7')], data }] };
  const ev = depositEvent(receipt, escrow);
  assert.equal(ev.index, 7n);
  assert.equal(ev.units, 100_000n);
  assert.equal(ev.recipient, 'aa'.repeat(32));
  assert.equal(ev.accumulator, 'cc'.repeat(32));
  assert.equal(ev.script, script);
  assert.equal(DEPOSIT_TOPIC, '0x' + bytesToHex(keccak256('Deposit(uint64,uint64,bytes32,bytes32,bytes32,bytes)')));
  assert.equal(REDEEMED_TOPIC, '0x' + bytesToHex(keccak256('Redeemed(bytes32,uint32,address,address,uint64)')));
});

test('a burn recipient is checksummed or the connected account', () => {
  const checksummed = '0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed';
  assert.equal(burnRecipient(checksummed, null), checksummed.toLowerCase());
  assert.throws(() => burnRecipient(checksummed.toLowerCase(), null), /checksummed/);
  assert.equal(burnRecipient(checksummed.toLowerCase(), checksummed.toLowerCase()), checksummed.toLowerCase(), 'the connected account');
  assert.throws(() => burnRecipient(checksummed.toUpperCase().replace('0X', '0x'), '0x' + '11'.repeat(20)), /checksummed/);
});

test('liftY recovers the generator and the parity', () => {
  assert.equal(liftY(hexToBytes('02' + G_X)), G_Y);
  assert.equal(liftY(hexToBytes('03' + G_X)), 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2fn - G_Y);
});

test('EIP-55 addresses', () => {
  assert.equal(ethAddress('0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed'), '0x5aaeb6053f3e94c9b9a09f33669435e7ef1beaed');
  assert.throws(() => ethAddress('0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAeD'), /checksum/);
  assert.throws(() => ethAddress('0x0000000000000000000000000000000000000000'), /zero/);
});

test('burn target is BridgeEscrow.burnScriptPubKey: a bare OP_RETURN naming the chain, escrow and recipient', () => {
  const escrow = '0x' + '12'.repeat(20);
  const recipient = '0x' + 'ab'.repeat(20);
  // abi.encodePacked(hex"6a46", bytes22("liquid-bridge-poc/burn"), uint64(chainid), escrow, recipient), byte by byte.
  const expected = '6a46' + '6c69717569642d6272696467652d706f632f6275726e' + '0000000000aa36a7' + '12'.repeat(20) + 'ab'.repeat(20);
  const t = burnTarget(11155111n, escrow, recipient);
  assert.deepEqual([t.chainId, t.escrow, t.recipient], [11155111n, escrow, recipient]);
  assert.equal(bytesToHex(t.scriptPubKey), expected);
  assert.equal(t.scriptPubKey.length, 72, 'one direct push of 70 bytes; under Bitcoin Core 23\'s default 83-byte -datacarriersize (relay policy)');
  assert.equal(bytesToHex(utf8(BURN_TAG)), '6c69717569642d6272696467652d706f632f6275726e');
  assert.deepEqual(readBurnScript(t.scriptPubKey), { chainId: 11155111n, escrow, recipient });
  assert.deepEqual(readBurnScript(burnTarget(1n, escrow, recipient).scriptPubKey).chainId, 1n, 'chain-bound');
  // Not a burn script: destroyamount's bare OP_RETURN, the same payload pushed with OP_PUSHDATA1, a trailing byte.
  for (const s of ['6a', '6a4c46' + expected.slice(4), expected + '00', '6a45' + expected.slice(4, -2)]) assert.equal(readBurnScript(hexToBytes(s)), null, s);
  assert.throws(() => burnTarget(11155111n, '0x' + '12'.repeat(19), recipient), /20 bytes/);
});

test('the page builds the burn target itself and only checks it against the escrow\'s answer', () => {
  const escrow = '0x' + '12'.repeat(20);
  const recipient = '0x' + 'ab'.repeat(20);
  const chainId = 11155111n;
  const bare = burnTarget(chainId, escrow, recipient);
  assert.deepEqual(escrowBurnTarget(chainId, escrow, recipient, bare.scriptPubKey), bare);
  // Any other answer is refused, though the page could build some of them: an RPC that answered so would otherwise
  // have a burn made that the escrow refuses. So is an answer for another recipient, escrow or chain, destroyamount's
  // bare OP_RETURN, an address's script, or the right payload pushed another way.
  for (const answer of [
    burnTarget(chainId, escrow, '0x' + 'cd'.repeat(20)).scriptPubKey,
    burnTarget(chainId, '0x' + '34'.repeat(20), recipient).scriptPubKey,
    burnTarget(1n, escrow, recipient).scriptPubKey,
    Uint8Array.of(0x6a),
    concat([0x00, 0x20], new Uint8Array(32).fill(0x22)),
    concat([0x6a, 0x4c, 0x46], bare.scriptPubKey.subarray(2)),
    new Uint8Array(0),
  ]) {
    assert.throws(() => escrowBurnTarget(chainId, escrow, recipient, answer), /disagree on the burn script/, bytesToHex(answer));
  }
});

test('a lookup says why outputs do not redeem: blinded, OP_RETURN, another chain, escrow or recipient, another script', () => {
  const asset = new Uint8Array(32).fill(0xa5); // a made-up bridge asset
  const lbtc = new Uint8Array(32).fill(0x49);
  const escrow = '0x' + '12'.repeat(20);
  const recipient = '0x' + 'ab'.repeat(20);
  const t = burnTarget(11155111n, escrow, recipient);
  const u64 = (v) => hexToBytes(v.toString(16).padStart(16, '0'));
  const explicit = (a, v, spk) => concat([0x01], a, [0x01], u64(v), [0x00, spk.length], spk);
  const blinded = (spk) => concat([0x0a], new Uint8Array(32).fill(1), [0x08], new Uint8Array(32).fill(2), [0x02], new Uint8Array(32).fill(3), [spk.length], spk);
  const txOf = (...outs) => parseTransaction(concat(hexToBytes('0200000000' + '01' + 'cc'.repeat(32) + '00000000' + '00' + 'ffffffff'), [outs.length], ...outs, le32(0)));
  const tx = txOf(
    blinded(t.scriptPubKey), // 0: the burn, confidential
    explicit(asset, 100_000n, burnTarget(1n, escrow, recipient).scriptPubKey), // 1: another chain
    explicit(asset, 200_000n, Uint8Array.of(0x6a)), // 2: a wallet's Burn (Elements destroyamount)
    explicit(asset, 300_000n, burnTarget(11155111n, '0x' + '34'.repeat(20), recipient).scriptPubKey), // 3: another escrow
    explicit(asset, 400_000n, burnTarget(11155111n, escrow, '0x' + 'cd'.repeat(20)).scriptPubKey), // 4: another recipient
    explicit(lbtc, 300n, new Uint8Array(0)), // the fee: not reported
    blinded(concat([0x00, 0x14], new Uint8Array(20).fill(0x11))), // counted, not read
    explicit(lbtc, 1n, t.scriptPubKey), // 7: another asset
    explicit(asset, 0n, t.scriptPubKey), // 8: nothing
    explicit(asset, 500_000n, concat([0x00, 0x20], new Uint8Array(32).fill(0x22))), // 9: an ordinary script hash address
    explicit(asset, 600_000n, concat([0x6a, 0x01, 0x00])), // 10: some other OP_RETURN
  );
  assert.ok(!burnOutputs(tx, asset, t.scriptPubKey).some((o) => o.usable));
  const { outputs, blinded: unread } = burnDiagnosis(tx, asset, t);
  assert.equal(unread, 1);
  assert.deepEqual(outputs.map((o) => [o.vout, o.units]), [[0, null], [1, 100_000n], [2, 200_000n], [3, 300_000n], [4, 400_000n], [7, null], [8, 0n], [9, 500_000n], [10, 600_000n]]);
  const text = Object.fromEntries(outputs.map((o) => [o.vout, o.text]));
  assert.match(text[0], /recipient's burn, but confidential \(blinded\)/);
  assert.equal(text[1], 'is a burn for chain id 1, which this escrow cannot redeem');
  assert.match(text[2], /OP_RETURN that names no recipient.*Burn or Destroy/);
  assert.equal(text[3], `is a burn for escrow 0x${'34'.repeat(20)}, which this escrow cannot redeem`);
  assert.match(text[4], new RegExp(`is a burn naming recipient 0x${'cd'.repeat(20)}: set step 1's recipient`));
  assert.match(text[7], /burns another asset/);
  assert.match(text[8], /burns nothing/);
  assert.equal(text[9], 'pays another script, such as change or an ordinary address: it is not a burn');
  assert.match(text[10], /OP_RETURN that names no recipient/);

  // The burn, explicit and of the asset, is redeemable and not reported; its change is reported only as another
  // script, which the page shows only when nothing is redeemable.
  const wpkh = concat([0x00, 0x14], new Uint8Array(20).fill(0x11));
  const good = txOf(explicit(asset, 100_000n, t.scriptPubKey), explicit(asset, 5n, wpkh));
  assert.deepEqual(burnOutputs(good, asset, t.scriptPubKey), [{ vout: 0, units: 100_000n, usable: true }]);
  assert.deepEqual(burnDiagnosis(good, asset, t).outputs.map((o) => o.vout), [1]);
  assert.match(burnDiagnosis(good, asset, t).outputs[0].text, /pays another script, such as change/);
});

test('redeem calldata follows the ABI head/tail layout', () => {
  const w = (hex) => hex.padStart(64, '0');
  const data = redeemCalldata({
    recipient: '0x' + '11'.repeat(20),
    burn: { transaction: hexToBytes('aabb'), vout: 1, branch: [hexToBytes('22'.repeat(32))], position: 3 },
    ref: { batch: 2, index: 1, path: [hexToBytes('55'.repeat(32))] },
  });
  const expected = [
    w('11'.repeat(20)), w('60'), w('160'), // recipient; offsets of burn (96) and ref (96 + 256)
    w('80'), w('1'), w('c0'), w('3'), // burn: offset of the transaction (128), vout, offset of branch (192), position
    w('2'), 'aabb'.padEnd(64, '0'), // transaction
    w('1'), '22'.repeat(32), // branch
    w('2'), w('1'), w('60'), // ref: batch, index, offset of path (96)
    w('1'), '55'.repeat(32), // path
  ].join('');
  assert.equal(data, selector(REDEEM_SIGNATURE) + expected);
  assert.equal(selector(REDEEM_SIGNATURE), selector('redeem(address,(bytes,uint32,bytes32[],uint32),(uint256,uint256,bytes32[]))'));
  // redeemTo has the same layout, with the payee in the first word.
  const redirect = redeemToCalldata({
    to: '0x' + '11'.repeat(20),
    burn: { transaction: hexToBytes('aabb'), vout: 1, branch: [hexToBytes('22'.repeat(32))], position: 3 },
    ref: { batch: 2, index: 1, path: [hexToBytes('55'.repeat(32))] },
  });
  assert.equal(redirect, selector(REDEEM_TO_SIGNATURE) + expected);
  assert.equal(selector(REDEEM_TO_SIGNATURE), selector('redeemTo(address,(bytes,uint32,bytes32[],uint32),(uint256,uint256,bytes32[]))'));

  const relay = submitHeadersCalldata({ headers: [hexToBytes('cc')], sigs: [{ r: hexToBytes('33'.repeat(32)), s: hexToBytes('44'.repeat(32)) }], witnessScript: new Uint8Array(0), keyY: [] });
  assert.equal(relay, selector(SUBMIT_SIGNATURE) + [
    w('80'), w('100'), w('160'), w('180'), // offsets: headers (128), sigs (256), witnessScript (352), keyY (384)
    w('1'), w('20'), w('1'), 'cc'.padEnd(64, '0'), // headers
    w('1'), '33'.repeat(32), '44'.repeat(32), // sigs
    w('0'), // empty witnessScript
    w('0'), // empty keyY
  ].join(''));
});

test('revert reasons are explained', () => {
  assert.match(explainRevert(selector('AlreadyRedeemed()')), /already been redeemed/);
  // Not only a key change: a forged header carrying its own signers reverts the same way.
  assert.match(explainRevert(selector('WrongSignblockscript()')), /signers the light client does not expect/);
  assert.match(explainRevert(selector('AmbiguousTally()')), /stopped/);
  assert.match(explainRevert(selector('DepositsClosed()')), /deposit window has ended.*only the last is fixed by relaying/);
  assert.match(explainRevert(selector('BadBeaconProof()')), /beacon block root/);
  assert.match(explainRevert(selector('Insolvent()')), /Nothing was recorded/);
  assert.match(explainRevert(selector('PayoutFailed()')), /burn is still unspent/);
  assert.match(explainRevert(selector('BadRecipientScript()')), /standard wallet script/);
  // A plain Error(string), from anything else on the call path, is shown as its reason.
  const errorString = '0x08c379a0' + '20'.padStart(64, '0') + '6'.padStart(64, '0') + bytesToHex(utf8('amount')).padEnd(64, '0');
  assert.equal(explainRevert(errorString), 'Reverted: amount');
  assert.equal(explainRevert('0x'), 'The transaction reverted without a reason.');
  assert.equal(explainRevert(undefined), 'The transaction reverted without a reason.');
  assert.equal(explainRevert('0xdeadbeef'), 'Reverted with unknown error 0xdeadbeef.');
});

test('deposit admission: the escrow decides, and its reads say why', () => {
  const now = 1_800_000_000;
  const admission = { depositsEnd: now + 86_400, forkCheckedAt: now - 60, maxForkCheckAge: 3600 };
  const b = { depositsOpen: true, lcTime: now - 60, maxRelayLag: 86_400, admission };
  const open = depositAdmission(b, now);
  assert.equal(open.deposit, true);
  assert.match(open.text, /until 2027-01-16 \d\d:\d\d UTC/);

  const closed = { ...b, depositsOpen: false };
  const why = (patch, at = now) => depositAdmission({ ...closed, ...patch, admission: { ...admission, ...patch.admission } }, at);
  // Only a lagging light client is reopened by relaying; the page offers the relay for that case alone.
  assert.deepEqual([why({ admission: { depositsEnd: now } }).relayReopens, why({ admission: { depositsEnd: now } }).text.includes('ended for good')], [false, true]);
  assert.match(why({ admission: { forkCheckedAt: 0 } }).text, /paused.*fresh fork proof/);
  assert.match(why({ admission: { forkCheckedAt: now - 3601 } }).text, /paused/);
  // Only a stale fork check is reopened by a fork proof; the page offers the proof form for that case alone.
  assert.deepEqual([why({ admission: { forkCheckedAt: 0 } }).forkReopens, why({ admission: { forkCheckedAt: 0 } }).relayReopens], [true, false]);
  assert.equal(why({ admission: { depositsEnd: now, forkCheckedAt: 0 } }).forkReopens, false);
  assert.equal(open.forkReopens, false);
  const lagging = why({ lcTime: now - 86_401 });
  assert.deepEqual([lagging.deposit, lagging.relayReopens, lagging.forkReopens], [false, true, false]);
  assert.match(lagging.text, /24 hours behind/);
  // The window is checked before the fork check, and the fork check before the relay lag.
  assert.match(why({ lcTime: 0, admission: { depositsEnd: now, forkCheckedAt: 0 } }).text, /ended for good/);
  assert.match(why({ lcTime: 0, admission: { forkCheckedAt: 0 } }).text, /paused/);
  // The escrow saying closed stands even when its reads look current, as with a clock behind the chain's.
  assert.equal(why({}).deposit, false);
});

// A synthetic Sepolia beacon chain for checkFork, built as contracts/solidity/test/SepoliaBeacon.sol builds it: whole trees, with
// node:crypto's SHA-256 and DataView's little-endian words, independent of the page's own merkleization.
const GENESIS = 1_655_733_600;
const GVR = hexToBytes('d8ea171f3c94aea21ebc42a1ed61052acf3f9209c00e4efbaaddac09ed9b8078');
const FULU = hexToBytes('90000075');
const GLOAS = hexToBytes('90000076');

function le64Chunk(n) {
  const b = new Uint8Array(32);
  new DataView(b.buffer).setBigUint64(0, BigInt(n), true);
  return b;
}

function chunkOf(b) {
  const c = new Uint8Array(32);
  c.set(b);
  return c;
}

/** The root of a power-of-two list of chunks, and the branch of chunk `index`, leaf level first. */
function merkle(level, index) {
  const branch = [];
  while (level.length > 1) {
    branch.push(level[index ^ 1]);
    const up = [];
    for (let i = 0; i < level.length; i += 2) up.push(sha(concat(level[i], level[i + 1])));
    level = up;
    index >>= 1;
  }
  return { root: level[0], branch };
}

/** EIP-7916's progressive tree of `chunks`, in levels of width, 4 * width, ... chunks: each level's binary subtree on
 * the left and the rest on the right, a zero chunk once none are left. */
function progressive(chunks, width = 1) {
  if (chunks.length === 0) return new Uint8Array(32);
  const level = Array.from({ length: width }, (_, i) => chunks[i] ?? new Uint8Array(32));
  return sha(concat(merkle(level, 0).root, progressive(chunks.slice(width), 4 * width)));
}

/** Active-fields bits of the fields `first` to `last`, as their chunk: field i at bit i % 8 of byte i / 8. */
function activeBits(first, last) {
  const b = new Uint8Array(32);
  for (let i = first; i <= last; i++) b[i >> 3] |= 1 << (i & 7);
  return b;
}

/** A BeaconBlockHeader's root: five fields in an 8-leaf tree. */
function headerRoot(h) {
  const z = new Uint8Array(32);
  return merkle([le64Chunk(h.slot), le64Chunk(h.proposer), h.parent, h.state, h.body, z, z, z], 0).root;
}

/** A 46-field progressive beacon state (Gloas's count on Sepolia) at `slot` under fork (FULU, current, epoch), in a
 * block whose root is returned. */
function syntheticForkProof(slot, current, epoch) {
  const z = new Uint8Array(32);
  const fields = Array.from({ length: 46 }, (_, i) => sha(utf8(`state field ${i} ${slot}`)));
  fields[0] = le64Chunk(GENESIS);
  fields[1] = GVR;
  fields[2] = le64Chunk(slot);
  fields[3] = merkle([chunkOf(FULU), chunkOf(current), le64Chunk(epoch), z], 0).root;
  const bits = activeBits(0, 45);
  const stateRoot = sha(concat(progressive(fields), bits));
  const block = merkle([le64Chunk(slot), le64Chunk(7), sha(utf8('parent')), stateRoot, sha(utf8('body')), z, z, z], 3);
  const proof = {
    timestamp: GENESIS + 12 * (slot + 1), genesisTime: GENESIS, genesisValidatorsRoot: GVR, slot, previousVersion: FULU, currentVersion: current,
    epoch, stateBranch: [fields[4], progressive(fields.slice(5), 16)], activeFields: bits, blockBranch: block.branch,
  };
  return { proof, root: block.root };
}

const forkProofJson = (p) => ({
  ...p, genesisValidatorsRoot: '0x' + bytesToHex(p.genesisValidatorsRoot), previousVersion: '0x' + bytesToHex(p.previousVersion),
  currentVersion: '0x' + bytesToHex(p.currentVersion), stateBranch: p.stateBranch.map((b) => '0x' + bytesToHex(b)),
  activeFields: '0x' + bytesToHex(p.activeFields), blockBranch: p.blockBranch.map((b) => '0x' + bytesToHex(b)),
});

test('fork proof: checkFork\'s root and calldata, and the JSON fork_proof.py prints', () => {
  const slot = 11_400_000;
  const { proof, root } = syntheticForkProof(slot, GLOAS, 353_024);
  assert.equal(bytesToHex(beaconBlockRoot(proof)), bytesToHex(root));
  assert.equal(forkSlotTime(proof), GENESIS + 12 * slot);
  // Every proven value is bound; the timestamp is not, since it only selects the EIP-4788 root.
  for (const [k, v] of [['slot', slot + 1], ['epoch', 353_025], ['genesisTime', GENESIS + 1], ['currentVersion', FULU], ['previousVersion', GLOAS],
    ['activeFields', activeBits(0, 46)], ['stateBranch', [proof.stateBranch[0], GVR]]]) {
    assert.notEqual(bytesToHex(beaconBlockRoot({ ...proof, [k]: v })), bytesToHex(root), k);
  }

  // The tool's whole output, or its proof alone; types are checked field by field.
  assert.deepEqual(parseForkProof(JSON.stringify({ ok: true, proof: forkProofJson(proof), blockRoot: '0x00' })), proof);
  assert.deepEqual(parseForkProof(JSON.stringify(forkProofJson(proof))), proof);
  assert.throws(() => parseForkProof('not json'), /JSON/);
  assert.throws(() => parseForkProof(JSON.stringify({ ...forkProofJson(proof), stateBranch: forkProofJson(proof).stateBranch.slice(1) })), /stateBranch/);
  assert.throws(() => parseForkProof(JSON.stringify({ ...forkProofJson(proof), currentVersion: '0x900000' })), /currentVersion/);
  assert.throws(() => parseForkProof(JSON.stringify({ ...forkProofJson(proof), slot: -1 })), /slot/);
  assert.throws(() => parseForkProof(JSON.stringify({ ...forkProofJson(proof), timestamp: '1' })), /timestamp/);
  assert.throws(() => parseForkProof(JSON.stringify({ ...forkProofJson(proof), activeFields: undefined })), /activeFields/);
  // checkFork refuses a state whose field 0 to 3 is inactive, and so does the page.
  const retired = forkProofJson({ ...proof, activeFields: activeBits(1, 45) });
  assert.throws(() => parseForkProof(JSON.stringify(retired)), /fields 0 to 3 inactive/);

  // A static tuple: thirteen words in place after the selector.
  assert.equal(CHECK_FORK_SIGNATURE, 'checkFork((uint64,uint64,bytes32,uint64,bytes4,bytes4,uint64,bytes32[2],bytes32,bytes32[3]))');
  const data = hexToBytes(checkForkCalldata(proof));
  const word = (i) => bytesToHex(data.subarray(4 + 32 * i, 36 + 32 * i));
  assert.equal(data.length, 4 + 13 * 32);
  assert.equal('0x' + bytesToHex(data.subarray(0, 4)), selector(CHECK_FORK_SIGNATURE));
  assert.equal(BigInt('0x' + word(0)), BigInt(proof.timestamp));
  assert.equal(word(2), bytesToHex(GVR));
  assert.equal(word(4), '90000075' + '00'.repeat(28));
  assert.equal(word(5), '90000076' + '00'.repeat(28));
  assert.deepEqual([7, 8, 9, 10, 11, 12].map(word), [...proof.stateBranch, proof.activeFields, ...proof.blockBranch].map(bytesToHex));
  assert.equal(beaconRootCall(proof.timestamp), '0x' + proof.timestamp.toString(16).padStart(64, '0'));
});

// A public Sepolia (Gloas) finality update, as served: its branch gives nodes 11 and 3 of the attested state, and its
// header node 43, so the page's root must be that real header's (contracts/solidity/test/BridgeEscrowForkProof.t.sol does the same).
test('fork proof: a real Sepolia state gives its real block root', () => {
  const doc = JSON.parse(readFileSync(new URL('../../contracts/solidity/test/fixtures/sepolia-finality-update-11381920.json', import.meta.url), 'utf8'));
  const header = (j) => ({ slot: Number(j.slot), proposer: Number(j.proposer_index), parent: hexToBytes(j.parent_root.slice(2)),
    state: hexToBytes(j.state_root.slice(2)), body: hexToBytes(j.body_root.slice(2)) });
  const attested = header(doc.data.attested_header.beacon);
  const branch = doc.data.finality_branch.map((b) => hexToBytes(b.slice(2)));
  let at = headerRoot(header(doc.data.finalized_header.beacon));
  let g = 735; // finalized_checkpoint.root
  let node11;
  for (const sibling of branch) {
    at = g & 1 ? sha(concat(sibling, at)) : sha(concat(at, sibling));
    g >>= 1;
    if (g === 11) node11 = at;
  }
  assert.equal(bytesToHex(at), bytesToHex(attested.state));
  assert.equal(bytesToHex(branch[8]), bytesToHex(activeBits(0, 45)));
  const z = new Uint8Array(32);
  const proof = {
    timestamp: GENESIS + 12 * (attested.slot + 1), genesisTime: GENESIS, genesisValidatorsRoot: GVR, slot: attested.slot,
    previousVersion: FULU, currentVersion: GLOAS, epoch: 353_024, stateBranch: [headerRoot({ ...attested, state: z }), node11],
    activeFields: branch[8], blockBranch: [attested.parent, sha(concat(le64Chunk(attested.slot), le64Chunk(attested.proposer))),
      sha(concat(sha(concat(attested.body, z)), sha(concat(z, z))))],
  };
  assert.equal(bytesToHex(beaconBlockRoot(parseForkProof(JSON.stringify(forkProofJson(proof))))), bytesToHex(headerRoot(attested)));
});

// Recorded from a real Sepolia state by tools/liquid-relay/fork_proof.py.
const FORK_FIXTURE = new URL('../../contracts/solidity/test/fixtures/sepolia-fork-proof.json', import.meta.url);
test('a real fork proof gives the root and calldata fork_proof.py recorded', { skip: !existsSync(FORK_FIXTURE) && 'no contracts/solidity/test/fixtures/sepolia-fork-proof.json yet' }, () => {
  const out = JSON.parse(readFileSync(FORK_FIXTURE, 'utf8'));
  const p = parseForkProof(JSON.stringify(out));
  assert.equal('0x' + bytesToHex(beaconBlockRoot(p)), out.blockRoot);
  assert.equal(checkForkCalldata(p), out.calldata);
});

function le32(x) {
  return Uint8Array.of(x & 0xff, (x >>> 8) & 0xff, (x >>> 16) & 0xff, x >>> 24);
}

test('burn proof, batch reference and relay batch from synthetic signed headers', () => {
  const escrow = '0x' + '12'.repeat(20);
  const recipient = '0x' + 'ab'.repeat(20);
  const asset = new Uint8Array(32).fill(0xa5); // a made-up bridge asset
  const { scriptPubKey } = burnTarget(11155111n, escrow, recipient);
  const u64 = (v) => hexToBytes(v.toString(16).padStart(16, '0'));
  const tx = concat(
    hexToBytes('0200000000' + '01' + 'cc'.repeat(32) + '00000000' + '00' + 'ffffffff' + '02'),
    [0x01], asset, [0x01], u64(250_000n), [0x00, scriptPubKey.length], scriptPubKey,
    [0x01], new Uint8Array(32).fill(0x49), [0x01], u64(300n), [0x00, 0x00],
    le32(0),
  );
  const parsed = parseTransaction(tx);
  assert.deepEqual(burnOutputs(parsed, asset, scriptPubKey), [{ vout: 0, units: 250_000n, usable: true }]);

  const key = hexToBytes('02' + G_X);
  const wscript = concat([0x51, 0x21], key, [0x51, 0xae]);
  const spk = concat([0x00, 0x20], sha(wscript));
  const sig = hexToBytes('30440220' + '11'.repeat(32) + '0220' + '2b'.repeat(32) + '01'); // made-up DER, SIGHASH_ALL
  const other = sha(Uint8Array.of(7));
  const root = sha2(concat(other, parsed.txid));
  const header = (prev, merkle, height) => concat(le32(0xa0000000), prev, merkle, le32(1_760_000_000), le32(height), [0x01, 34], spk, le32(150), new Uint8Array(32), [0x00],
    [0x03, 0x00, sig.length], sig, [wscript.length], wscript);
  const h0 = header(new Uint8Array(32).fill(9), root, 5000);
  const h1 = header(parseHeader(h0).hash, new Uint8Array(32).fill(1), 5001);

  // Burn proof: the transaction's position and branch in its block.
  const p = burnProof({ txidDisplay: displayHex(parsed.txid), txHex: bytesToHex(tx), vout: 0, txidsDisplay: [displayHex(other), displayHex(parsed.txid)], blockHeaderHex: bytesToHex(h0) });
  assert.equal(p.burn.position, 1);
  assert.deepEqual(p.burn.branch.map(bytesToHex), [bytesToHex(other)]);
  assert.equal(bytesToHex(p.burn.transaction), bytesToHex(tx));
  assert.equal(p.height, 5000);
  assert.throws(() => burnProof({ txidDisplay: displayHex(parsed.txid), txHex: bytesToHex(tx), vout: 0, txidsDisplay: [displayHex(parsed.txid), displayHex(other)], blockHeaderHex: bytesToHex(h0) }), /Merkle root/);
  assert.throws(() => burnProof({ txidDisplay: '00'.repeat(32), txHex: bytesToHex(tx), vout: 0, txidsDisplay: [], blockHeaderHex: bytesToHex(h0) }), /do not match the txid/);

  // Batch reference: LiquidLightClient's keccak tree over three Merkle roots, padded to four leaves.
  const roots = [root, new Uint8Array(32).fill(1), new Uint8Array(32).fill(2)];
  const leaves = [...roots.map((r) => keccak256(r)), new Uint8Array(32)];
  const left = keccak256(concat(leaves[0], leaves[1]));
  const right = keccak256(concat(leaves[2], leaves[3]));
  const batch = { index: 4, firstHeight: 5000, count: 3, root: bytesToHex(keccak256(concat(left, right))) };
  const ref = batchRef(batch, roots, 5001);
  assert.equal(ref.batch, 4);
  assert.equal(ref.index, 1);
  assert.deepEqual(ref.path.map(bytesToHex), [bytesToHex(leaves[0]), bytesToHex(right)]);
  assert.throws(() => batchRef({ ...batch, root: '00'.repeat(32) }, roots, 5001), /differs/);
  assert.throws(() => batchRef(batch, roots, 5003), /outside/);

  // Relay batch: hash forms, the tip's signatures, and keys only when the signing script changes.
  const same = relayBatch([bytesToHex(h0), bytesToHex(h1)], '0x' + bytesToHex(keccak256(spk)));
  assert.equal(same.headers.length, 2);
  assert.equal(same.headers[0].length, 149, 'hash form without the witness');
  assert.equal(same.sigs.length, 1);
  assert.equal(same.witnessScript.length, 0);
  assert.deepEqual(same.keyY, []);
  const changed = relayBatch([bytesToHex(h0), bytesToHex(h1)], '0x' + '00'.repeat(32));
  assert.equal(bytesToHex(changed.witnessScript), bytesToHex(wscript));
  assert.deepEqual(changed.keyY, [G_Y]);
  const broken = header(new Uint8Array(32), new Uint8Array(32).fill(1), 5001);
  assert.throws(() => relayBatch([bytesToHex(h0), bytesToHex(broken)], '0x' + '00'.repeat(32)), /not the child/);
});
