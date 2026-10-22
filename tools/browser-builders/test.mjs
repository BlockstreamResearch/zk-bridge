// Requires synthetic fixtures from test_testnet.py --full. Never signs or broadcasts.
import assert from 'node:assert/strict';
import { readFile, writeFile, mkdir } from 'node:fs/promises';
import { resolve, dirname } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { execFileSync } from 'node:child_process';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '../..');
const fixtures = resolve(process.env.BROWSER_BUILDERS_FIXTURES ?? `${root}/build/sg16-testnet`);
const modules = resolve(process.env.BROWSER_BUILDERS_OUT ?? `${root}/target/browser-builders`);
const out = `${root}/target/browser-builders-tests`;
await mkdir(out, { recursive: true });
const text = (path) => readFile(path, 'utf8');
const json = async (path) => JSON.parse(await text(path));
const txTool =
  process.env.BROWSER_BUILDERS_TX_TOOL ?? `${root}/tools/sg16/bridge-guest/target/testnet-tx/release/sg16-testnet`;
const claimTool =
  process.env.BROWSER_BUILDERS_CLAIM_TOOL ??
  `${root}/tools/sg16/bridge-guest/target/testnet-claim/release/sg16-testnet-claim`;
const run = (tool, args) => JSON.parse(execFileSync(tool, args, { encoding: 'utf8', maxBuffer: 16 * 1024 * 1024 }));

// Compare all transaction fields and covenant witness. Surjection proof randomness is
// intentionally excluded; rust-elements verifies both complete transactions separately.
function stableBytes(hex) {
  const b = Buffer.from(hex.trim(), 'hex');
  let at = 0;
  const take = (n) => {
    const x = b.subarray(at, at + n);
    assert.equal(x.length, n);
    at += n;
    return x;
  };
  const count = () => {
    const n = take(1)[0];
    return n < 253
      ? n
      : n === 253
        ? take(2).readUInt16LE()
        : n === 254
          ? take(4).readUInt32LE()
          : Number(take(8).readBigUInt64LE());
  };
  const variable = () => take(count());
  const vector = () => Array.from({ length: count() }, variable);
  const confidential = (explicit) => {
    const tag = take(1)[0];
    if (tag !== 0) take(tag === 1 ? explicit : 32);
  };
  take(4);
  const flag = take(1)[0];
  const inputs = count();
  for (let i = 0; i < inputs; i++) {
    take(32);
    const index = take(4).readUInt32LE();
    variable();
    take(4);
    if (index !== 0xffffffff && index & 0x80000000) {
      take(64);
      confidential(8);
      confidential(8);
    }
  }
  const outputs = count();
  for (let i = 0; i < outputs; i++) {
    confidential(32);
    confidential(8);
    confidential(32);
    variable();
  }
  take(4);
  const result = { body: b.subarray(0, at).toString('hex'), inputs: [], ranges: [] };
  if (flag) {
    for (let i = 0; i < inputs; i++) {
      const start = at;
      variable();
      variable();
      vector();
      vector();
      result.inputs.push(b.subarray(start, at).toString('hex'));
    }
    for (let i = 0; i < outputs; i++) {
      variable();
      result.ranges.push(variable().toString('hex'));
    }
  }
  assert.equal(at, b.length);
  return result;
}

const results = [];
for (const action of (process.env.BROWSER_BUILDERS_ACTIONS ?? 'update,claim').split(',')) {
  assert.ok(['update', 'claim'].includes(action));
  const module = await import(pathToFileURL(`${modules}/${action}/${action}.js`));
  await module.default({ module_or_path: await readFile(`${modules}/${action}/${action}_bg.wasm`) });
  const build = (input) => JSON.parse(module[`build_${action}`](JSON.stringify(input)));
  assert.throws(() => module[`build_${action}`]('{'), /JSON/);
  assert.throws(() => build([]), /object/);
  const folder = action === 'update' ? `${fixtures}/synthetic-key` : fixtures;
  const manifest = await json(action === 'update' ? `${folder}/manifest.json` : `${fixtures}/local/manifest.json`);
  assert.equal(manifest.deployable, false, 'only synthetic fixture manifests belong in this test');
  const input = {
    manifest,
    state: await json(action === 'update' ? `${folder}/initial_state.json` : `${folder}/state1_lc_only.json`),
    state_tx_hex: await text(action === 'update' ? `${folder}/bootstrap.hex` : `${folder}/state1_prev.hex`),
    state_vout: 0,
    fee_tx_hex: await text(action === 'update' ? `${folder}/fee.hex` : `${folder}/fee_prev.hex`),
    fee_vout: 0,
    ...(action === 'update'
      ? {
          program: await text(`${folder}/update_leaf.simpl`),
          witness: await json(`${folder}/update.witness.json`),
          new_state: await json(`${folder}/new_state.json`),
        }
      : { deposits: await json(`${folder}/deposits.json`), index: 0 }),
  };
  if (action === 'update') {
    const compiledPath = process.env.BROWSER_BUILDERS_COMPILED ?? `${out}/update-compiled.json`;
    if (!process.env.BROWSER_BUILDERS_COMPILED) {
      console.log('Compiling the synthetic update program once in the native CLI...');
      run(txTool, ['compile-update', `${folder}/update_leaf.simpl`, `${folder}/update.witness.json`, compiledPath]);
    }
    input.compiled_program = await json(compiledPath);
    await writeFile(`${out}/update-compiled.json`, JSON.stringify(input.compiled_program));
  }
  assert.throws(() => build(input), /deployable/);
  // Exercise the exact production entrypoint with a fictional, cryptographically valid fixture.
  // This does not claim that any fixture is deployed or safe to use on a network.
  input.manifest = { ...manifest, deployable: true };
  await writeFile(`${out}/${action}-input.json`, JSON.stringify(input));
  for (const key of ['manifest', 'state', ...(action === 'update' ? ['witness', 'new_state'] : ['deposits'])]) {
    await writeFile(`${out}/${action}-${key}.json`, JSON.stringify(input[key]));
  }
  await writeFile(`${out}/${action}-state.hex`, input.state_tx_hex);
  await writeFile(`${out}/${action}-fee.hex`, input.fee_tx_hex);
  console.log(`Building ${action} in WASM...`);
  const started = performance.now();
  const built = build(input);
  const elapsed = Math.round(performance.now() - started);
  console.log(`${action} WASM built in ${elapsed} ms; comparing CLI bytes...`);
  const args =
    action === 'update'
      ? [
          'update-compiled',
          `${out}/update-manifest.json`,
          `${out}/update-compiled.json`,
          `${out}/update-state.json`,
          `${out}/update-new_state.json`,
          `${out}/update-state.hex`,
          '0',
          `${out}/update-fee.hex`,
          '0',
          `${out}/update-cli.hex`,
        ]
      : [
          'claim',
          `${out}/claim-manifest.json`,
          `${out}/claim-state.json`,
          `${out}/claim-deposits.json`,
          `${out}/claim-state.hex`,
          '0',
          `${out}/claim-fee.hex`,
          '0',
          `${out}/claim-cli.hex`,
          '--deposit',
          '0',
        ];
  const cli = run(action === 'update' ? txTool : claimTool, args);
  assert.equal(built.report.txid, cli.txid);
  assert.deepEqual(built.report.successor_state, cli.successor_state);
  assert.deepEqual(stableBytes(built.raw_tx), stableBytes(await text(`${out}/${action}-cli.hex`)));
  if (action === 'update') assert.deepEqual(stableBytes(built.raw_tx), stableBytes(await text(`${folder}/update.hex`)));
  await writeFile(`${out}/${action}-wasm.hex`, built.raw_tx);
  assert.equal(
    run(txTool, ['verify', `${out}/${action}-wasm.hex`, '0', `${out}/${action}-state.hex`, `${out}/${action}-fee.hex`])
      .ok,
    true,
  );
  assert.equal(
    run(txTool, ['verify', `${out}/${action}-cli.hex`, '0', `${out}/${action}-state.hex`, `${out}/${action}-fee.hex`])
      .ok,
    true,
  );
  for (const [patch, expected] of [
    [{ state_vout: 0x100000000 }, /exceeds u32/],
    [{ fee_vout: 99 }, /fee vout/],
    [{ state_tx_hex: 'xx' }, /transaction|hex|character/i],
    [{ state: { ...input.state, acc: '00'.repeat(32) } }, /state UTXO|accumulator/],
    ...(action === 'update'
      ? [
          [{ compiled_program: undefined, program: 'main := unit', witness: { w_in: { bit: 2 } } }, /bit must be/],
          [{ compiled_program: undefined, program: 'main := unit', witness: { w_in: { w: '' } } }, /hex word/],
          [{ compiled_program: undefined, program: 'not a program' }, /program/],
          [{ compiled_program: { ...input.compiled_program, witness_hex: '00' } }, /compiled|rejected/],
          [
            { manifest: { ...input.manifest, update_leaf: { ...input.manifest.update_leaf, cmr: '00'.repeat(32) } } },
            /CMR/,
          ],
          [{ new_state: input.state }, /advances/],
        ]
      : [
          [{ index: 2 }, /unclaimed/],
          [{ index: 3 }, /proven/],
          [{ deposits: [[1, '0014' + '33'.repeat(20)]] }, /bounds/],
        ]),
  ])
    assert.throws(() => build({ ...input, ...patch }), expected);
  if (action === 'update') {
    const corrupted = Buffer.from(input.compiled_program.witness_hex, 'hex');
    corrupted[10] ^= 1;
    assert.throws(
      () =>
        build({
          ...input,
          compiled_program: {
            ...input.compiled_program,
            witness_hex: corrupted.toString('hex'),
          },
        }),
      /rejected/,
      'a canonically encoded but altered proof must fail execution',
    );
  }
  results.push({
    action,
    milliseconds: elapsed,
    bytes: (await readFile(`${modules}/${action}/${action}_bg.wasm`)).length,
    txid: built.report.txid,
  });
}
await writeFile(`${out}/results.json`, JSON.stringify(results, null, 2));
console.log(JSON.stringify(results, null, 2));
