#!/usr/bin/env node
// Real Worker + WASM regression and viewport captures. All inputs are local synthetic fixtures.
// Prepare fixtures with tools/browser-builders/test.mjs and run npm run build first.
// No wallet or chain access is used. BROWSER_BUILDERS_TX_TOOL optionally verifies outputs natively.
// --screens-only skips builders; --actions=claim permits a focused run while update fixtures compile.
import assert from 'node:assert/strict';
import { spawn, execFileSync } from 'node:child_process';
import { mkdirSync, readFileSync, readdirSync, unlinkSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { parseTransaction, readWitness, displayHex } from '../../bridge-core/lib/elements.js';
import { hexToBytes } from '../../bridge-core/lib/bytes.js';
import { openChrome, sleep } from './chrome.mjs';

const ui = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const root = path.resolve(ui, '..');
const fixtures = path.join(root, 'target/browser-builders-tests');
const out = path.join(root, 'target/browser-ux/screens');
const port = Number(process.env.BROWSER_CHECK_PORT ?? 4183);
const base = `http://127.0.0.1:${port}/`;
const json = (file) => JSON.parse(readFileSync(file, 'utf8'));
const report = { status: 'running', builders: [], preparedBuilders: [], productionWorkers: [], screens: [], consoleErrors: [], externalRequests: [] };
mkdirSync(out, { recursive: true });
const server = spawn(process.execPath, [path.join(ui, 'node_modules/vite/bin/vite.js'), '--mode', 'fixture', '--host', '127.0.0.1', '--port', String(port), '--strictPort'], { cwd: ui, stdio: 'pipe' });
let serverLog = '';
server.stderr.on('data', (chunk) => { serverLog += chunk; });
let browser;
let preview;
let productionPage;
const allowedOrigins = new Set([new URL(base).origin]);

// txid commits to every unsigned field. Also compare all input witnesses and rangeproofs;
// only randomized surjection proofs differ. The native verifier checks the full browser output.
function stable(hex) {
  const raw = hexToBytes(hex.trim());
  const tx = parseTransaction(raw);
  const witness = readWitness(raw);
  return { body: tx.txidForm, inputs: witness.inputs, ranges: witness.outputs.map((output) => output.rangeproof) };
}

try {
  if (!process.argv.includes('--screens-only')) {
    execFileSync(process.execPath, [path.join(ui, 'node_modules/vitest/vitest.mjs'), 'run', 'src/bridge/browser-build.integration.test.ts'], {
      cwd: ui, env: { ...process.env, BROWSER_PREPARATION_INTEGRATION: '1' }, stdio: 'inherit',
    });
  }
  for (let i = 0; ; i++) {
    if (server.exitCode !== null) throw new Error(`Vite exited: ${serverLog}`);
    try { if ((await fetch(base)).ok) break; } catch { /* Starting local Vite. */ }
    if (i === 80) throw new Error(`Vite did not start: ${serverLog}`);
    await sleep(150);
  }
  browser = await openChrome();
  const { page, evaluate, waitFor } = browser;
  browser.onEvent((event) => {
    if (event.method === 'Runtime.exceptionThrown') report.consoleErrors.push(event.params.exceptionDetails.text);
    if (event.method === 'Runtime.consoleAPICalled' && event.params.type === 'error') report.consoleErrors.push(event.params.args.map((arg) => arg.value ?? arg.description).join(' '));
    if (event.method === 'Network.requestWillBeSent' && /^https?:/.test(event.params.request.url)
      && !allowedOrigins.has(new URL(event.params.request.url).origin)) report.externalRequests.push(event.params.request.url);
  });
  async function load() {
    await page('Page.navigate', { url: `${base}?scenario=connected` });
    await waitFor(`!!document.querySelector('#guide') && document.fonts.status === 'loaded'`);
    assert.match(await evaluate('document.title'), /zk-bridge/);
    assert.equal(await evaluate('location.origin'), new URL(base).origin);
    assert.equal(await evaluate(`!!document.querySelector('vite-error-overlay')`), false);
  }
  await load();
  if (!process.argv.includes('--screens-only')) {
    await evaluate(`import('/src/bridge/builder.ts').then(module => { window.buildTransaction = module.buildTransaction; })`);
    const actions = (process.argv.find((arg) => arg.startsWith('--actions='))?.slice(10) ?? 'claim,update').split(',');
    for (const kind of actions) {
      assert.ok(['claim', 'update'].includes(kind));
      const input = json(path.join(fixtures, `${kind}-input.json`));
      assert.match(input.manifest.label, /fictional|local test/i, 'never use a deployed manifest in this test');
      await evaluate(`window.builderInput = ${JSON.stringify(input)}; window.workerResult = undefined; window.workerError = undefined;
        window.started = performance.now(); window.uiTicks = 0; window.tick = setInterval(() => window.uiTicks++, 10);
        window.buildTransaction(${JSON.stringify(kind)}, window.builderInput).then(result => {
          clearInterval(window.tick); window.workerResult = result; window.elapsed = Math.round(performance.now() - window.started);
        }, error => { clearInterval(window.tick); window.workerError = error.message; });`);
      await waitFor('window.workerResult || window.workerError', 600_000);
      assert.equal(await evaluate('window.workerError'), undefined);
      const built = await evaluate('window.workerResult');
      const uiTicks = await evaluate('window.uiTicks');
      assert.ok(uiTicks > 0, 'UI event loop stays responsive during worker execution');
      assert.equal(built.report.ok, true);
      assert.ok(built.report.gates_passed.length > 0);
      assert.equal(displayHex(parseTransaction(hexToBytes(built.raw_tx)).txid), built.report.txid);
      assert.deepEqual(stable(built.raw_tx), stable(readFileSync(path.join(fixtures, `${kind}-cli.hex`), 'utf8')));
      const output = path.join(fixtures, `${kind}-browser.hex`);
      writeFileSync(output, built.raw_tx);
      const tool = process.env.BROWSER_BUILDERS_TX_TOOL;
      if (tool) {
        const verified = JSON.parse(execFileSync(tool, ['verify', output, '0', path.join(fixtures, `${kind}-state.hex`), path.join(fixtures, `${kind}-fee.hex`)], { encoding: 'utf8', maxBuffer: 16 * 1024 * 1024 }));
        assert.equal(verified.ok, true);
      }
      const rejection = await evaluate(`window.buildTransaction(${JSON.stringify(kind)}, {...window.builderInput, fee_vout: 99}).then(() => '', error => error.message)`);
      assert.match(rejection, /fee vout/);
      const cancelled = await evaluate(`(async () => {
        const before = new AbortController(); before.abort();
        const first = await window.buildTransaction(${JSON.stringify(kind)}, window.builderInput, before.signal).then(() => '', error => error.message);
        const during = new AbortController();
        const pending = window.buildTransaction(${JSON.stringify(kind)}, window.builderInput, during.signal).then(() => '', error => error.message);
        during.abort();
        return [first, await pending];
      })()`);
      assert.deepEqual(cancelled, ['Build cancelled', 'Build cancelled']);
      if (kind === 'update') {
        assert.equal(await evaluate(`(async () => {
          const during = new AbortController();
          const pending = window.buildTransaction('update', window.builderInput, during.signal).then(() => '', error => error.message);
          setTimeout(() => during.abort(), 250);
          return pending;
        })()`), 'Build cancelled', 'cancel an update after worker computation starts');
      }
      // A new worker still handles errors after the cancelled worker was terminated.
      assert.match(await evaluate(`window.buildTransaction(${JSON.stringify(kind)}, {}).then(() => '', error => error.message)`), /manifest/);
      const result = { kind, milliseconds: await evaluate('window.elapsed'), txid: built.report.txid,
        nativeParity: true, nativeVerification: !!tool, uiTicks, rejection, cancellation: cancelled };
      report.builders.push(result);
      console.log(JSON.stringify(result));
      // Consume the exact serialized result of the real preparation helper.
      // The test harness replaces source data and liveState only; no builder input is rewritten here.
      const prepared = json(path.join(fixtures, `${kind}-prepared-input.json`));
      await evaluate(`window.preparedResult = undefined; window.preparedError = undefined;
        window.preparedStarted = performance.now();
        window.buildTransaction(${JSON.stringify(kind)}, ${JSON.stringify(prepared)}).then(result => {
          window.preparedResult = result; window.preparedElapsed = Math.round(performance.now() - window.preparedStarted);
        }, error => { window.preparedError = error.message; });`);
      await waitFor('window.preparedResult || window.preparedError', 600_000);
      assert.equal(await evaluate('window.preparedError'), undefined);
      const preparedBuilt = await evaluate('window.preparedResult');
      assert.equal(preparedBuilt.report.ok, true);
      const preparedRaw = hexToBytes(preparedBuilt.raw_tx);
      const preparedTx = parseTransaction(preparedRaw);
      const nativeTx = parseTransaction(hexToBytes(built.raw_tx));
      assert.equal(preparedBuilt.report.txid, displayHex(preparedTx.txid));
      assert.deepEqual(preparedTx.inputs[0], nativeTx.inputs[0]);
      assert.deepEqual(preparedTx.outputs[0].raw, nativeTx.outputs[0].raw);
      assert.deepEqual(stable(preparedBuilt.raw_tx).inputs, stable(built.raw_tx).inputs);
      assert.deepEqual(stable(preparedBuilt.raw_tx).ranges, stable(built.raw_tx).ranges);
      if (kind === 'claim') assert.deepEqual(stable(preparedBuilt.raw_tx), stable(built.raw_tx));
      else {
        assert.equal(preparedTx.outputs.length, 2);
        assert.equal(preparedTx.outputs[1].value.amount, 50_000n);
        assert.equal(displayHex(preparedTx.inputs[1].prevTxid), displayHex(parseTransaction(hexToBytes(prepared.fee_tx_hex)).txid));
        assert.equal(preparedTx.inputs[1].n, prepared.fee_vout);
      }
      const preparedOutput = path.join(fixtures, `${kind}-prepared-browser.hex`);
      writeFileSync(preparedOutput, preparedBuilt.raw_tx);
      if (tool) {
        const preparedFee = path.join(fixtures, `${kind}-prepared-fee.hex`);
        writeFileSync(preparedFee, prepared.fee_tx_hex);
        assert.equal(JSON.parse(execFileSync(tool, ['verify', preparedOutput, '0', path.join(fixtures, `${kind}-state.hex`), preparedFee],
          { encoding: 'utf8', maxBuffer: 16 * 1024 * 1024 })).ok, true);
      }
      const preparedResult = { kind, milliseconds: await evaluate('window.preparedElapsed'), txid: preparedBuilt.report.txid,
        actualPreparationOutput: true, nativeVerification: !!tool, feeSats: String(preparedTx.outputs.at(-1).value.amount) };
      report.preparedBuilders.push(preparedResult);
      console.log(`Prepared worker: ${JSON.stringify(preparedResult)}`);
    }
  }
  for (const [width, height] of [[1440, 1000], [390, 900]]) {
    await page('Emulation.setDeviceMetricsOverride', { width, height, deviceScaleFactor: 1, mobile: width < 720 });
    await page('Emulation.setTouchEmulationEnabled', { enabled: width < 720 });
    await load();
    async function capture(name, selector) {
      await evaluate(`document.querySelector(${JSON.stringify(selector)}).scrollIntoView({block:'start', behavior:'instant'})`);
      await sleep(150);
      const layout = await evaluate(`({ width: innerWidth, client: document.documentElement.clientWidth, scroll: document.documentElement.scrollWidth,
        overlay: !!document.querySelector('vite-error-overlay') })`);
      assert.equal(layout.width, width);
      assert.equal(layout.overlay, false);
      assert.ok(layout.scroll <= layout.client, `${name}: horizontal overflow ${JSON.stringify(layout)}`);
      const { data } = await page('Page.captureScreenshot', { format: 'png' });
      const file = path.join(out, `${name}-${width}.png`);
      writeFileSync(file, Buffer.from(data, 'base64'));
      report.screens.push({ name, width, height, file, layout });
      console.log(`Captured ${name} ${width} × ${height}`);
    }
    await capture('guide', '#guide');
    await evaluate(`[...document.querySelectorAll('#guide button')].find(button => button.textContent === 'Open update').click()`);
    await waitFor(`document.querySelector('#update').open`);
    assert.equal(await evaluate(`document.querySelector('#claim').open`), false);
    await capture('update', '#update');
    await evaluate(`[...document.querySelectorAll('#guide button')].find(button => button.textContent === 'Open claim').click()`);
    await waitFor(`document.querySelector('#claim').open && document.activeElement.matches('#claim input[inputmode="numeric"]')`);
    await capture('claim', '#claim');
    await evaluate(`document.querySelector('#claim fieldset details summary').click()`);
    assert.equal(await evaluate(`[...document.querySelectorAll('#claim fieldset button')].find(button => button.textContent === 'Prepare fee coin').disabled`), true);
    await capture('fee-prepare', '#claim fieldset');
    await evaluate(`(() => {
      const input = document.querySelector('#claim fieldset input[placeholder]');
      Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value').set.call(input, 'not-an-address');
      input.dispatchEvent(new Event('input', {bubbles:true}));
    })()`);
    await waitFor(`![...document.querySelectorAll('#claim fieldset button')].find(button => button.textContent === 'Find fee coins').disabled`);
    await evaluate(`[...document.querySelectorAll('#claim fieldset button')].find(button => button.textContent === 'Find fee coins').click()`);
    await waitFor(`document.querySelector('#claim fieldset [role="alert"]').textContent.trim()`);
    assert.equal(await evaluate(`[...document.querySelectorAll('#claim fieldset button')].find(button => button.textContent === 'Prepare fee coin').disabled`), true);
    await capture('fee-error', '#claim fieldset');
    // Drive the real file-input handler with a malformed local file; signing must stay disabled.
    await evaluate(`(() => {
      const disclosure = [...document.querySelectorAll('#claim details')].find(element => element.querySelector('summary')?.textContent === 'Import a transaction built elsewhere');
      disclosure.querySelector('summary').click();
      const input = disclosure.querySelector('input[type="file"]');
      const transfer = new DataTransfer(); transfer.items.add(new File(['not transaction hex'], 'invalid.hex', {type:'text/plain'}));
      input.files = transfer.files; input.dispatchEvent(new Event('change', {bubbles:true}));
    })()`);
    await waitFor(`[...document.querySelectorAll('#claim details:has(input[type="file"]) [role="alert"]')].some(element => element.textContent.trim())`);
    assert.equal(await evaluate(`[...document.querySelectorAll('#claim button')].find(button => button.textContent === 'Sign and send with Humid').disabled`), true);
    await capture('claim-error', '#claim details:has(input[type="file"])');
  }
  if (!process.argv.includes('--screens-only')) {
    // Use the production artifact without mounting its network-connected application.
    // This page exists only in the generated build during this check and is removed below.
    const dist = path.join(ui, 'dist');
    const workers = readdirSync(path.join(dist, 'assets')).filter((name) => /^builder\.worker-.*\.js$/.test(name));
    assert.equal(workers.length, 1, 'run npm run build to create exactly one production worker');
    const checkPage = path.join(dist, 'browser-worker-check.html');
    writeFileSync(checkPage, '<!doctype html><title>Local production worker check</title><p>Synthetic fixture only</p>', { flag: 'wx' });
    productionPage = checkPage;
    const previewBase = `http://127.0.0.1:${port + 1}/`;
    allowedOrigins.add(new URL(previewBase).origin);
    preview = spawn(process.execPath, [path.join(ui, 'node_modules/vite/bin/vite.js'), 'preview', '--mode', 'fixture', '--outDir', 'dist', '--host', '127.0.0.1', '--port', String(port + 1), '--strictPort'], { cwd: ui, stdio: 'ignore' });
    for (let i = 0; ; i++) {
      if (preview.exitCode !== null) throw new Error('Production preview exited');
      try { if ((await fetch(`${previewBase}browser-worker-check.html`)).ok) break; } catch { /* Starting preview. */ }
      if (i === 80) throw new Error('Production preview did not start');
      await sleep(150);
    }
    await page('Page.navigate', { url: `${previewBase}browser-worker-check.html` });
    await waitFor(`document.title === 'Local production worker check'`);
    for (const { kind } of report.builders) {
      const input = json(path.join(fixtures, `${kind}-input.json`));
      await evaluate(`window.productionResult = undefined; window.productionError = undefined;
        window.productionStarted = performance.now();
        window.productionWorker = new Worker(${JSON.stringify(`./assets/${workers[0]}`)}, {type:'module'});
        window.productionWorker.onmessage = ({data}) => {
          window.productionWorker.terminate(); window.productionElapsed = Math.round(performance.now() - window.productionStarted);
          if (data.error) window.productionError = data.error; else window.productionResult = data.result;
        };
        window.productionWorker.onerror = (error) => { window.productionError = error.message; window.productionWorker.terminate(); };
        window.productionWorker.postMessage({kind:${JSON.stringify(kind)}, input:${JSON.stringify(input)}});`);
      await waitFor('window.productionResult || window.productionError', 600_000);
      assert.equal(await evaluate('window.productionError'), undefined);
      const built = await evaluate('window.productionResult');
      assert.equal(built.report.ok, true);
      assert.equal(built.report.txid, report.builders.find((result) => result.kind === kind).txid);
      assert.deepEqual(stable(built.raw_tx), stable(readFileSync(path.join(fixtures, `${kind}-cli.hex`), 'utf8')));
      const result = { kind, milliseconds: await evaluate('window.productionElapsed'), nativeParity: true, txid: built.report.txid };
      report.productionWorkers.push(result);
      console.log(`Production worker: ${JSON.stringify(result)}`);
    }
  }
  assert.deepEqual(report.consoleErrors, [], 'unexpected browser errors');
  assert.deepEqual(report.externalRequests, [], 'fixture browser must stay local');
  report.status = 'passed';
  console.log('Browser Worker/WASM and viewport checks passed.');
} finally {
  if (report.status === 'running') report.status = 'failed';
  writeFileSync(path.join(out, process.argv.includes('--screens-only') ? 'screens-check.json' : 'browser-check.json'), JSON.stringify(report, null, 2));
  await browser?.close();
  server.kill();
  preview?.kill();
  if (productionPage) unlinkSync(productionPage);
}
