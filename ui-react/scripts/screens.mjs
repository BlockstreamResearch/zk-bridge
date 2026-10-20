#!/usr/bin/env node
// Screenshots of the fixture build for visual review, at desktop and narrow mobile widths, in every fixture
// scenario, and a check that no scenario overflows the screen sideways. No dependency beyond Vite: it serves
// dist-fixture/ with `vite preview` and drives headless Chrome over the DevTools protocol (--remote-debugging-pipe).
// Run `npm run build:fixture` first. Writes screens/<scenario>-<width>.png, and <scenario>-<width>-open.png with every
// tab panel shown and every disclosure open; with --check, writes nothing and only checks the layout, in both states.
//
//   CHROME=/path/to/chrome npm run screens     # default: Google Chrome's macOS path, or `google-chrome` on PATH
//   npm run check:layout                       # the same pages, no screenshots
//
// Each width is set with device-metrics emulation, not --window-size: headless Chrome keeps its window at least
// 500 px wide, so a 390 px window lays the page out at 500 px and the screenshot crops it, which reads as overflow
// that a phone would not show and hides overflow it would. The check fails if the page was laid out at any other
// width than asked, if it scrolls sideways, or if an element reaches past either edge of the screen.
import { spawn } from 'node:child_process';
import { existsSync, mkdirSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const out = path.join(root, 'screens');
const port = 4179;
const checkOnly = process.argv.includes('--check');
const scenarios = ['connected', 'disconnected', 'no-wallet', 'no-instance', 'relay-closed', 'fork-closed', 'liquid-down', 'bad-code', 'activity'];
// Tall viewports stand in for full-page captures. Below 720 px the page uses its mobile layout, and the emulation
// is a phone's: the viewport meta tag applies and touch is on. 320 px is the narrowest phone width in common use.
const sizes = [[1440, 3400], [390, 7600], [320, 7600]];

const chrome = process.env.CHROME
  ?? ['/Applications/Google Chrome.app/Contents/MacOS/Google Chrome', '/Applications/Chromium.app/Contents/MacOS/Chromium'].find(existsSync)
  ?? 'google-chrome';

if (!existsSync(path.join(root, 'dist-fixture', 'index.html'))) {
  console.error('dist-fixture/ is missing: run `npm run build:fixture` first.');
  process.exit(1);
}
if (!checkOnly) mkdirSync(out, { recursive: true });

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

/** The DevTools protocol over Chrome's pipe: NUL-terminated JSON, Chrome reading fd 3 and writing fd 4. */
function devtools(browser) {
  const pending = new Map();
  const waiters = [];
  let next = 0;
  let buffer = '';
  browser.stdio[4].setEncoding('utf8');
  browser.stdio[4].on('data', (chunk) => {
    buffer += chunk;
    let end;
    while ((end = buffer.indexOf('\0')) >= 0) {
      const msg = JSON.parse(buffer.slice(0, end));
      buffer = buffer.slice(end + 1);
      if (msg.id !== undefined) {
        const p = pending.get(msg.id);
        pending.delete(msg.id);
        if (msg.error) p?.reject(new Error(`${p.method}: ${msg.error.message}`));
        else p?.resolve(msg.result);
      } else {
        for (let i = waiters.length - 1; i >= 0; i--) {
          if (waiters[i].method === msg.method && waiters[i].sessionId === msg.sessionId) waiters.splice(i, 1)[0].resolve(msg.params);
        }
      }
    }
  });
  return {
    send(method, params = {}, sessionId) {
      const id = ++next;
      browser.stdio[3].write(JSON.stringify({ id, method, params, sessionId }) + '\0');
      return new Promise((resolve, reject) => {
        pending.set(id, { method, resolve, reject });
        setTimeout(() => pending.delete(id) && reject(new Error(`${method}: no answer in 30 s`)), 30_000).unref();
      });
    },
    /** The next event of this name in this session. */
    event(method, sessionId) {
      return new Promise((resolve) => waiters.push({ method, sessionId, resolve }));
    },
  };
}

// Runs in the page. Reports the outermost elements that reach past the screen's edges; .sr-only text is meant to be
// off-screen, and a hidden element has no box.
const MEASURE = `(() => {
  const vw = document.documentElement.clientWidth;
  const past = [...document.body.querySelectorAll('*')].filter((e) => {
    const r = e.getBoundingClientRect();
    return r.width > 0 && (r.right > vw + 0.5 || r.left < -0.5) && !e.closest('.sr-only');
  });
  const outer = past.filter((e) => !past.includes(e.parentElement));
  return {
    laidOut: window.innerWidth, scrollWidth: document.documentElement.scrollWidth, clientWidth: vw,
    past: outer.slice(0, 8).map((e) => {
      const r = e.getBoundingClientRect();
      const name = e.tagName.toLowerCase() + (e.className && typeof e.className === 'string' ? '.' + e.className.trim().split(/\\s+/).join('.') : '');
      const text = (e.textContent ?? '').replace(/\\s+/g, ' ').trim().slice(0, 40);
      return name + ' [' + Math.round(r.left) + ', ' + Math.round(r.right) + ']' + (text ? ' "' + text + '"' : '');
    }),
  };
})()`;

// Runs in the page. Shows the Redeem and Activity panels under the Deposit one and opens every disclosure, so the
// second measurement covers what a reader can reach by a click, not only what the page shows on load. Each scenario
// is a fresh load, so the next one starts as the page does.
const REVEAL = `(() => {
  for (const p of document.querySelectorAll('[role="tabpanel"][hidden]')) p.hidden = false;
  for (const d of document.querySelectorAll('details')) d.open = true;
})()`;

const vite = path.join(root, 'node_modules', 'vite', 'bin', 'vite.js');
const server = spawn(process.execPath, [vite, 'preview', '--mode', 'fixture', '--outDir', 'dist-fixture', '--host', '127.0.0.1', '--port', String(port), '--strictPort'], { cwd: root, stdio: 'ignore' });
const browser = spawn(chrome, [
  '--headless=new', '--remote-debugging-pipe', '--disable-gpu', '--hide-scrollbars', '--force-prefers-reduced-motion',
  '--no-first-run', '--no-default-browser-check', 'about:blank',
], { stdio: ['ignore', 'ignore', 'ignore', 'pipe', 'pipe'] });
browser.on('error', (e) => {
  console.error(`cannot start Chrome (${chrome}): ${e.message}. Set CHROME to its path.`);
  server.kill();
  process.exit(1);
});
const base = `http://127.0.0.1:${port}/`;

try {
  for (let i = 0; ; i++) {
    try {
      if ((await fetch(base)).ok) break;
    } catch {
      /* not up yet */
    }
    if (i > 50) throw new Error('vite preview did not start');
    await sleep(200);
  }
  const cdp = devtools(browser);
  const { targetId } = await cdp.send('Target.createTarget', { url: 'about:blank' });
  const { sessionId } = await cdp.send('Target.attachToTarget', { targetId, flatten: true });
  const page = (method, params) => cdp.send(method, params, sessionId);
  await page('Page.enable');
  // So clientWidth is the full width asked for; --hide-scrollbars covers a Chrome without this experimental method.
  await page('Emulation.setScrollbarsHidden', { hidden: true }).catch(() => {});

  let failed = 0;
  for (const [w, h] of sizes) {
    const mobile = w < 720;
    await page('Emulation.setDeviceMetricsOverride', { width: w, height: h, deviceScaleFactor: 1, mobile });
    await page('Emulation.setTouchEmulationEnabled', { enabled: mobile });
    for (const scenario of scenarios) {
      const label = `${scenario}-${w}`;
      const loaded = cdp.event('Page.loadEventFired', sessionId);
      await page('Page.navigate', { url: `${base}?scenario=${scenario}` });
      await loaded;
      // The fixture answers at once; wait for the app to render and its fonts to load, then give it a moment.
      for (let i = 0; i < 50; i++) {
        const { result } = await page('Runtime.evaluate', { expression: `!!document.querySelector('.readings') && document.fonts.status === 'loaded'`, returnByValue: true });
        if (result.value) break;
        await sleep(100);
      }
      await sleep(800);

      for (const state of ['', 'open']) {
        const name = state ? `${label}-${state}` : label;
        if (state) {
          await page('Runtime.evaluate', { expression: REVEAL });
          await sleep(200);
        }
        const measured = await page('Runtime.evaluate', { expression: MEASURE, returnByValue: true });
        if (measured.exceptionDetails) throw new Error(`${name}: measuring failed: ${measured.exceptionDetails.exception?.description ?? measured.exceptionDetails.text}`);
        const m = measured.result.value;
        const problems = [];
        if (m.laidOut !== w) problems.push(`laid out at ${m.laidOut} px, not ${w} px`);
        if (m.scrollWidth > m.clientWidth) problems.push(`scrolls sideways: ${m.scrollWidth} px of content in ${m.clientWidth} px`);
        if (m.past.length) problems.push(`past the screen's edge: ${m.past.join('; ')}`);

        let wrote = '';
        if (!checkOnly) {
          const { data } = await page('Page.captureScreenshot', { format: 'png' });
          const file = path.join(out, `${name}.png`);
          writeFileSync(file, Buffer.from(data, 'base64'));
          wrote = `wrote ${path.relative(root, file)}`;
        }
        if (problems.length) failed += 1;
        console.log(`${problems.length ? 'FAILED' : 'ok'} ${name}${wrote ? ` (${wrote})` : ''}${problems.length ? `\n  ${problems.join('\n  ')}` : ''}`);
      }
    }
  }
  process.exitCode = failed ? 1 : 0;
} finally {
  browser.kill();
  server.kill();
}
