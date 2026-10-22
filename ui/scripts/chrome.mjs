// Isolated local Chrome/CDP harness shared by browser regression scripts.
import { spawn } from 'node:child_process';
import { existsSync, mkdtempSync } from 'node:fs';
import { rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';

export const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

export async function openChrome() {
  const executable = process.env.CHROME
    ?? ['/Applications/Google Chrome.app/Contents/MacOS/Google Chrome', '/Applications/Chromium.app/Contents/MacOS/Chromium'].find(existsSync)
    ?? 'google-chrome';
  const profile = mkdtempSync(path.join(tmpdir(), 'bridge-browser-check-'));
  const browser = spawn(executable, [
    '--headless=new', '--remote-debugging-pipe', '--disable-gpu', '--hide-scrollbars',
    '--force-prefers-reduced-motion', '--no-first-run', '--no-default-browser-check',
    `--user-data-dir=${profile}`, 'about:blank',
  ], { stdio: ['ignore', 'ignore', 'ignore', 'pipe', 'pipe'] });
  const closed = new Promise((resolve) => browser.once('close', resolve));
  const pending = new Map();
  const listeners = new Set();
  let next = 0;
  let buffer = '';
  const fail = (error) => {
    for (const entry of pending.values()) { clearTimeout(entry.timer); entry.reject(error); }
    pending.clear();
  };
  browser.on('error', fail);
  browser.on('exit', () => fail(new Error('Chrome exited')));
  browser.stdio[4].setEncoding('utf8');
  browser.stdio[4].on('data', (chunk) => {
    buffer += chunk;
    let end;
    while ((end = buffer.indexOf('\0')) >= 0) {
      const message = JSON.parse(buffer.slice(0, end));
      buffer = buffer.slice(end + 1);
      if (message.id !== undefined) {
        const entry = pending.get(message.id);
        if (!entry) continue;
        pending.delete(message.id);
        clearTimeout(entry.timer);
        if (message.error) entry.reject(new Error(`${entry.method}: ${message.error.message}`));
        else entry.resolve(message.result);
      } else for (const listener of listeners) listener(message);
    }
  });
  function send(method, params = {}, sessionId) {
    const id = ++next;
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => { pending.delete(id); reject(new Error(`${method}: no answer in 30 s`)); }, 30_000);
      pending.set(id, { method, resolve, reject, timer });
      browser.stdio[3].write(JSON.stringify({ id, method, params, sessionId }) + '\0');
    });
  }
  const close = async () => {
    if (browser.pid && browser.exitCode === null && browser.signalCode === null) {
      browser.kill();
    }
    await closed;
    // Chrome's helper processes can finish profile writes after the browser exits.
    await rm(profile, { recursive: true, force: true, maxRetries: 10, retryDelay: 100 });
  };
  try {
    const { targetId } = await send('Target.createTarget', { url: 'about:blank' });
    const { sessionId } = await send('Target.attachToTarget', { targetId, flatten: true });
    const page = (method, params) => send(method, params, sessionId);
    await page('Page.enable');
    await page('Runtime.enable');
    await page('Network.enable');
    const evaluate = async (expression) => {
      const result = await page('Runtime.evaluate', { expression, returnByValue: true, awaitPromise: true });
      if (result.exceptionDetails) throw new Error(result.exceptionDetails.exception?.description ?? result.exceptionDetails.text);
      return result.result.value;
    };
    const waitFor = async (expression, milliseconds = 15_000) => {
      const deadline = Date.now() + milliseconds;
      do {
        const result = await evaluate(expression);
        if (result) return result;
        await sleep(100);
      } while (Date.now() < deadline);
      throw new Error(`Browser condition timed out: ${expression.slice(0, 160)}`);
    };
    return { page, evaluate, waitFor, close, onEvent: (listener) => listeners.add(listener) };
  } catch (error) { await close(); throw error; }
}
