// Entry point: the interface for the one published instance, config.js INSTANCE, read-only from ../ui. No link,
// setting or stored value can change the instance. In the 'fixture' mode only (npm run dev:fixture or
// build:fixture, for screenshots), a stand-in wallet, escrow and Liquid API replace the real ones; a production
// build has no such branch, as Vite replaces import.meta.env.MODE with the literal 'production'.
import { INSTANCE, type RawInstance } from '@bridge/ui/config.js';
import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';
import { App } from './app/App';
import { BridgeProvider } from './bridge/context';
import { BridgeController } from './bridge/controller';
import { browserEnv } from './bridge/env';
import { message } from './bridge/format';
import type { BridgeEnv } from './bridge/types';
import './styles/app.css';

async function boot(): Promise<{ instance: RawInstance | null; env: BridgeEnv }> {
  if (import.meta.env.MODE === 'fixture') {
    const { fixture, SCENARIOS } = await import('./dev/fixture');
    const asked = new URLSearchParams(window.location.search).get('scenario');
    const f = fixture(SCENARIOS.find((s) => s === asked) ?? 'connected');
    return { instance: f.instance, env: f.env };
  }
  return { instance: INSTANCE, env: browserEnv() };
}

const root = createRoot(document.getElementById('root')!);
boot().then(({ instance, env }) => {
  let controller: BridgeController;
  try {
    controller = new BridgeController(instance, env);
  } catch (e) {
    // An invalid instance record stops the page rather than serving a mistaken escrow.
    root.render(<p className="fatal">This page's instance record is invalid, so it serves nothing: {message(e)}.</p>);
    return;
  }
  root.render(
    <StrictMode>
      <BridgeProvider controller={controller}>
        <App />
      </BridgeProvider>
    </StrictMode>,
  );
});
