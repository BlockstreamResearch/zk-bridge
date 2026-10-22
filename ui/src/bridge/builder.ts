export interface BuiltTransaction {
  raw_tx: string;
  report: Record<string, unknown>;
}

export type BuildTransaction = (kind: 'update' | 'claim', input: Record<string, unknown>, signal?: AbortSignal) => Promise<BuiltTransaction>;

/** A cancellable, bounded compiler invocation. The wallet is never available inside this worker. */
export const buildTransaction: BuildTransaction = (kind, input, signal) => new Promise((resolve, reject) => {
  if (signal?.aborted) {
    reject(new Error('Build cancelled'));
    return;
  }
  const worker = new Worker(new URL('./builder.worker.ts', import.meta.url), { type: 'module' });
  const finish = () => {
    clearTimeout(timer);
    signal?.removeEventListener('abort', cancel);
    worker.terminate();
  };
  const cancel = () => {
    finish();
    reject(new Error('Build cancelled'));
  };
  const timer = setTimeout(() => {
    finish();
    reject(new Error('Transaction construction timed out. Try again on a faster device.'));
  }, 600_000);
  signal?.addEventListener('abort', cancel, { once: true });
  worker.onerror = () => {
    finish();
    reject(new Error('Transaction builder failed to load or run. Reload the page and try again.'));
  };
  worker.onmessage = ({ data }) => {
    finish();
    if (data.error) {
      const error = String(data.error);
      reject(new Error(error.includes('fee covers 0.1 sat/vB')
        ? 'The selected fee coin is too small for this transaction. Choose a larger coin and build again; it will be spent entirely as the fee.'
        : error === 'unreachable'
          ? 'Transaction construction failed. Reload the page and try again; nothing was signed or sent.'
          : error));
    } else if (typeof data.result?.raw_tx !== 'string' || !/^[0-9a-f]+$/i.test(data.result.raw_tx)) {
      reject(new Error('Transaction builder returned an invalid transaction'));
    } else resolve(data.result as BuiltTransaction);
  };
  worker.postMessage({ kind, input });
});
