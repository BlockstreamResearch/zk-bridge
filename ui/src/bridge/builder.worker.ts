// The compiler and covenant interpreter run off the UI thread. Each build gets a fresh worker,
// so cancellation and malformed inputs cannot leave an interpreter behind for the next request.
interface Request {
  kind: 'update' | 'claim';
  input: Record<string, unknown>;
}

self.onmessage = async ({ data }: MessageEvent<Request>) => {
  try {
    const input = JSON.stringify(data.input);
    let result: string;
    if (data.kind === 'update') {
      const module = await import('../../../target/browser-builders/update/update.js');
      await module.default();
      result = module.build_update(input);
    } else if (data.kind === 'claim') {
      const module = await import('../../../target/browser-builders/claim/claim.js');
      await module.default();
      result = module.build_claim(input);
    } else {
      throw new Error('Unknown transaction type');
    }
    self.postMessage({ result: JSON.parse(result) });
  } catch (error) {
    self.postMessage({ error: error instanceof Error ? error.message : String(error) });
  }
};
