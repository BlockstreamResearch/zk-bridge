// Build and test configuration.
//
// The bridge's rules live in ../ui/lib and its one published instance in ../ui/config.js. This app imports both
// read-only through the `@bridge/ui` alias. TypeScript sees them through the declarations in src/contracts/ui/.
//
// `base: './'` makes every asset URL relative, so the build works at a GitHub Pages project subpath
// (https://<owner>.github.io/<repo>/) as well as at a domain root, with no rebuild.
//
// The site publishes one instance record beside the page, instances/<name>/ for config.js INSTANCE, and no other
// (.github/workflows/pages.yml). `vite build`, `vite` and `vite preview` refuse to start unless that record exists
// and pins exactly INSTANCE (checkRecord), and the two servers serve that record's files and nothing else under
// instances/ (recordRequest). src/publication/instance-record.test.ts tests both.
import { readFile, realpath, stat } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import react from '@vitejs/plugin-react';
import type { Connect, Plugin } from 'vite';
import { defineConfig } from 'vitest/config';

const here = path.dirname(fileURLToPath(import.meta.url));
const uiDir = path.resolve(here, '../ui');
const instancesDir = path.resolve(here, '../instances');

/** A module of ../ui, read as Node reads it: the config is not bundled through the `@bridge/ui` alias. */
// eslint-disable-next-line @typescript-eslint/no-explicit-any
const uiModule = (file: string): Promise<any> => import(pathToFileURL(path.join(uiDir, file)).href);

/** An instance name, as config.js parseInstance requires it: the record's directory under instances/. */
const NAME = /^[a-z0-9-]+$/;
/** One path segment of a record file: letters, digits, '-', '_' and '.', not starting with '.' (no '..', no dotfile). */
const SEGMENT = /^[A-Za-z0-9_-][A-Za-z0-9._-]*$/;
/** The kinds of file a record holds and the page reads or links: JSON pins and stores, transaction hex, its README. */
const SERVED = /\.(?:json|hex|md)$/;
const TYPES: Record<string, string> = {
  '.json': 'application/json; charset=utf-8',
  '.hex': 'text/plain; charset=utf-8',
  '.md': 'text/plain; charset=utf-8',
};

/**
 * What the dev and preview servers answer for the request path `pathname` (no query): 'pass' for a path outside
 * instances/, which Vite serves as usual; otherwise the real path of the file of record `name` to send, or null for
 * 404. Every path under instances/ is answered here, never passed on, so no other record, no file outside the
 * record (by `..`, an encoded `..`, a backslash or a symlink), no dotfile, no directory and no other kind of file is
 * served from it. `dir` is the instances directory (../instances).
 */
export async function recordRequest(pathname: string, name: string | null, dir = instancesDir): Promise<'pass' | string | null> {
  let decoded: string;
  try {
    decoded = decodeURIComponent(pathname);
  } catch {
    // Unreadable escapes: refused under instances/, left to Vite elsewhere.
    return /^\/instances(?:\/|%2f|$)/i.test(pathname) ? null : 'pass';
  }
  if (decoded !== '/instances' && !decoded.startsWith('/instances/')) return 'pass';
  if (!name || !NAME.test(name)) return null;
  // Exact, case-sensitive: a case-insensitive file system would otherwise serve /instances/NAME/ as the record.
  const prefix = `/instances/${name}/`;
  if (!decoded.startsWith(prefix)) return null;
  const segments = decoded.slice(prefix.length).split('/');
  if (!segments.every((s) => SEGMENT.test(s)) || !SERVED.test(decoded)) return null;
  try {
    const realDir = await realpath(dir);
    const root = await realpath(path.join(dir, name));
    const file = await realpath(path.join(root, ...segments));
    // The record directory and the file must both stay inside, after following any symlink.
    if (!root.startsWith(realDir + path.sep) || !file.startsWith(root + path.sep) || !SERVED.test(file)) return null;
    return (await stat(file)).isFile() ? file : null;
  } catch {
    return null;
  }
}

/** recordRequest as connect middleware, for record `name`; a refusal is a bare 404 that names nothing. */
export function recordMiddleware(name: string | null, dir = instancesDir): Connect.NextHandleFunction {
  const refuse = (res: Parameters<Connect.NextHandleFunction>[1]) => {
    res.statusCode = 404;
    res.end();
  };
  return (req, res, next) => {
    // The raw request path: new URL() would resolve dot segments before they could be refused.
    const pathname = (req.url ?? '/').split(/[?#]/, 1)[0];
    recordRequest(pathname, name, dir).then(async (file) => {
      if (file === 'pass') return next();
      if (!file) return refuse(res);
      const body = await readFile(file);
      res.statusCode = 200;
      res.setHeader('content-type', TYPES[path.extname(file)]);
      res.setHeader('x-content-type-options', 'nosniff');
      res.setHeader('cache-control', 'no-store');
      res.end(body);
    }).catch(() => refuse(res));
  };
}

/**
 * Checks that config.js INSTANCE (`raw`) is its published record, ../instances/<name>/, as the site will publish it:
 * instance.json, manifest.json and bootstrap.hex exist and parse, and pin exactly INSTANCE's escrow, code hash, state
 * address and bootstrap txid. Returns the parsed instance, or null for no instance (nothing to check). Throws on an
 * invalid INSTANCE, a missing or malformed file, or any mismatch. Messages name the file and the field, never a
 * file's content.
 */
export async function checkRecord(raw: unknown, dir = instancesDir) {
  const { parseInstance } = await uiModule('config.js');
  const inst = parseInstance(raw);
  if (!inst) return null;
  const at = (file: string) => `instances/${inst.name}/${file}`;
  const read = async (file: string) => {
    try {
      return await readFile(path.join(dir, inst.name, file), 'utf8');
    } catch {
      throw new Error(`${at(file)} is missing: config.js INSTANCE names a record this checkout does not have`);
    }
  };
  const object = async (file: string) => {
    const text = await read(file);
    let value: unknown;
    // No cause: a JSON parser's message quotes the text it read.
    try {
      value = JSON.parse(text);
    } catch {
      throw new Error(`${at(file)} is not JSON`);
    }
    if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error(`${at(file)} is not a JSON object`);
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    return value as Record<string, any>;
  };
  const pins = await object('instance.json');
  const manifest = await object('manifest.json');
  const hex = (await read('bootstrap.hex')).trim();
  const [{ hexToBytes }, { displayHex, parseTransaction }] = await Promise.all([uiModule('lib/bytes.js'), uiModule('lib/elements.js')]);
  let txid: string;
  try {
    txid = displayHex(parseTransaction(hexToBytes(hex)).txid);
  } catch {
    throw new Error(`${at('bootstrap.hex')} is not a Liquid transaction`);
  }
  const escrow = inst.escrow.slice(2);
  const wrong = ([
    [pins.ESCROW, escrow, 'instance.json ESCROW'],
    [pins.ESCROW_CODE_HASH, inst.codeHash, 'instance.json ESCROW_CODE_HASH'],
    [manifest.sepolia?.escrow, escrow, 'manifest.json sepolia.escrow'],
    [manifest.sepolia?.escrow_code_hash, inst.codeHash, 'manifest.json sepolia.escrow_code_hash'],
    [manifest.state_tree?.address, inst.state, 'manifest.json state_tree.address'],
    [txid, inst.bootstrap, 'the txid of bootstrap.hex'],
  ] as const).filter(([got, want]) => got !== want).map(([, , what]) => what);
  if (wrong.length) throw new Error(`config.js INSTANCE is not its record instances/${inst.name}/: ${wrong.join(', ')} differ`);
  return inst as { name: string; record: string; escrow: string; codeHash: string; bootstrap: string; state: string };
}

/**
 * Serves the published instance record at instances/<name>/ in `vite` and `vite preview`, as Pages publishes it:
 * only the record config.js INSTANCE names, read in place from ../instances/<name>/. The claim and update panels read
 * it there. The build itself never contains a record: the Pages workflow stages it beside the build.
 *
 * Outside tests and the fixture mode, the record must be INSTANCE's (checkRecord) or Vite stops, so no build, dev or
 * preview server runs for a record that is missing, malformed or another deployment's. Tests check records
 * themselves; the fixture mode's stand-in instance has no record, so it serves none.
 */
function instanceRecord(): Plugin {
  let name: string | null = null;
  const serve: Connect.NextHandleFunction = (req, res, next) => recordMiddleware(name)(req, res, next);
  return {
    name: 'bridge-instance-record',
    async configResolved(config) {
      if (config.mode === 'fixture' || config.mode === 'test') return;
      const { INSTANCE } = await uiModule('config.js');
      name = (await checkRecord(INSTANCE))?.name ?? null;
    },
    configureServer(server) {
      server.middlewares.use(serve);
    },
    configurePreviewServer(server) {
      server.middlewares.use(serve);
    },
  };
}

export default defineConfig({
  base: './',
  plugins: [react(), instanceRecord()],
  resolve: {
    alias: { '@bridge/ui': uiDir },
  },
  server: {
    // The dev server may read ../ui (the shared modules) and this directory; nothing else outside it, so ../instances
    // is reachable only through instanceRecord's middleware, never through /@fs/.
    fs: { allow: [here, uiDir] },
  },
  build: {
    outDir: 'dist',
    emptyOutDir: true,
    sourcemap: true,
  },
  test: {
    environment: 'jsdom',
    setupFiles: ['./src/test/setup.ts'],
    include: ['src/**/*.test.{ts,tsx}'],
    restoreMocks: true,
  },
});
