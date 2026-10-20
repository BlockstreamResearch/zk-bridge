// @vitest-environment node
//
// The site publishes one instance record, ../instances/<INSTANCE.name>/, beside the page. These test the gates in
// vite.config.ts that keep it that way. The dev and preview servers serve that record's files and nothing else under
// instances/ (recordRequest, recordMiddleware). Builds and servers refuse a record that is missing, malformed or not
// INSTANCE's (checkRecord). config.js INSTANCE and the Pages workflow name the same record. They run on a scratch
// instances/ tree whose record is the fixture instance's, with the real public bootstrap as its bootstrap.hex.
import { mkdir, mkdtemp, rm, symlink, writeFile } from 'node:fs/promises';
import { readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { INSTANCE } from '@bridge/ui/config.js';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { checkRecord, recordMiddleware, recordRequest } from '../../vite.config';
import { BOOTSTRAP_TXID, ESPLORA, FIXTURE_INSTANCE, fixture } from '../dev/fixture';

const NAME = FIXTURE_INSTANCE.name;
const REPO_ROOT = new URL('../../../', import.meta.url);
let tmp = '';
let dir = ''; // the scratch instances/ directory
let record = ''; // its record, instances/<NAME>/
let bootstrapHex = '';

const pins = () => ({ ESCROW: FIXTURE_INSTANCE.escrow.slice(2), ESCROW_CODE_HASH: FIXTURE_INSTANCE.codeHash, ANCHOR: { slot: 1 } });
const manifest = () => ({
  sepolia: { escrow: FIXTURE_INSTANCE.escrow.slice(2), escrow_code_hash: FIXTURE_INSTANCE.codeHash },
  state_tree: { address: FIXTURE_INSTANCE.state },
});

/** Writes a complete, consistent record for the fixture instance at `at`, then applies `files` over it. */
async function writeRecord(at: string, files: Record<string, string> = {}) {
  await mkdir(path.join(at, 'lc_stores'), { recursive: true });
  const all = {
    'instance.json': JSON.stringify(pins()),
    'manifest.json': JSON.stringify(manifest()),
    'bootstrap.hex': bootstrapHex,
    'initial_state.json': '{}',
    'README.md': '# Record\n',
    'lc_stores/9.json': '{"head":9}',
    ...files,
  };
  for (const [file, text] of Object.entries(all)) await writeFile(path.join(at, file), text);
}

beforeAll(async () => {
  bootstrapHex = await (await fixture().env.fetch(`${ESPLORA}/tx/${BOOTSTRAP_TXID}/hex`)).text();
  tmp = await mkdtemp(path.join(tmpdir(), 'bridge-record-'));
  dir = path.join(tmp, 'instances');
  record = path.join(dir, NAME);
  await writeRecord(record, { '.secret.json': '{"key":"SECRET"}', 'notes.txt': 'not a record file' });
  // Another deployment's record, a file beside instances/, and a record kept outside instances/.
  await mkdir(path.join(dir, 'other'), { recursive: true });
  await writeFile(path.join(dir, 'other', 'manifest.json'), '{"other":true}');
  await writeFile(path.join(tmp, 'secret.json'), '{"key":"SECRET"}');
  await writeRecord(path.join(tmp, 'elsewhere'));
  // Symlinks: out of the record, to a non-record file type, within the record, and a record directory pointing out.
  await symlink(path.join(tmp, 'secret.json'), path.join(record, 'escape.json'));
  await symlink(path.join(record, 'notes.txt'), path.join(record, 'notes.json'));
  await symlink(path.join(record, 'manifest.json'), path.join(record, 'inner.json'));
  await symlink(path.join(tmp, 'elsewhere'), path.join(dir, 'linked'));
});

afterAll(async () => {
  if (tmp) await rm(tmp, { recursive: true, force: true });
});

describe('the record the dev and preview servers serve', () => {
  it.each([
    'manifest.json', 'instance.json', 'bootstrap.hex', 'README.md', 'lc_stores/9.json', 'manifest%2Ejson', 'inner.json',
  ])('serves the configured record\'s %s', async (file) => {
    const served = await recordRequest(`/instances/${NAME}/${file}`, NAME, dir);
    expect(served).toBe(file === 'inner.json' || file === 'manifest%2Ejson' ? path.join(await realRecord(), 'manifest.json') : path.join(await realRecord(), file));
  });

  it.each([
    ['another deployment\'s record', '/instances/other/manifest.json'],
    ['the configured name in another case', `/instances/${NAME.toUpperCase()}/manifest.json`],
    ['the instances directory', '/instances'],
    ['the instances directory listing', '/instances/'],
    ['the record directory', `/instances/${NAME}/`],
    ['a directory in the record', `/instances/${NAME}/lc_stores`],
    ['a missing file', `/instances/${NAME}/missing.json`],
    ['a dot-dot path out of the record', `/instances/${NAME}/../other/manifest.json`],
    ['a dot-dot path out of instances/', `/instances/${NAME}/../../secret.json`],
    ['an encoded dot-dot', `/instances/${NAME}/%2e%2e/%2e%2e/secret.json`],
    ['an encoded slash and dot-dot', `/instances/${NAME}/..%2f..%2fsecret.json`],
    ['a doubly encoded dot-dot', `/instances/${NAME}/%252e%252e/secret.json`],
    ['a backslash path', `/instances/${NAME}/..\\..\\secret.json`],
    ['an encoded backslash path', `/instances/${NAME}/..%5c..%5csecret.json`],
    ['a single-dot segment', `/instances/${NAME}/./manifest.json`],
    ['an empty segment', `/instances/${NAME}//manifest.json`],
    ['a NUL byte', `/instances/${NAME}/manifest.json%00.json`],
    ['a dotfile', `/instances/${NAME}/.secret.json`],
    ['a file of another kind', `/instances/${NAME}/notes.txt`],
    ['a symlink out of the record', `/instances/${NAME}/escape.json`],
    ['a symlink to a file of another kind', `/instances/${NAME}/notes.json`],
    ['an unreadable escape', `/instances/${NAME}/%e0%a4%a`],
    ['an unreadable escape in the prefix', '/instances%2f%e0%a4%a'],
  ])('refuses %s', async (_case, pathname) => {
    expect(await recordRequest(pathname, NAME, dir)).toBeNull();
  });

  it('refuses a record directory that is a symlink out of instances/', async () => {
    await writeFile(path.join(tmp, 'elsewhere', 'manifest.json'), JSON.stringify(manifest()));
    expect(await recordRequest('/instances/linked/manifest.json', 'linked', dir)).toBeNull();
  });

  it('serves no record at all while config.js names none, or names an invalid one', async () => {
    for (const name of [null, '', '..', 'a/b', 'Fixture', `${NAME}/..`]) {
      expect(await recordRequest(`/instances/${NAME}/manifest.json`, name, dir), String(name)).toBeNull();
    }
  });

  it('refuses everything while the instances directory is missing', async () => {
    expect(await recordRequest(`/instances/${NAME}/manifest.json`, NAME, path.join(tmp, 'nowhere'))).toBeNull();
  });

  it.each(['/', '/index.html', '/assets/index.js', '/src/main.tsx', '/instancesfoo/manifest.json', '/@vite/client', '/%e0%a4%a'])(
    'leaves %s to Vite', async (pathname) => {
      expect(await recordRequest(pathname, NAME, dir)).toBe('pass');
    },
  );
});

interface Answer {
  passed: boolean;
  status?: number;
  headers?: Record<string, string>;
  body?: string;
}

/** One request through recordMiddleware, with a minimal request and response. */
function request(url: string, name: string | null = NAME): Promise<Answer> {
  return new Promise((resolve) => {
    const headers: Record<string, string> = {};
    const res = {
      statusCode: 0,
      setHeader(k: string, v: string) {
        headers[k.toLowerCase()] = v;
      },
      end(body?: Buffer | string) {
        resolve({ passed: false, status: this.statusCode, headers, body: body === undefined ? '' : String(body) });
      },
    };
    type Middleware = ReturnType<typeof recordMiddleware>;
    recordMiddleware(name, dir)({ url } as unknown as Parameters<Middleware>[0], res as unknown as Parameters<Middleware>[1], () => resolve({ passed: true }));
  });
}

describe('the instance-record middleware', () => {
  it('sends a record file as data the browser will not sniff, uncached', async () => {
    const a = await request(`/instances/${NAME}/manifest.json`);
    expect(a).toMatchObject({ passed: false, status: 200, body: JSON.stringify(manifest()) });
    expect(a.headers).toMatchObject({ 'content-type': 'application/json; charset=utf-8', 'x-content-type-options': 'nosniff', 'cache-control': 'no-store' });
    expect((await request(`/instances/${NAME}/bootstrap.hex`)).headers?.['content-type']).toBe('text/plain; charset=utf-8');
  });

  it('ignores the query string, which cannot carry a path', async () => {
    const a = await request(`/instances/${NAME}/manifest.json?file=../../secret.json#../../secret.json`);
    expect(a).toMatchObject({ status: 200, body: JSON.stringify(manifest()) });
  });

  it.each([
    `/instances/${NAME}/../../secret.json`, `/instances/${NAME}/%2e%2e/%2e%2e/secret.json`, `/instances/${NAME}/escape.json`,
    `/instances/${NAME}/.secret.json`, '/instances/other/manifest.json', `/instances/${NAME}/missing.json`, '/instances/',
  ])('answers %s with a bare 404 that reveals nothing', async (url) => {
    const a = await request(url);
    expect(a).toEqual({ passed: false, status: 404, headers: {}, body: '' });
  });

  it('answers every record path 404 while no instance is configured', async () => {
    expect(await request(`/instances/${NAME}/manifest.json`, null)).toEqual({ passed: false, status: 404, headers: {}, body: '' });
  });

  it('passes the page\'s own files on to Vite', async () => {
    expect(await request('/assets/index.js')).toEqual({ passed: true });
    expect(await request('/')).toEqual({ passed: true });
  });
});

describe('the record a build or server starts with', () => {
  /** A scratch instances/ directory holding the fixture instance's record with `files` replaced. */
  async function variant(files: Record<string, string>) {
    const at = await mkdtemp(path.join(tmp, 'variant-'));
    await writeRecord(path.join(at, NAME), files);
    return at;
  }

  it('is accepted when it pins exactly INSTANCE', async () => {
    await expect(checkRecord(FIXTURE_INSTANCE, dir)).resolves.toMatchObject({ name: NAME, record: `instances/${NAME}/`, escrow: FIXTURE_INSTANCE.escrow });
  });

  it('is not needed, and not read, while no instance is configured', async () => {
    await expect(checkRecord(null, path.join(tmp, 'nowhere'))).resolves.toBeNull();
  });

  it('refuses an invalid INSTANCE before reading any record', async () => {
    await expect(checkRecord({ ...FIXTURE_INSTANCE, codeHash: 'not hex' }, dir)).rejects.toThrow(/codeHash/);
    await expect(checkRecord({ ...FIXTURE_INSTANCE, name: '../other' }, dir)).rejects.toThrow(/instance name/);
  });

  it('fails closed when the record is missing', async () => {
    await expect(checkRecord(FIXTURE_INSTANCE, path.join(tmp, 'nowhere'))).rejects.toThrow(`instances/${NAME}/instance.json is missing`);
    await expect(checkRecord({ ...FIXTURE_INSTANCE, name: 'other' }, dir)).rejects.toThrow('instances/other/instance.json is missing');
  });

  it.each([
    ['instance.json', 'SECRET-not-json', 'instances/fixture-instance/instance.json is not JSON'],
    ['manifest.json', '["SECRET"]', 'instances/fixture-instance/manifest.json is not a JSON object'],
    ['manifest.json', 'null', 'instances/fixture-instance/manifest.json is not a JSON object'],
    ['bootstrap.hex', 'SECRETzz', 'instances/fixture-instance/bootstrap.hex is not a Liquid transaction'],
  ])('fails closed on a malformed %s, without quoting it', async (file, text, message) => {
    const error = await checkRecord(FIXTURE_INSTANCE, await variant({ [file]: text })).catch((e: Error) => e);
    expect(error).toBeInstanceOf(Error);
    expect((error as Error).message).toBe(message);
    expect(String((error as Error).cause ?? '')).not.toContain('SECRET');
  });

  it.each([
    ['instance.json', { ...pins(), ESCROW: '11'.repeat(20) }, 'instance.json ESCROW'],
    ['instance.json', { ...pins(), ESCROW_CODE_HASH: 'cd'.repeat(32) }, 'instance.json ESCROW_CODE_HASH'],
    ['manifest.json', { ...manifest(), sepolia: { ...manifest().sepolia, escrow: '11'.repeat(20) } }, 'manifest.json sepolia.escrow'],
    ['manifest.json', { ...manifest(), sepolia: { ...manifest().sepolia, escrow_code_hash: 'cd'.repeat(32) } }, 'manifest.json sepolia.escrow_code_hash'],
    ['manifest.json', { ...manifest(), state_tree: {} }, 'manifest.json state_tree.address'],
  ])('refuses a %s that pins another deployment', async (file, content, field) => {
    await expect(checkRecord(FIXTURE_INSTANCE, await variant({ [file]: JSON.stringify(content) }))).rejects.toThrow(
      new RegExp(`is not its record instances/${NAME}/: ${field} differ`),
    );
  });

  it('refuses a bootstrap.hex that is another transaction', async () => {
    // The same bootstrap with locktime 1: a readable transaction with another txid.
    const other = bootstrapHex.trim().slice(0, -8) + '01000000';
    await expect(checkRecord(FIXTURE_INSTANCE, await variant({ 'bootstrap.hex': other }))).rejects.toThrow(/the txid of bootstrap.hex differ/);
  });
});

describe('the published deployment', () => {
  const workflow = readFileSync(new URL('.github/workflows/pages.yml', REPO_ROOT), 'utf8');
  const RECORD = workflow.match(/^\s+RECORD: ([^\s#]+)\s*$/m)?.[1];

  it('the Pages workflow publishes one record, by a valid instance name', () => {
    expect(RECORD).toMatch(/^[a-z0-9-]+$/);
  });

  it.skipIf(INSTANCE === null)('config.js INSTANCE is the record Pages publishes, and that record pins it', async () => {
    expect(INSTANCE!.name).toBe(RECORD);
    await expect(checkRecord(INSTANCE)).resolves.toMatchObject({ name: INSTANCE!.name });
  });
});

/** The scratch record's real path (tmpdir may itself be a symlink, as /var is on macOS). */
async function realRecord() {
  const { realpath } = await import('node:fs/promises');
  return realpath(record);
}
