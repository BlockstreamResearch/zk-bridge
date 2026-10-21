// @vitest-environment node
//
// The Pages workflow (.github/workflows/pages.yml) publishes this app's production build and one instance record,
// and nothing else. These read the workflow itself, so an edit that drops or reorders one of its gates, or a rename
// that would make its fixture check look for a name no longer used, fails here rather than on Pages.
import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { FIXTURE_INSTANCE } from '../dev/fixture';

const workflow = readFileSync(new URL('../../../.github/workflows/pages.yml', import.meta.url), 'utf8');
const scripts = JSON.parse(readFileSync(new URL('../../package.json', import.meta.url), 'utf8')).scripts as Record<string, string>;

/** The workflow's steps in order, each its text from its `- ` to the next step. */
const steps = workflow.split(/^ {6}- /m).slice(1);

/** The step named `name`. */
function step(name: string) {
  const found = steps.find((s) => s.startsWith(`name: ${name}\n`));
  if (!found) throw new Error(`.github/workflows/pages.yml has no step named "${name}"`);
  return found;
}

const at = (name: string) => steps.indexOf(step(name));

describe('the Pages workflow', () => {
  it('checks the published record and its live pin before it builds or tests anything', () => {
    const gate = step('Check the published instance record');
    expect(gate).toContain('instances/$RECORD/instance.json');
    expect(gate).toContain('INSTANCE?.name !== record');
    expect(gate).toContain('import("./bridge-core/test/live-state.js")');
    expect(gate).toContain('Object.hasOwn(LIVE, record)');
    expect(steps.findIndex((s) => /^\s+run: /m.test(s))).toBe(at('Check the published instance record'));
  });

  it('publishes only from the published repository and branch, and only to the published site', () => {
    const gate = step('Check the published instance record');
    expect(gate).toContain('"https://github.com/" + process.env.GITHUB_REPOSITORY');
    expect(gate).toContain('here !== PUBLISHED.repo || process.env.GITHUB_REF !== "refs/heads/" + PUBLISHED.branch');
    const address = step('Check the Pages address');
    expect(address).toContain('BASE_URL: ${{ steps.pages.outputs.base_url }}');
    expect(address).toContain('!== PUBLISHED.site');
    expect(steps[at('Check the Pages address') - 1]).toMatch(/^uses: actions\/configure-pages@[0-9a-f]{40} # v5\n\s+id: pages\n/);
    expect(at('Check the Pages address')).toBeLessThan(at('Upload static site'));
  });

  it('stages the production build its checks produced', () => {
    expect(workflow).toContain('uses: ./.github/workflows/ci.yml');
    expect(workflow).toContain('needs: ci');
    expect(step('Build the React interface')).toContain('npm --prefix ui run build');
    expect(scripts.check).toMatch(/&& npm run build$/);
    expect(scripts.build).toBe('vite build');
    expect(workflow).not.toMatch(/--mode|build:fixture|dist-fixture/);
    expect(at('Build the React interface')).toBeLessThan(at('Stage the page and its instance record'));
  });

  it('publishes the build and the one record, and nothing else', () => {
    const stage = step('Stage the page and its instance record');
    expect(stage).toContain('site="$RUNNER_TEMP/site"');
    expect(stage.match(/\bcp /g)).toHaveLength(2);
    expect(stage).toContain('cp -R ui/dist/. "$site/"');
    expect(stage).toContain('cp -R "instances/$RECORD" "$site/instances/"');
    expect(stage).toContain('[ "$(ls -A "$site/instances")" = "$RECORD" ]');
    expect(stage).toContain('find "$site" -type l');
    expect(step('Upload static site')).toContain('path: ${{ runner.temp }}/site');
  });

  it('refuses a build that contains the fixture instance, by its name', () => {
    expect(step('Stage the page and its instance record')).toContain(`'${FIXTURE_INSTANCE.name}' "$site"`);
  });

  it('checks the staged copy of the record before upload', () => {
    expect(step('Check the staged instance record')).toContain('RECORD_DIR="$RUNNER_TEMP/site/instances/$RECORD"');
    expect(at('Check the staged instance record')).toBeLessThan(at('Upload static site'));
  });
});
