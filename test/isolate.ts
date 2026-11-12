/**
 * Loaded before every test file (`node --import ./test/isolate.ts --test`, and imported by each test): the home
 * folder and every place llm-redact keeps its key and vault point into a new, empty temp folder. A test that
 * forgets to pass a path then uses a throwaway key, never the real one of whoever runs the tests.
 */
import { mkdirSync, mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const KEY = 'LLM_REDACT_TEST_HOME';

if (!process.env[KEY]) {
  const home = mkdtempSync(join(tmpdir(), 'lr-test-home-'));
  for (const sub of ['AppData/Roaming', 'AppData/Local', '.config']) mkdirSync(join(home, sub), { recursive: true });
  Object.assign(process.env, {
    [KEY]: home,
    HOME: home,
    USERPROFILE: home,
    APPDATA: join(home, 'AppData', 'Roaming'),
    LOCALAPPDATA: join(home, 'AppData', 'Local'),
    XDG_CONFIG_HOME: join(home, '.config'),
  });
  // A proxy setting must not send a test's request anywhere but 127.0.0.1.
  for (const name of ['LLM_REDACT_HOME', 'HTTP_PROXY', 'HTTPS_PROXY', 'http_proxy', 'https_proxy', 'ALL_PROXY', 'all_proxy']) delete process.env[name];
  // Child processes (the CLI under test) inherit all of this; only the process that made the folder removes it.
  process.on('exit', () => rmSync(home, { recursive: true, force: true }));
}

export const TEST_HOME = process.env[KEY] as string;
