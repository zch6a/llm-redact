import './isolate.ts';
// The release setup: notes come from the CHANGELOG, every workflow pins its actions and runs read-only by default.
import assert from "node:assert/strict";
import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";

// @ts-expect-error a plain .mjs script, no type declarations
import { notes } from "../scripts/release-notes.mjs";

const ROOT = fileURLToPath(new URL("..", import.meta.url));
const read = (name: string) => readFileSync(join(ROOT, name), "utf8").replace(/\r\n/g, "\n");

test("the current version has release notes in the CHANGELOG", () => {
  const version = JSON.parse(read("package.json")).version as string;
  const body = notes(read("CHANGELOG.md"), version) as string;
  assert.ok(body.length > 20);
  assert.ok(!body.includes(`## [${version}]`), "the heading itself is left out");
  assert.throws(() => notes(read("CHANGELOG.md"), "0.0.0-none"), /no section/);
  assert.equal(notes("## [2.0.0] — x\n\n- a\n\n## [1.0.0]\n- b\n", "2.0.0"), "- a");
});

test("workflows pin every action to a commit, keep no credentials and start read-only", () => {
  const dir = join(ROOT, ".github", "workflows");
  for (const file of readdirSync(dir)) {
    const yml = read(join(".github", "workflows", file));
    const uses = [...yml.matchAll(/^\s*-?\s*uses:\s*(\S+)/gm)].map((m) => m[1] ?? "");
    assert.ok(uses.length > 0, file);
    for (const u of uses) assert.match(u, /^[\w.-]+\/[\w.-]+@[0-9a-f]{40}$/, `${file}: ${u}`);
    for (const block of yml.split(/uses: actions\/checkout@/).slice(1)) assert.match(block, /^\S+[^\n]*\n\s+with:\n\s+persist-credentials: false/, `${file}: checkout keeps the token`);
    assert.match(yml, /^permissions:\n\s+contents: read$/m, `${file}: read-only by default`);
    // Commands only (`run:` lines), not comments that mention npm ci.
    for (const run of yml.split('\n').filter((l) => /^\s*-?\s*run:/.test(l))) assert.ok(!/npm ci(?! --ignore-scripts)/.test(run), `${file}: ${run.trim()}`);
  }
});
