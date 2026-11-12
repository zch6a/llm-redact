// The release notes for a version: its section of CHANGELOG.md, printed for `gh release create --notes-file`.
//   node scripts/release-notes.mjs 1.2.0
import { readFileSync } from "node:fs";
import { pathToFileURL } from "node:url";

/** @param {string} changelog @param {string} version */
export function notes(changelog, version) {
  const lines = changelog.replace(/\r\n/g, "\n").split("\n");
  const heading = (/** @type {string} */ l) => l.startsWith(`## [${version}]`) || l.startsWith(`## ${version} `) || l === `## ${version}`;
  const start = lines.findIndex(heading);
  if (start < 0) throw new Error(`CHANGELOG.md has no section for ${version}`);
  const end = lines.findIndex((l, i) => i > start && l.startsWith("## "));
  const body = lines.slice(start + 1, end < 0 ? undefined : end).join("\n").trim();
  if (!body) throw new Error(`CHANGELOG.md's section for ${version} is empty`);
  return body;
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const version = (process.argv[2] ?? "").replace(/^v/, "");
  if (!version) throw new Error("usage: node scripts/release-notes.mjs <version>");
  process.stdout.write(`${notes(readFileSync(new URL("../CHANGELOG.md", import.meta.url), "utf8"), version)}\n`);
}
