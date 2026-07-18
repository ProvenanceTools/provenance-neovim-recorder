#!/usr/bin/env node
// Plan 4 Task 10 (SUCCESS CRITERION) — loads a sealed bundle .zip produced by
// this repo's Neovim recorder into the REAL Provenance monorepo's
// analysis-core (loadBundle + runValidation), and checks it against the
// plan's gate: overall !== 'fail', and the manifest_sig, session_binding,
// chain_integrity checks are all 'pass'.
//
// Usage: node scripts/verify-bundle-with-analyzer.mjs <path-to-bundle.zip>
// Env:   PROVENANCE_MONOREPO (default: /Users/aaryanmehta/projects/provenance)

import fs from 'node:fs';
import path from 'node:path';
import url from 'node:url';

const zipPath = process.argv[2];
if (!zipPath) {
  console.error('usage: verify-bundle-with-analyzer.mjs <path-to-bundle.zip>');
  process.exit(2);
}

const monorepo = process.env.PROVENANCE_MONOREPO || '/Users/aaryanmehta/projects/provenance';
const analysisCoreEntry = path.join(monorepo, 'packages/analysis-core/dist/index.js');

let loadBundle;
let runValidation;
try {
  const mod = await import(url.pathToFileURL(analysisCoreEntry).href);
  loadBundle = mod.loadBundle;
  runValidation = mod.runValidation;
} catch (e) {
  console.error(`Failed to import analysis-core from ${analysisCoreEntry}:`);
  console.error(e);
  process.exit(2);
}

if (typeof loadBundle !== 'function' || typeof runValidation !== 'function') {
  console.error('analysis-core did not export loadBundle/runValidation as expected.');
  process.exit(2);
}

const bytes = fs.readFileSync(zipPath);
const arrayBuffer = bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength);

const result = await loadBundle(arrayBuffer, path.basename(zipPath), () => '2026-05-19T00:00:00.000Z');

if (!result.ok) {
  console.error('loadBundle FAILED:');
  console.error(JSON.stringify(result.error, null, 2));
  process.exit(2);
}

const report = await runValidation(result.value);

console.log(JSON.stringify(report, null, 2));

const REQUIRED_PASS = ['manifest_sig', 'session_binding', 'chain_integrity'];

const failedRequired = REQUIRED_PASS.filter((id) => {
  const check = report.checks.find((c) => c.id === id);
  return !check || check.status !== 'pass';
});

if (report.overall === 'fail' || failedRequired.length > 0) {
  console.error('\nGATE FAILED.');
  if (report.overall === 'fail') {
    console.error(`  overall = 'fail'`);
  }
  for (const id of failedRequired) {
    const check = report.checks.find((c) => c.id === id);
    console.error(`  required check '${id}' status = ${check ? check.status : 'MISSING'}${check && check.detail ? ` (${check.detail})` : ''}`);
  }
  process.exit(3);
}

console.log(`\nGATE PASSED. overall=${report.overall}; manifest_sig/session_binding/chain_integrity all pass.`);
process.exit(0);
