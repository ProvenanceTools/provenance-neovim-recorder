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
let reconcileWitnesses;
try {
  const mod = await import(url.pathToFileURL(analysisCoreEntry).href);
  loadBundle = mod.loadBundle;
  runValidation = mod.runValidation;
  reconcileWitnesses = mod.reconcileWitnesses;
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

// ---------------------------------------------------------------------------
// PEER WITNESSING (Tier 4.1) — the writer half, checked against the REAL
// reader.
//
// The bundle carries two sessions: the student's, and a partner's `.slog`
// pulled into `.provenance/` mid-session (see produce_bundle.lua step 3b). The
// student's chain must therefore contain a `peer.observed` that the monorepo's
// own `reconcileWitnesses` — not this repo's port of anything — resolves to
// `corroborated`.
//
// This is the only place the two halves meet. `peer-observed.json` pins the
// BYTES the writer produces; nothing in this repo can prove those bytes are
// read the way they were meant to be. A witness that narrowed cleanly and then
// reconciled to `indeterminate` — or, worse, to a verdict that is evidence —
// would pass every test in provnvim and still be wrong.
//
// `corroborated` specifically, because it is the CLEAN case: the witnessed log
// is present, reaches the witnessed seq, and the hash there matches. Anything
// else here would mean this recorder had written a witness against an innocent
// partner whose log was sitting right beside it in the same archive.
// ---------------------------------------------------------------------------
let witnessFailure = null;
if (typeof reconcileWitnesses !== 'function') {
  witnessFailure = 'analysis-core does not export reconcileWitnesses';
} else {
  const w = reconcileWitnesses(result.value);
  console.log('\nreconcileWitnesses:');
  console.log(
    JSON.stringify(
      {
        witnesses: w.witnesses.map((r) => ({
          verdict: r.verdict,
          authority: r.witness.authority,
          file: r.witness.payload.file,
          state: r.witness.payload.state,
          seqHigh: r.witness.payload.seq_high,
          matchedSessionId: r.matchedSessionId,
          detail: r.detail,
        })),
        excluded: w.excluded.map((e) => ({ reason: e.reason, file: e.witness.payload.file })),
        malformed: w.malformed,
      },
      null,
      2,
    ),
  );

  if (w.malformed.length > 0) {
    // A payload the real reader cannot narrow. This is the failure mode the
    // shared vectors exist to prevent, and it is fatal here.
    witnessFailure = `${w.malformed.length} malformed witness(es): ${w.malformed
      .map((m) => m.detail)
      .join('; ')}`;
  } else if (w.witnesses.length === 0) {
    witnessFailure =
      'no peer.observed witness reached the analyzer — the writer half did not emit, ' +
      'or the observation never landed in the sealed .slog';
  } else {
    const corroborated = w.witnesses.filter((r) => r.verdict === 'corroborated');
    if (corroborated.length === 0) {
      witnessFailure =
        'no witness reconciled to `corroborated`; got ' +
        w.witnesses.map((r) => r.verdict).join(', ');
    }
    // A self-witness is circular and the writer must not produce one, even
    // though the reader excludes it anyway.
    const selfWitness = w.excluded.filter((e) => e.reason === 'self_witness');
    if (selfWitness.length > 0) {
      witnessFailure =
        `${selfWitness.length} SELF-witness(es) emitted: a chain cannot corroborate itself, ` +
        'and the reader excluding one is not a licence for the writer to produce it';
    }
  }
}

const REQUIRED_PASS = ['manifest_sig', 'session_binding', 'chain_integrity'];

const failedRequired = REQUIRED_PASS.filter((id) => {
  const check = report.checks.find((c) => c.id === id);
  return !check || check.status !== 'pass';
});

if (report.overall === 'fail' || failedRequired.length > 0 || witnessFailure !== null) {
  console.error('\nGATE FAILED.');
  if (witnessFailure !== null) {
    console.error(`  peer witnessing: ${witnessFailure}`);
  }
  if (report.overall === 'fail') {
    console.error(`  overall = 'fail'`);
  }
  for (const id of failedRequired) {
    const check = report.checks.find((c) => c.id === id);
    console.error(`  required check '${id}' status = ${check ? check.status : 'MISSING'}${check && check.detail ? ` (${check.detail})` : ''}`);
  }
  process.exit(3);
}

console.log(
  `\nGATE PASSED. overall=${report.overall}; manifest_sig/session_binding/chain_integrity all pass; ` +
    `peer witnessing reconciles as corroborated.`,
);
process.exit(0);
