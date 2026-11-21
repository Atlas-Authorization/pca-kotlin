#!/usr/bin/env node
// Kotlin merge gate, dead-minion rule (same rule as Go/Python): a ledgered EQUIVALENT mutant that a test KILLED in this run is
// evidence of a nondeterministic killer, not a gap in the ledger. mutation-merge.mjs fails such an entry as STALE; this wraps it:
//   node stale-killed.mjs <merge.log> <reports dir> <merge exit code>      (exit code 0: nothing to do)
// Fails (exit 1) unless the merge failed ONLY by STALE ("no survivor at this site") lines, none of its survivors was unlisted, the
// checker's own problem count equals the excused stale lines (any other error shape fails), and every excused line is a mutant that
// a shard recorded as KILLED (killed-equiv-<k>.json: same file, mutant, source line, occurrence and function). A stale entry whose
// mutant was not generated, or was generated but did not die, still fails. Each excused entry is a ::notice:: naming it.
//   node stale-killed.mjs --selftest        the cases on a small fixture (the merge runs it first: a control that must hold)
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

// `<crate>/<file>:<line>[ (#n)][ in <fn>]: <mutant, 90 chars> | <source line, 70 chars>`; both halves can contain ' | ', so the tail
// is kept whole and compared with the one built from each killed record.
const STALE = /^STALE \(no survivor at this site; killed or changed, remove it\): ([^/\s]+)\/(\S+?\.kt):(\d+)(?: \(#(\d+)\))?(?: in (.+?))?: (.*)$/;
// an equivalent entry that covers M identical mutants while only N < M survived: the other M - N were killed this run
const MULT = /^multiplicity: (\d+) identical survivor\(s\) at this site, entry covers (\d+): ([^/\s]+)\/(\S+?\.kt):(\d+)(?: \(#(\d+)\))?(?: in (.+?))?: (.*)$/;
const FAILRE = /^FAIL: (\d+) problem\(s\); \d+ entries$/;

export function judge(log, killed, code) {
  if (code === 0) return { ok: true, notices: [], errors: [] };
  const lines = log.split('\n').map((l) => l.replace(/^\S+Z /, '').replace(/^##\[error\]/, '')); // CI timestamps / annotations
  const stale = lines.map((l) => STALE.exec(l)).filter(Boolean);
  const mult = lines.map((l) => MULT.exec(l)).filter(Boolean);
  const tally = /unlisted survivors: (\d+); stale entries: (\d+)/.exec(log);
  const errors = [];
  if (!tally) errors.push('no ledger tally in the merge log (the merge failed before the ledger check)');
  else {
    if (Number(tally[1]) !== 0) errors.push(`${tally[1]} unlisted survivor(s)`);
    if (Number(tally[2]) !== stale.length || stale.length + mult.length === 0) errors.push(`${tally[2]} stale entr(ies) but ${stale.length} excusable STALE line(s)`);
  }
  // the checker prints other error shapes too (multiplicity, UNPLACEABLE SURVIVOR, source file gone, ...): whatever it prints, its own
  // count of problems must be exactly the stale lines excused here
  const failLine = lines.map((l) => FAILRE.exec(l)).find(Boolean);
  if (!failLine) errors.push('no "FAIL: N problem(s)" count in the merge log');
  else if (Number(failLine[1]) !== stale.length + mult.length) errors.push(`the checker counts ${failLine[1]} problem(s) but ${stale.length} stale and ${mult.length} multiplicity line(s) are excused: something else failed`);
  const bad = lines.filter((l) => /^(STALE|AMBIGUOUS|UNLISTED|duplicate|bad |fn '|multiplicity|FAIL|UNPLACEABLE)/.test(l) && !STALE.test(l) && !MULT.test(l) && !FAILRE.test(l));
  for (const b of bad) errors.push(b);
  const notices = [];
  for (const m of stale) {
    const [, , file, lineno, occ, fn, tail] = m;
    const hit = killed.find((k) => k.file === file && `${String(k.mutant).slice(0, 90)} | ${String(k.line || '').trim().slice(0, 70)}` === tail
      && (occ === undefined || String(k.occurrence) === occ) && (fn === undefined || k.fn === fn));
    if (hit) notices.push(`::notice::equivalent entry killed this run (nondeterministic killer): ${file}:${lineno}${fn ? ` in ${fn}` : ''}: ${tail}`);
    else errors.push(`stale entry, no such mutant killed this run: ${file}:${lineno}: ${tail}`);
  }
  for (const m of mult) {
    const [, n, cov, , file, lineno, occ, fn, tail] = m;
    const k = killed.filter((x) => x.file === file && `${String(x.mutant).slice(0, 90)} | ${String(x.line || '').trim().slice(0, 70)}` === tail
      && (occ === undefined || String(x.occurrence) === occ) && (fn === undefined || x.fn === fn)).length;
    const short = Number(cov) - Number(n);
    if (short > 0 && k >= short) notices.push(`::notice::equivalent entry covers ${cov}, ${n} survived and ${k} were killed this run (nondeterministic killer): ${file}:${lineno}${fn ? ` in ${fn}` : ''}: ${tail}`);
    else errors.push(`multiplicity: entry covers ${cov}, ${n} survived, ${k} killed this run (need ${short}): ${file}:${lineno}: ${tail}`);
  }
  return { ok: errors.length === 0, notices, errors };
}

export function loadKilled(dir) {
  const out = [];
  const walk = (d) => { for (const e of fs.readdirSync(d, { withFileTypes: true })) { const p = path.join(d, e.name); if (e.isDirectory()) walk(p); else if (/^killed-equiv-\d+\.json$/.test(e.name)) out.push(...JSON.parse(fs.readFileSync(p, 'utf8'))); } };
  if (dir && fs.existsSync(dir)) walk(dir);
  return out;
}

function selftest() {
  const F = 'src/main/kotlin/net/atlasauth/pca/verifier/Json.kt';
  const rec = { file: F, mutant: 'InlineConstantMutator: Substituted 0 with 1', line: 'var n = 0', occurrence: 1, fn: 'parse', status: 'KILLED' };
  const one = `STALE (no survivor at this site; killed or changed, remove it): kotlin-pca/${F}:9 (#1) in parse: InlineConstantMutator: Substituted 0 with 1 | var n = 0`;
  const noFn = `STALE (no survivor at this site; killed or changed, remove it): kotlin-pca/${F}:9 (#1): InlineConstantMutator: Substituted 0 with 1 | var n = 0`;
  const tally = (u, s, f = s) => `FAIL: ${f} problem(s); 5 entries\nledger entries for kotlin-pca: 5; unlisted survivors: ${u}; stale entries: ${s}\n`;
  const t = (name, r, ok) => { if (r.ok !== ok) { console.error(`stale-killed selftest FAILED: ${name}: ${JSON.stringify(r)}`); process.exit(1); } return r; };
  const r1 = t('killed equivalent is a notice', judge(`${one}\n${tally(0, 1)}`, [rec], 1), true);
  if (r1.notices.length !== 1 || !r1.notices[0].startsWith('::notice::equivalent entry killed this run (nondeterministic killer)')) { console.error('selftest: no notice'); process.exit(1); }
  t('a label without a function is matched too', judge(`${noFn}\n${tally(0, 1)}`, [rec], 1), true);
  t('not generated / not killed stays stale', judge(`${one}\n${tally(0, 1)}`, [], 1), false);
  t('another mutant killed does not excuse it', judge(`${one}\n${tally(0, 1)}`, [{ ...rec, mutant: 'InlineConstantMutator: Substituted 1 with 2' }], 1), false);
  t('another source line does not excuse it', judge(`${one}\n${tally(0, 1)}`, [{ ...rec, line: 'var m = 0' }], 1), false);
  t('another file does not excuse it', judge(`${one}\n${tally(0, 1)}`, [{ ...rec, file: F.replace('Json', 'Other') }], 1), false);
  t('another occurrence does not excuse it', judge(`${one}\n${tally(0, 1)}`, [{ ...rec, occurrence: 2 }], 1), false);
  t('another function does not excuse it', judge(`${one}\n${tally(0, 1)}`, [{ ...rec, fn: 'other' }], 1), false);
  t('an unlisted survivor still fails', judge(`${one}\nUNLISTED SURVIVOR kotlin-pca/a.kt:1: m | l\n${tally(1, 1, 2)}`, [rec], 1), false);
  // the checker's other error shapes: only its own problem count catches the ones that match no shape above
  for (const other of ['UNPLACEABLE SURVIVOR kotlin-pca/a.kt:1: m', 'multiplicity: 2 identical survivor(s) at this site, entry covers 1: kotlin-pca/a.kt:1', 'source file gone: sdks/kotlin-pca/a.kt', 'something new the checker prints']) {
    t(`stale plus "${other.slice(0, 24)}" fails`, judge(`${one}\n${other}\n${tally(0, 1, 2)}`, [rec], 1), false);
  }
  t('a missing FAIL count fails', judge(`${one}\nledger entries for kotlin-pca: 5; unlisted survivors: 0; stale entries: 1\n`, [rec], 1), false);
  t('a source-line-gone stale still fails', judge(`STALE (source line gone): kotlin-pca/${F}:9: m | l\n${tally(0, 1)}`, [rec], 1), false);
  const piped = { ...rec, mutant: 'MathMutator: Replaced bitwise OR with AND', line: 'x = a | b | c' };
  const pipedLine = `STALE (no survivor at this site; killed or changed, remove it): kotlin-pca/${F}:9 (#1) in parse: MathMutator: Replaced bitwise OR with AND | x = a | b | c`;
  t('a source line with " | " matches', judge(`${pipedLine}\n${tally(0, 1)}`, [piped], 1), true);
  t('a piped line does not match another mutant', judge(`${pipedLine}\n${tally(0, 1)}`, [{ ...piped, mutant: 'MathMutator: Replaced bitwise OR with XOR' }], 1), false);
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'stale-killed-'));
  fs.mkdirSync(path.join(tmp, 'shard-3')); fs.writeFileSync(path.join(tmp, 'shard-3', 'killed-equiv-3.json'), JSON.stringify([rec]));
  const loaded = loadKilled(tmp);
  fs.rmSync(tmp, { recursive: true, force: true });
  if (loaded.length !== 1) { console.error('stale-killed selftest FAILED: loadKilled'); process.exit(1); }
  // multiplicity shortfall: the entry covers 2, one survived, the other was killed
  const mline = (n, c) => `multiplicity: ${n} identical survivor(s) at this site, entry covers ${c}: kotlin-pca/${F}:9 (#1) in parse: InlineConstantMutator: Substituted 0 with 1 | var n = 0`;
  const ftally = (f) => `FAIL: ${f} problem(s); 5 entries\nledger entries for kotlin-pca: 5; unlisted survivors: 0; stale entries: 0\n`;
  const r2 = t('a shortfall covered by killed mutants is a notice', judge(`${mline(1, 2)}\n${ftally(1)}`, [rec], 1), true);
  if (r2.notices.length !== 1 || !r2.notices[0].includes('1 survived and 1 were killed')) { console.error('selftest: no multiplicity notice'); process.exit(1); }
  t('a shortfall of 2 with one killed fails', judge(`${mline(1, 3)}\n${ftally(1)}`, [rec], 1), false);
  t('no killed mutant fails', judge(`${mline(1, 2)}\n${ftally(1)}`, [], 1), false);
  t('more survivors than the entry covers fails', judge(`${mline(3, 2)}\n${ftally(1)}`, [rec], 1), false);
  t('a shortfall plus another error shape fails', judge(`${mline(1, 2)}\nUNPLACEABLE SURVIVOR kotlin-pca/a.kt:1: m\n${ftally(2)}`, [rec], 1), false);
  t('a shortfall plus a stale line is counted together', judge(`${mline(1, 2)}\n${one}\nFAIL: 2 problem(s); 5 entries\nledger entries for kotlin-pca: 5; unlisted survivors: 0; stale entries: 1\n`, [rec, { ...rec, mutant: 'InlineConstantMutator: Substituted 0 with 1', line: 'var n = 0' }], 1), true);
  t('exit 0 passes', judge('', [], 0), true);
  console.log('stale-killed selftest ok');
}

if (process.argv[2] === '--selftest') selftest();
else if (process.argv[1] && import.meta.url === new URL(`file://${path.resolve(process.argv[1])}`).href) {
  selftest(); // the control first
  const [logFile, reportsDir, code] = process.argv.slice(2);
  const r = judge(fs.readFileSync(logFile, 'utf8'), loadKilled(reportsDir), Number(code));
  for (const n of r.notices) console.log(n);
  for (const e of r.errors) console.log(`::error::${e}`);
  process.exit(r.ok ? 0 : 1);
}
