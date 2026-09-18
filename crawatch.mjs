#!/usr/bin/env node
/**
 * crawatch — scan a lockfile against OSV and the CISA exploited list from
 * the terminal or CI, using the same free endpoint as https://crawatch.dev/scan.
 *
 *   npx crawatch package-lock.json
 *   npx crawatch Cargo.lock --fail-on kev        # exit 1 if any dependency is on the CISA list (default)
 *   npx crawatch go.sum --fail-on any            # exit 1 on any known vulnerability
 *   npx crawatch pnpm-lock.yaml --fail-on none   # report only
 *   npx crawatch package-lock.json --json        # machine-readable
 *
 * No account, no token, no dependencies. The lockfile is sent to the scan
 * endpoint (package names and versions, nothing else), the result is printed,
 * and the share link is the same one the web scan gives. Rate limit: 30 scans
 * an hour per IP. The daily watch, alerts and the ENISA drafts are the paid
 * part: https://crawatch.dev/pricing
 */
import fs from 'node:fs';
import path from 'node:path';

const SITE = process.env.CRAWATCH_URL || 'https://crawatch.dev';
const args = process.argv.slice(2);
const flag = (n, d) => { const i = args.indexOf(`--${n}`); return i >= 0 ? (args[i + 1] ?? true) : d; };
const files = args.filter((a, i) => !a.startsWith('--') && !(i > 0 && args[i - 1] === '--fail-on'));
const failOn = String(flag('fail-on', 'kev'));
const asJson = args.includes('--json');

if (!files.length || args.includes('--help')) {
  console.log('usage: crawatch <lockfile> [--fail-on kev|any|none] [--json]');
  process.exit(files.length ? 0 : 2);
}
if (!['kev', 'any', 'none'].includes(failOn)) { console.error(`--fail-on must be kev, any or none (got ${failOn})`); process.exit(2); }

let worst = 0;
for (const file of files) {
  let content;
  try { content = fs.readFileSync(file, 'utf8'); } catch (e) { console.error(`${file}: ${e.message}`); process.exit(2); }
  if (content.length > 4 * 1024 * 1024) { console.error(`${file}: larger than 4 MB`); process.exit(2); }
  let res, body;
  try {
    res = await fetch(`${SITE}/api/scan`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', 'user-agent': 'crawatch-cli/1.0 (+https://crawatch.dev)' },
      body: JSON.stringify({ filename: path.basename(file), content }),
    });
    body = await res.json();
  } catch (e) { console.error(`${file}: could not reach ${SITE}: ${e.message}`); process.exit(2); }
  if (!res.ok) { console.error(`${file}: ${body.error || `HTTP ${res.status}`}`); process.exit(2); }

  const findings = body.findings || [];
  const kev = findings.filter((f) => f.kev);
  if (asJson) {
    console.log(JSON.stringify({ file, ecosystem: body.ecosystem, packages: body.packageCount, findings: findings.length, kev: kev.length, share: `${SITE}/r/${body.scanId}`, result: body }, null, 2));
  } else {
    console.log(`${file}: ${body.ecosystem || 'unknown ecosystem'}, ${body.packageCount} package(s), ${findings.length} known vulnerabilit${findings.length === 1 ? 'y' : 'ies'}, ${kev.length} on the CISA exploited list`);
    for (const f of kev) console.log(`  KEV  ${f.package}@${f.version}  ${f.cve || f.id}${f.kev.dateAdded ? `  listed ${f.kev.dateAdded}` : ''}${f.fixed ? `  fixed in ${f.fixed}` : ''}${f.kev.ransomware === 'Known' ? '  ransomware: known' : ''}`);
    const sev = (s) => (!s ? '' : /^CVSS:/i.test(String(s)) ? '  severity: see advisory' : `  severity ${s}`);
    for (const f of findings.filter((x) => !x.kev).slice(0, 25)) console.log(`       ${f.package}@${f.version}  ${f.cve || f.id}${sev(f.severity)}${f.fixed ? `  fixed in ${f.fixed}` : ''}`);
    if (findings.length - kev.length > 25) console.log(`       and ${findings.length - kev.length - 25} more`);
    for (const w of body.warnings || []) console.log(`  note ${w}`);
    console.log(`  share ${SITE}/r/${body.scanId}`);
    if (kev.length) console.log('  Under CRA Article 14 the 24-hour early warning runs from when you become aware. That may be now: https://crawatch.dev/docs/cra-first-24-hours');
  }
  worst = Math.max(worst, kev.length ? 2 : findings.length ? 1 : 0);
}

const fail = failOn === 'kev' ? worst >= 2 : failOn === 'any' ? worst >= 1 : false;
process.exit(fail ? 1 : 0);
