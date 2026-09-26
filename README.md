# crawatch

**Fail the build when a dependency you ship is on CISA's Known Exploited Vulnerabilities list.**

One command, no account, no token, no dependencies. Works on 19 lockfile formats and on CycloneDX or SPDX SBOMs.

```
npx crawatch package-lock.json
```

```
package-lock.json: npm, 1 package(s), 18 known vulnerabilities, 1 on the CISA exploited list
  KEV  vite@4.5.0  CVE-2025-31125  listed 2026-01-22  fixed in 4.5.11
       vite@4.5.0  CVE-2024-23331  severity 7.5  fixed in 4.5.2
       ...
  share https://crawatch.dev/r/1bpOHVu2yOPE7NDAg5R9n
  Under CRA Article 14 the 24-hour early warning runs from when you become aware. That may be now: https://crawatch.dev/docs/cra-first-24-hours
```

## Why the exploited list, and not every CVE

A typical lockfile carries dozens of advisories. Almost none of them are being exploited. The ones on [CISA's KEV catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) are: an attacker has used them, in the wild, with evidence. Over the last twelve months that was 33 CVEs in open-source packages, about three a month (litellm, n8n and drupal/core among them; [the full list](https://crawatch.dev/docs/open-source-packages-on-the-cisa-exploited-list)).

That short list is the one worth failing a build over. It is also the one that matters legally. Since **11 September 2026**, Article 14 of the EU **Cyber Resilience Act** requires anyone who sells software in the EU to report an *actively exploited* vulnerability in their product to ENISA within **24 hours** of becoming aware of it. A dependency counts as part of your product.

So `crawatch` fails on KEV by default, and only reports everything else.

## GitHub Action

```yaml
name: CRA Watch
on:
  push:
  pull_request:
  schedule:
    - cron: '0 6 * * *'   # daily: the list changes when CISA adds to it, not when you push
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: abinjohnson400-beep/crawatch.dev@v1
        with:
          lockfile: package-lock.json
          fail-on: kev        # kev (default) | any | none
```

Outputs: `kev` (count on the exploited list), `findings` (all known vulnerabilities) and `share` (a link to the result page). A KEV hit also raises a workflow warning.

## CLI

```
npx crawatch <lockfile> [--fail-on kev|any|none] [--json]
```

| exit | meaning |
|---|---|
| 0 | nothing at or above the `--fail-on` level |
| 1 | a dependency matched the `--fail-on` level |
| 2 | usage error, unreadable file, or the scan could not be reached |

Supported: `package-lock.json`, `npm-shrinkwrap.json`, `yarn.lock` (classic and berry), `pnpm-lock.yaml`, `requirements.txt` (`==` pins), `Pipfile.lock`, `poetry.lock`, `uv.lock`, `Cargo.lock`, `go.mod`, `go.sum`, `Gemfile.lock`, `composer.lock`, `packages.lock.json`, `pom.xml`, `gradle.lockfile`, `pubspec.lock`, `mix.lock`, `Package.resolved`, and CycloneDX or SPDX JSON.

## What is sent

Package names and versions from the file, to `https://crawatch.dev/api/scan`, which checks them against [OSV.dev](https://osv.dev) and the CISA KEV catalog. Nothing else from your repository. The result is kept so the share link works. Rate limit: 30 scans an hour per IP. [Privacy policy](https://crawatch.dev/privacy).

## Free tools on the same data

- [Scan a lockfile in the browser](https://crawatch.dev/scan)
- [SBOM generator](https://crawatch.dev/sbom): CycloneDX 1.5 or SPDX 2.3 from any of the lockfiles above
- [Vulnerability disclosure policy and security.txt generator](https://crawatch.dev/vdp), with an RFC 9116 checker
- [`kev-packages.json`](https://crawatch.dev/kev-packages.json): the CISA KEV catalog joined to package names and versions, as a file

## The part CI does not do

A scheduled run tells you something in a CI log. It does not email you at the moment CISA lists a dependency, start the 24/72-hour/14-day clock, draft the ENISA early warning, or keep the audit trail a market-surveillance authority can ask for. [CRA Watch](https://crawatch.dev/pricing) does. The first 100 accounts pay €14 a month for life.

## Licence

MIT. Not legal advice.
