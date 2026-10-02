# Evaluation and provenance

## Local automated validation

On 1 October 2026, Python 3.12.14:

```text
109 passed
99% statement coverage across desk/
pip check: No broken requirements found.
node --check desk/static/app.js: passed
```

The test suite uses isolated temporary SQLite databases and mocked network
transports. It does not contact OSV or install submitted dependencies.
Coverage is a measure of code exercised, not proof that no bugs exist.

The suite checks:

- Exact Python pins, package normalisation, PEP 440 versions, duplicate and
  conflicting pins, malicious syntax, unsupported requirement features and
  byte/line/package limits.
- Empty successful responses versus failures, invalid provider schemas,
  malformed cache records, absent snapshots, pagination, withdrawn advisories,
  alias deduplication, order-independent highest severity, missing retrieval
  timestamps, unsafe links and invalid advisory URL identities.
- Bounded detail requests, scan time budget exhaustion, oversized/malformed
  HTTP responses and blocked redirects.
- Same-origin CSRF protection, Host validation, app-specific session cookies,
  JSON exports, UTF-8 uploads, API errors, request size and scan count limits.
- Concurrent live request exclusion, cooldown, history persistence, immutable
  old scans after cache refresh, and valid caches surviving failed refreshes.
- New, resolved and unchanged findings within common fully checked packages;
  dependency removal, unknown/failed versions and conflicting versions cannot
  be represented as fixed findings.

## Original OSV fixture evidence

All four responses were retrieved from the official `/v1/query` endpoint on
1 October 2026 UTC. Full original source responses and retrieval timestamps
are in `demo/osv-snapshots.json`; see `demo/NOTICE.md` for attribution.

| Package/version | Active source records | Alias-grouped families |
| --- | ---: | ---: |
| jinja2 3.1.4 | 6 | 3 |
| jinja2 3.1.6 | 0 | 0 |
| requests 2.32.4 | 2 | 1 |
| requests 2.19.1 | 10 | 5 |

Baseline: jinja2 3.1.4 + requests 2.32.4. Update: jinja2 3.1.6 + requests
2.19.1. The comparison contains **4 new, 3 resolved and 1 unchanged family**.
This describes the captured evidence, not current vulnerability counts.
The app does not recommend deliberately downgrading requests; the fictional
update exists to demonstrate a regression alongside a resolved problem.

## Live client smoke check

The completed `/v1/querybatch` + bounded `/v1/vulns/{id}` implementation was
tested against official OSV on **1 October 2026, 23:14 UTC** using only
`jinja2 3.1.4` and `requests 2.32.4`.

Both lookups completed. The live client retrieved 6/2 source records and
grouped them into 3/1 advisory families, matching the bundled snapshots.
No manifest text, scan name, account information or private dependency names
were sent. Live requests remain optional; the automated suite stays offline.

## Scope and practical limits

OSV matches may include vulnerable code paths that are not reachable in an
application. No runtime reachability, exploitability, authentication, package
installation, transitive resolution or upgrade compatibility analysis is done.
Scanning the app's own broad requirements file will correctly show unsupported
range specifiers; use a pinned exported environment or the included manifests.
An empty successful OSV lookup means no known matching entries in that
retrieval snapshot. It does not establish that a dependency or release is safe.

Browser workflow and screenshot validation are recorded separately by the
integrating agent after the local browser review.

## Running-browser verification

On 1 October 2026 the actual Flask UI was exercised in the in-app browser:

- Created an offline report with one cached pin, an uncached fictional package
  and an unsupported range. The UI showed the incomplete coverage warning
  despite a zero finding count.
- Compared the seeded snapshots and verified 4 new, 3 resolved and 1 unchanged
  family, along with common-package coverage and changed versions.
- Imported the real local `demo/update.txt` through the browser file chooser
  and saved an offline report with two checked pins and five families.
- Explicitly opted into a live `requests==2.32.4` lookup. The report showed
  complete live evidence, its original retrieval time and one advisory family.
- Downloaded JSON using the UI and parsed the downloaded file; its name, mode
  and checked-package count matched the live report.
- Verified that a fresh scan dialog starts offline. Editing package text after
  checking live consent clears the checkbox; closing/reopening clears previous
  consent and restores offline mode.
- Inspected the 1280-pixel desktop and 390-pixel mobile comparison. Neither
  layout had horizontal document overflow; saved-scan cards intentionally
  scroll within their own mobile row. Final console warnings/errors were empty.
- Verified independent localhost sessions across this app, Sutra and Repair Works.

Original JPEG screenshots show the working live report, seeded comparison and
mobile comparison. Extra saved scans and timestamps belong to the fictional
local QA session. This manual inspection is not an exhaustive automated
cross-browser suite. These initial browser checks preceded publication. [GitHub Actions](https://github.com/Siddh-sys-rgb/nirikshak-dependency-workbench/actions/workflows/tests.yml) now records the Linux matrix results.
