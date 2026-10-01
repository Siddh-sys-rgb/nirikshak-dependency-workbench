# Advisory data attribution

`osv-snapshots.json` contains unmodified original JSON responses from
`POST https://api.osv.dev/v1/query`, captured on **1 October 2026 UTC**.
Each query includes its exact package, version, retrieval timestamp and response.
No vulnerable dependency is installed to produce these examples.

The responses include GitHub Advisory Database (`GHSA-*`) and PyPI Advisory
Database (`PYSEC-*`) records, distributed under **CC BY 4.0** according to the
[OSV data sources page](https://google.github.io/osv.dev/data/).
Attribution belongs to GitHub Advisory Database, PyPI Advisory Database, and
the original researchers and maintainers named in the individual records.
Their original reference URLs, credits, identifiers and descriptions are
preserved. Source records remain available at
`https://osv.dev/vulnerability/<advisory-id>`.

License: https://creativecommons.org/licenses/by/4.0/
Original sources: https://github.com/github/advisory-database and
https://github.com/pypa/advisory-database

The app derives concise summaries and groups records sharing CVE/GHSA aliases.
Those display transformations do not alter this raw source file. Cached results
represent the retrieval date; they are not a claim about today's full database.
The sample manifests, developer names and agency are fictional and original.
