"""Bounded OSV queries and readable, alias-deduplicated evidence."""
import json
import re
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone

API = "https://api.osv.dev"
MAX_RESPONSE = 2 * 1024 * 1024
MAX_DETAILS = 60
ID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,119}$")


def now():
    return datetime.now(timezone.utc).isoformat()


class LookupFailure(RuntimeError):
    pass


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise LookupFailure("OSV redirects are not followed.")


def fetch_json(path, payload=None, timeout=4):
    # Callers supply only fixed route names or validated advisory IDs. No user
    # URL, manifest URL, proxy-derived host, or request header is accepted.
    if not (path == "/v1/querybatch" or
            re.fullmatch(r"/v1/vulns/[A-Za-z0-9][A-Za-z0-9._-]{0,119}", path)):
        raise LookupFailure("Invalid advisory API route.")
    data = json.dumps(payload).encode() if payload is not None else None
    request = urllib.request.Request(API + path, data=data, headers={
        "Content-Type": "application/json", "Accept": "application/json",
        "User-Agent": "Nirikshak-Dependency-Workbench/1.0"})
    try:
        # Ignore environment proxies: outbound requests use the fixed HTTPS host.
        opener = urllib.request.build_opener(NoRedirect(), urllib.request.ProxyHandler({}))
        with opener.open(request, timeout=timeout) as response:
            content = response.read(MAX_RESPONSE + 1)
        if len(content) > MAX_RESPONSE:
            raise LookupFailure("OSV response exceeded the 2 MiB limit.")
        body = json.loads(content)
        if not isinstance(body, dict):
            raise LookupFailure("OSV returned an invalid response object.")
        return body
    except (urllib.error.URLError, TimeoutError, OSError, ValueError) as exc:
        raise LookupFailure("OSV lookup failed or returned malformed JSON.") from exc


def identity(record):
    candidates = [record.get("id", "")] + record.get("aliases", [])
    cves = sorted(v for v in candidates if isinstance(v, str) and v.startswith("CVE-"))
    ghsas = sorted(v for v in candidates if isinstance(v, str) and v.startswith("GHSA-"))
    return (cves or ghsas or [record.get("id", "unknown")])[0]


def validate_record(record):
    if not isinstance(record, dict) or not isinstance(record.get("id"), str) or not ID_PATTERN.fullmatch(record["id"]):
        raise ValueError("Invalid advisory identity.")
    aliases = record.get("aliases", [])
    if not isinstance(aliases, list) or any(not isinstance(a, str) for a in aliases):
        raise ValueError("Invalid advisory aliases.")
    if not isinstance(record.get("affected", []), list) or not isinstance(record.get("references", []), list):
        raise ValueError("Invalid advisory evidence lists.")
    if not isinstance(record.get("database_specific", {}), dict):
        raise ValueError("Invalid advisory metadata.")
    return record


def summarise(records, package):
    if not isinstance(records, list):
        raise ValueError("Advisories must be a list.")
    groups = {}
    for record in records:
        validate_record(record)
        if record.get("withdrawn"):
            continue
        key = identity(record)
        group = groups.setdefault(key, {"key": key, "ids": [], "aliases": [],
            "summary": "Advisory details unavailable", "details": "", "severity": "UNKNOWN",
            "references": [], "fixed_markers": [], "modified": None})
        group["ids"].append(record["id"])
        group["aliases"] += [a for a in record.get("aliases", []) if isinstance(a, str)]
        if record.get("summary"):
            group["summary"] = str(record["summary"])[:500]
        if record.get("details") and not group["details"]:
            group["details"] = str(record["details"])[:8000]
        severity = str(record.get("database_specific", {}).get("severity", "UNKNOWN")).upper()
        rank = {"UNKNOWN": 0, "LOW": 1, "MODERATE": 2, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
        if rank.get(severity, 0) > rank[group["severity"]]:
            group["severity"] = severity
        group["modified"] = record.get("modified") or group["modified"]
        for reference in record.get("references", []):
            url = reference.get("url", "") if isinstance(reference, dict) else ""
            try:
                parsed = urllib.parse.urlparse(url)
            except (ValueError, TypeError):
                continue
            if parsed.scheme in {"http", "https"} and parsed.hostname and len(url) < 2000:
                group["references"].append(url)
        for affected in record.get("affected", []):
            pkg = affected.get("package", {})
            if pkg.get("ecosystem") != "PyPI" or pkg.get("name", "").lower() != package:
                continue
            for value in affected.get("ranges", []):
                for event in value.get("events", []):
                    if isinstance(event.get("fixed"), str):
                        group["fixed_markers"].append(event["fixed"][:80])
    for group in groups.values():
        for field in ("ids", "aliases", "references", "fixed_markers"):
            group[field] = sorted(set(group[field]))
        group["evidence_url"] = "https://osv.dev/vulnerability/" + urllib.parse.quote(group["ids"][0], safe="")
    return sorted(groups.values(), key=lambda item: item["key"])


class OSVClient:
    def __init__(self, transport=fetch_json, clock=time.monotonic):
        self.transport = transport
        self.clock = clock

    def query(self, packages):
        if not packages:
            return []
        started = self.clock()
        queries = [{"package": {"name": p["name"], "ecosystem": "PyPI"},
                    "version": p["version"]} for p in packages]
        retrieved = now()
        try:
            result = self.transport("/v1/querybatch", {"queries": queries}, timeout=4)
            batch = result.get("results")
            if not isinstance(batch, list) or len(batch) != len(packages):
                raise LookupFailure("OSV returned an unexpected batch size.")
        except (LookupFailure, AttributeError, TypeError) as exc:
            return [{"state": "failed", "records": [], "retrieved_at": retrieved,
                     "reason": str(exc)} for _ in packages]
        outputs, details, count = [], {}, 0
        for item in batch:
            if not isinstance(item, dict) or not isinstance(item.get("vulns", []), list):
                outputs.append({"state": "failed", "records": [], "retrieved_at": retrieved,
                                "reason": "OSV returned an invalid package result."})
                continue
            records, reasons = [], []
            if item.get("next_page_token"):
                reasons.append("OSV pagination is present; only the first page is represented.")
            if len(item.get("vulns", [])) > 100:
                reasons.append("More than 100 records matched; only the first 100 are represented.")
            for reference in item.get("vulns", [])[:100]:
                advisory_id = reference.get("id", "") if isinstance(reference, dict) else ""
                if not isinstance(advisory_id, str) or not ID_PATTERN.fullmatch(advisory_id):
                    reasons.append("An advisory ID was invalid.")
                    continue
                if advisory_id not in details:
                    remaining = 18 - (self.clock() - started)
                    if count >= MAX_DETAILS or remaining <= 0:
                        details[advisory_id] = None
                    else:
                        count += 1
                        try:
                            record = self.transport("/v1/vulns/" + advisory_id,
                                                    timeout=min(4, remaining))
                            if record.get("id") != advisory_id:
                                raise LookupFailure("Advisory identity did not match the query.")
                            validate_record(record)
                            details[advisory_id] = record
                        except (LookupFailure, ValueError, AttributeError, TypeError):
                            details[advisory_id] = None
                if details[advisory_id] is None:
                    reasons.append("Some advisory details were unavailable or exceeded the scan budget.")
                    records.append({"id": advisory_id, "modified": reference.get("modified"),
                                    "summary": "Details unavailable; review OSV source"})
                else:
                    records.append(details[advisory_id])
            outputs.append({"state": "partial" if reasons else "complete", "records": records,
                            "retrieved_at": retrieved, "reason": " ".join(sorted(set(reasons)))})
        return outputs
