"""Evidence coverage is independent from whether findings are present."""
import hashlib
import uuid
from datetime import datetime, timezone

from .advisories import now, summarise
from .manifest import parse_manifest
from .storage import cached, save_cache


def freshness(retrieved):
    try:
        date = datetime.fromisoformat(retrieved.replace("Z", "+00:00"))
        if date.tzinfo is None:
            raise ValueError()
        age = max(0, int((datetime.now(timezone.utc) - date).total_seconds()))
        return {"age_seconds": age, "freshness": "fresh" if age <= 86400 else "stale"}
    except (ValueError, TypeError, AttributeError):
        return {"age_seconds": None, "freshness": "unknown"}


def scan(db, text, name, mode="offline", client=None, scan_id=None):
    manifest = parse_manifest(text)
    packages = manifest["packages"]
    results = client.query(packages) if mode == "live" else None
    report = {"id": scan_id or uuid.uuid4().hex, "name": name, "mode": mode,
              "created_at": now(), "manifest": text,
              "manifest_sha256": hashlib.sha256(text.encode()).hexdigest(),
              "unsupported": manifest["unsupported"], "packages": []}
    for index, package in enumerate(packages):
        entry = {**package, "source": "none", "retrieved_at": None,
                 "findings": [], "age_seconds": None, "freshness": "unknown"}
        if mode == "offline":
            record = cached(db, package["name"], package["version"])
            if record is None:
                entry.update(state="unverified", reason="No exact-version snapshot is cached. Run an opt-in live lookup.")
                report["packages"].append(entry)
                continue
            payload = record["response"]
            entry.update(state="complete", source=record["source"],
                         retrieved_at=record["retrieved_at"], reason="")
            records = payload.get("vulns", [])
        else:
            result = results[index]
            records = result["records"]
            entry.update(state=result["state"], source="OSV live lookup",
                         retrieved_at=result["retrieved_at"], reason=result["reason"])
        try:
            entry["findings"] = summarise(records, package["name"])
        except (TypeError, AttributeError, KeyError, ValueError):
            entry.update(state="failed", reason="Advisory details did not match the supported schema.")
        entry.update(freshness(entry["retrieved_at"]))
        if mode == "live" and entry["state"] == "complete":
            save_cache(db, package["name"], package["version"], entry["retrieved_at"], {"vulns": records})
        report["packages"].append(entry)
    checked = sum(p["state"] == "complete" for p in report["packages"])
    report["summary"] = {
        "packages": len(packages), "checked": checked,
        "unchecked": len(packages) - checked,
        "unsupported": len(report["unsupported"]),
        "findings": sum(len(p["findings"]) for p in report["packages"]),
        "affected_packages": sum(bool(p["findings"]) for p in report["packages"]),
        "complete": checked == len(packages) and not report["unsupported"] and bool(packages),
    }
    return report


def compare(before, after):
    old = {p["name"]: p for p in before["packages"]}
    new = {p["name"]: p for p in after["packages"]}
    common = old.keys() & new.keys()
    covered = sorted(name for name in common if old[name]["state"] == new[name]["state"] == "complete")
    def findings(mapping):
        return {(name, f["key"]): {"package": name, **f}
                for name in covered for f in mapping[name]["findings"]}
    a, b = findings(old), findings(new)
    result = {"before": before["id"], "after": after["id"],
        "new": [b[k] for k in sorted(b.keys() - a.keys())],
        "resolved": [a[k] for k in sorted(a.keys() - b.keys())],
        "unchanged": [b[k] for k in sorted(a.keys() & b.keys())],
        "added_packages": sorted(new.keys() - old.keys()),
        "removed_packages": sorted(old.keys() - new.keys()),
        "changed_versions": [{"package": n, "before": old[n]["version"], "after": new[n]["version"]}
                             for n in sorted(common) if old[n]["version"] != new[n]["version"]],
        "coverage": {"compared_packages": covered,
                     "unverified_packages": sorted(common - set(covered)),
                     "unsupported_before": len(before["unsupported"]),
                     "unsupported_after": len(after["unsupported"]),
                     "scope": "Common packages with complete exact-version lookups on both sides."},
        "note": "Resolved means absent in the later evidence for a covered package; removed packages are not labelled fixed."}
    return result
