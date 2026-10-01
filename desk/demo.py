import json
from pathlib import Path

from .scanning import scan
from .storage import cached, save_cache, save_scan

ROOT = Path(__file__).resolve().parent.parent


def load_demo(db, seed=True):
    bundle = json.loads((ROOT / "demo/osv-snapshots.json").read_text())
    with db:
        for query in bundle["queries"]:
            if cached(db, query["name"], query["version"]) is None:
                save_cache(db, query["name"], query["version"], query["retrieved_at"],
                           query["response"], "Bundled OSV snapshot")
        if seed and db.execute("SELECT COUNT(*) FROM scans").fetchone()[0] == 0:
            for filename, name, scan_id in (
                ("baseline.txt", "Aarav · shop-api baseline", "demo-baseline"),
                ("update.txt", "Meera · template update", "demo-update")):
                report = scan(db, (ROOT / "demo" / filename).read_text(), name, scan_id=scan_id)
                save_scan(db, report)
