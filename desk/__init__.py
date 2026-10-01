"""Local-only Nirikshak web application."""
import hmac
import json
import secrets
import threading
import time
from pathlib import Path

from flask import Flask, Response, g, jsonify, render_template, request, session
from werkzeug.exceptions import HTTPException

from .advisories import OSVClient
from .demo import load_demo
from .manifest import InputError, MAX_BYTES
from .scanning import compare, scan
from .storage import connect, get_scan, initialise, list_scans, save_scan

ROOT = Path(__file__).resolve().parent.parent


def create_app(config=None):
    app = Flask(__name__, instance_path=str(ROOT / "instance"))
    app.config.update(DATA_DIR=str(ROOT / "instance"), MAX_CONTENT_LENGTH=65536,
        TRUSTED_HOSTS=["localhost", "127.0.0.1", "[::1]"],
        SESSION_COOKIE_NAME="nirikshak_session", SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Strict",
        SEED_DEMO=True, BUNDLED_CACHE=True, LIVE_COOLDOWN=5, OSV_CLIENT=OSVClient())
    if config:
        app.config.update(config)
    data_dir = Path(app.config["DATA_DIR"])
    data_dir.mkdir(parents=True, exist_ok=True)
    if not app.config.get("SECRET_KEY"):
        key_path = data_dir / "session.key"
        try:
            with key_path.open("x") as file:
                file.write(secrets.token_hex(32))
            key_path.chmod(0o600)
        except FileExistsError:
            pass
        app.config["SECRET_KEY"] = key_path.read_text()
    database = str(data_dir / "workbench.db")
    initialise(database)
    if app.config["BUNDLED_CACHE"]:
        with connect(database) as db:
            load_demo(db, app.config["SEED_DEMO"])
    live_lock = threading.Lock()
    last_live = [float("-inf")]

    def db():
        if "db" not in g:
            g.db = connect(database)
        return g.db

    @app.teardown_appcontext
    def close_db(error):
        connection = g.pop("db", None)
        if connection is not None:
            connection.close()

    @app.before_request
    def protect_mutations():
        if request.method not in {"POST", "PUT", "PATCH", "DELETE"}:
            return None
        origin = request.headers.get("Origin")
        if origin and origin != request.host_url.rstrip("/"):
            return jsonify(error="Cross-origin mutations are not accepted."), 403
        if not session.get("csrf") or not hmac.compare_digest(
                request.headers.get("X-CSRF-Token", "").encode("utf-8"), session["csrf"].encode("utf-8")):
            return jsonify(error="Reload the page to obtain a valid session token."), 403

    @app.after_request
    def headers(response):
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self'; "
            "font-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'")
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "same-origin"
        if request.path.startswith("/api/"):
            response.headers["Cache-Control"] = "no-store"
        return response

    @app.errorhandler(Exception)
    def error(exc):
        if isinstance(exc, HTTPException):
            return jsonify(error=exc.description), exc.code
        if isinstance(exc, InputError):
            return jsonify(error=str(exc)), 422
        if isinstance(exc, LookupError):
            return jsonify(error=str(exc)), 404
        app.logger.exception("Unexpected application error")
        return jsonify(error="Unexpected error. No success or clean result is inferred."), 500

    @app.get("/")
    def index():
        return render_template("index.html")

    @app.get("/api/health")
    def health():
        return jsonify(status="ok", app="Nirikshak", ecosystem="PyPI", network="Opt-in OSV only")

    @app.get("/api/bootstrap")
    def bootstrap():
        session.setdefault("csrf", secrets.token_hex(24))
        return jsonify(csrf=session["csrf"], agency="Vistar Digital · Ahmedabad",
                       analyst="Meera Shah", max_packages=30, max_manifest_bytes=MAX_BYTES)

    @app.get("/api/scans")
    def scans():
        reports = list_scans(db())
        return jsonify(scans=[{k: r[k] for k in ("id", "name", "created_at", "mode", "summary")}
                              for r in reports])

    @app.get("/api/scans/<scan_id>")
    def scan_detail(scan_id):
        return jsonify(get_scan(db(), scan_id))

    @app.get("/api/scans/<scan_id>/export")
    def export(scan_id):
        report = get_scan(db(), scan_id)
        # ID is stored only by this application, not taken as a filesystem path.
        return Response(json.dumps(report, indent=2), mimetype="application/json",
                        headers={"Content-Disposition": 'attachment; filename="dependency-scan.json"'})

    @app.post("/api/scans")
    def create_scan():
        if request.is_json:
            payload = request.get_json()
            if not isinstance(payload, dict):
                raise InputError("A JSON object is required.")
        else:
            file = request.files.get("manifest")
            if not file or not file.filename.lower().endswith(".txt"):
                raise InputError("Upload a UTF-8 .txt manifest.")
            raw = file.read(MAX_BYTES + 1)
            if len(raw) > MAX_BYTES:
                raise InputError("Manifest exceeds 32 KiB.")
            try:
                text = raw.decode("utf-8-sig")
            except UnicodeDecodeError:
                raise InputError("Manifest must be UTF-8 text.") from None
            payload = {**request.form, "text": text,
                       "live_consent": request.form.get("live_consent") == "true"}
        name = payload.get("name", "Untitled dependency review")
        if not isinstance(name, str) or not 1 <= len(name.strip()) <= 80 or any(ord(c) < 32 for c in name):
            raise InputError("Scan name must be 1–80 printable characters.")
        mode = payload.get("mode", "offline")
        if mode not in {"offline", "live"}:
            raise InputError("Choose offline or live lookup.")
        if db().execute("SELECT COUNT(*) FROM scans").fetchone()[0] >= 200:
            raise InputError("This local demo supports 200 immutable scans per data directory.")
        if mode == "live":
            if payload.get("live_consent") is not True:
                raise InputError("Explicit consent is required to send package names and versions to api.osv.dev.")
            if not live_lock.acquire(blocking=False):
                return jsonify(error="Another live lookup is running. Try again shortly."), 429
            try:
                if time.monotonic() - last_live[0] < app.config["LIVE_COOLDOWN"]:
                    return jsonify(error="Wait five seconds between live lookups."), 429
                last_live[0] = time.monotonic()
                with db():
                    report = scan(db(), payload.get("text"), name.strip(), mode, app.config["OSV_CLIENT"])
                    save_scan(db(), report)
            finally:
                live_lock.release()
        else:
            with db():
                report = scan(db(), payload.get("text"), name.strip())
                save_scan(db(), report)
        return jsonify(report), 201

    @app.get("/api/compare")
    def comparison():
        before, after = request.args.get("before"), request.args.get("after")
        if not before or not after:
            raise InputError("Choose both a baseline and an updated scan.")
        return jsonify(compare(get_scan(db(), before), get_scan(db(), after)))

    return app
