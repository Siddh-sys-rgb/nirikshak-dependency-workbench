import argparse

from desk import create_app


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Run Nirikshak locally; no remote Git operations.")
    parser.add_argument("--port", type=int, default=8108)
    parser.add_argument("--data-dir", default="instance")
    parser.add_argument("--no-demo", action="store_true")
    args = parser.parse_args()
    app = create_app({"DATA_DIR": args.data_dir, "SEED_DEMO": not args.no_demo})
    app.run(host="127.0.0.1", port=args.port, debug=False, threaded=True)
