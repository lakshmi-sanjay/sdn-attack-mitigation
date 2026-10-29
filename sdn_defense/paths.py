import os
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
CONFIG_DIR = REPO_ROOT / "config"
RUNTIME_DIR = Path(os.environ.get("SDN_RUNTIME_DIR", REPO_ROOT / "runtime"))

DETECTION_CONFIG = Path(
    os.environ.get("SDN_DETECTION_CONFIG", CONFIG_DIR / "detection_config.json")
)

REQUEST_FILE = RUNTIME_DIR / "block_requests.json"
REQUEST_LOCK_FILE = RUNTIME_DIR / "block_requests.lock"

CONNECTION_EVENTS_FILE = RUNTIME_DIR / "connection_events.json"
CONNECTION_EVENTS_LOCK_FILE = RUNTIME_DIR / "connection_events.json.lock"

BLOCK_EVENTS_FILE = RUNTIME_DIR / "block_events.csv"
BLOCK_EVENTS_LOCK_FILE = RUNTIME_DIR / "block_events.lock"

DETECTION_LOG = RUNTIME_DIR / "detection_log.csv"
CONTEXT_FILE = RUNTIME_DIR / "experiment_context.json"

RUNTIME_DIR.mkdir(parents=True, exist_ok=True)
