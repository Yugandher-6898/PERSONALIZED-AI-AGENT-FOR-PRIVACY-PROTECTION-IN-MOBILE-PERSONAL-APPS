import sys
import os
from pathlib import Path

# Add project root and backend to sys.path
PROJECT_DIR = Path(__file__).resolve().parent
BACKEND_DIR = PROJECT_DIR / "backend"
sys.path.insert(0, str(BACKEND_DIR))
sys.path.insert(0, str(PROJECT_DIR))

log_path = PROJECT_DIR / "server.log"
try:
    log_file = open(log_path, "a", encoding="utf-8", buffering=1)
    sys.stdout = log_file
    sys.stderr = log_file
except Exception:
    log_file = open(os.devnull, "w")
    sys.stdout = log_file
    sys.stderr = log_file

import logging
logging.basicConfig(stream=log_file, level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

import uvicorn

if __name__ == "__main__":
    # Bind to 0.0.0.0 so mobile phones on local Wi-Fi / hotspot can connect
    uvicorn.run("backend.app:app", host="0.0.0.0", port=8000, log_config=None)
