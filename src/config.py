"""
Central configuration, read from environment variables.

Nothing secret is hard-coded here. Copy .env.example to .env and set your
own values; .env is git-ignored so keys never reach the repository.
"""
from __future__ import annotations

import os
from pathlib import Path

# Load a .env file if python-dotenv is available (optional dependency).
try:
    from dotenv import load_dotenv

    load_dotenv()
except Exception:  # pragma: no cover - dotenv is optional
    pass

# --- Paths -----------------------------------------------------------------
ROOT_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = ROOT_DIR / "data"
MODELS_DIR = ROOT_DIR / "models"

ANSWER_KEY = DATA_DIR / "expectedresults-1.2.csv"
DATASET = DATA_DIR / "dataset.csv"
MODEL_PATH = MODELS_DIR / "model.joblib"

# --- ZAP -------------------------------------------------------------------
# The ZAP API key is read from the environment. Never commit a real key.
ZAP_BASE_URL = os.getenv("ZAP_BASE_URL", "http://localhost:8080")
ZAP_API_KEY = os.getenv("ZAP_API_KEY", "")

# --- Target under test -----------------------------------------------------
# ZAP runs inside the docker network, so it reaches Benchmark by its compose
# service name, not localhost. (In a browser on the host, use :8081.)
TARGET_URL = os.getenv("TARGET_URL", "http://benchmark:8080/benchmark/")

# --- Optional LLM (for the MCP triage assistant) ---------------------------
LLM_PROVIDER = os.getenv("LLM_PROVIDER", "none")  # none | ollama | openai | anthropic
LLM_API_KEY = os.getenv("LLM_API_KEY", "")
