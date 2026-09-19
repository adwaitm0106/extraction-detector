"""Victim inference API for model-extraction research.

Exposes a sentiment classifier and logs every successful query so that a
downstream detector can look for extraction-shaped traffic patterns.

Environment:
    LOG_PATH         request log (default data/logs/requests.jsonl)
    BLOCKLIST_PATH   keys the detector has flagged (default blocked.json)
    RESPONSE_MODE    full | label | rounded   (see api/defences.py)
    QUERY_BUDGET     requests per key, 0 = unlimited
    MODEL_STUB       set to 1 to skip the real model, for tests and CI
"""

import json
import os
import sys
import threading
import time
from collections import defaultdict
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from starlette.concurrency import run_in_threadpool

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from defences import RESPONSE_MODES, QueryBudget, shape_response  # noqa: E402
from stub import StubPipeline  # noqa: E402

MODEL_NAME = "distilbert-base-uncased-finetuned-sst-2-english"
LOG_PATH = os.environ.get("LOG_PATH", "data/logs/requests.jsonl")
BLOCKLIST_PATH = os.environ.get("BLOCKLIST_PATH", "blocked.json")
MAX_INPUT_CHARS = 2000

# Response-side defences. A bad value fails at startup rather than on the
# first request, so a misconfigured deployment never serves at all.
RESPONSE_MODE = os.environ.get("RESPONSE_MODE", "full")
if RESPONSE_MODE not in RESPONSE_MODES:
    raise RuntimeError("RESPONSE_MODE must be one of %s, got %r"
                       % (", ".join(RESPONSE_MODES), RESPONSE_MODE))
_BUDGET = QueryBudget(os.environ.get("QUERY_BUDGET", "0"))

# Module state. The pipeline is heavy to build, so it is created once at
# startup and shared. _MODEL_LOCK serialises inference and log writes because
# sync endpoints are dispatched to a threadpool.
_MODEL = None
_MODEL_LOCK = threading.Lock()
_LOG_LOCK = threading.Lock()


# --- Lifespan: load the model once, before the first request is served. ---
@asynccontextmanager
async def lifespan(app: FastAPI):
    global _MODEL
    if os.environ.get("MODEL_STUB") == "1":
        _MODEL = StubPipeline()
    else:
        from transformers import pipeline

        _MODEL = pipeline("sentiment-analysis", model=MODEL_NAME, device=-1)
    os.makedirs(os.path.dirname(LOG_PATH) or ".", exist_ok=True)
    yield
    _MODEL = None


app = FastAPI(title="Victim Sentiment API", lifespan=lifespan)


def _error(status: int, message: str, **extra):
    """Uniform JSON error body so clients never see a stack trace."""
    return JSONResponse(status_code=status, content={"error": message, **extra})


# --- Any unhandled exception becomes a 500 JSON body; the process stays up. ---
@app.exception_handler(Exception)
async def _unhandled(request: Request, exc: Exception):
    return _error(500, "internal server error", detail=str(exc))


# --- Append-only audit log. Flushed per line so another process can tail it. ---
def _log(record: dict) -> None:
    os.makedirs(os.path.dirname(LOG_PATH) or ".", exist_ok=True)
    with _LOG_LOCK, open(LOG_PATH, "a", encoding="utf-8") as fh:
        fh.write(json.dumps(record, ensure_ascii=False) + "\n")
        fh.flush()
        os.fsync(fh.fileno())


# --- Enforcement. The detector writes flagged keys to a JSON file; it is
# --- re-read only when its mtime changes, so the per-request cost is one
# --- stat(). A missing or unreadable file means nobody is blocked: the API must
# --- keep serving even when the detector is not running.
_BLOCK_CACHE = {"mtime": None, "keys": {}}


def _blocked(api_key: str):
    try:
        mtime = os.stat(BLOCKLIST_PATH).st_mtime
    except OSError:
        _BLOCK_CACHE["mtime"], _BLOCK_CACHE["keys"] = None, {}
        return None
    if mtime != _BLOCK_CACHE["mtime"]:
        try:
            with open(BLOCKLIST_PATH, encoding="utf-8") as fh:
                _BLOCK_CACHE["keys"] = json.load(fh).get("blocked", {})
            _BLOCK_CACHE["mtime"] = mtime
        except (OSError, ValueError):
            return None  # half-written; keep the previous view
    return _BLOCK_CACHE["keys"].get(api_key)


# --- Predict. Body is parsed by hand so auth is checked before validation and
# --- malformed JSON returns 422 rather than a framework stack trace.
@app.post("/predict")
async def predict(request: Request):
    api_key = (request.headers.get("X-API-Key") or "").strip()
    if not api_key:
        return _error(401, "missing or empty X-API-Key header")

    block = _blocked(api_key)
    if block is not None:
        return _error(429, "api key throttled: suspected model extraction",
                      why=block.get("why", []))

    raw = await _read_body(request)
    if raw is None:
        return _error(422, "request body must be valid JSON")
    if not isinstance(raw, dict) or "input" not in raw:
        return _error(422, "body must be a JSON object containing an 'input' field")

    text = raw["input"]
    if not isinstance(text, str):
        return _error(422, "'input' must be a string")
    if not text.strip():
        return _error(422, "'input' must not be empty or whitespace only")
    if len(text) > MAX_INPUT_CHARS:
        return _error(422, f"'input' must be at most {MAX_INPUT_CHARS} characters")

    if _MODEL is None:
        return _error(500, "model is not loaded")

    # Checked after validation, so a malformed request never spends budget.
    if not _BUDGET.allow(api_key):
        return _error(429, "query budget exhausted for this api key",
                      budget=_BUDGET.limit)

    started = time.perf_counter()
    result = (await run_in_threadpool(_infer, text))[0]
    latency_ms = int((time.perf_counter() - started) * 1000)

    label, confidence = str(result["label"]), float(result["score"])
    # The log keeps the full confidence whatever the client is shown: the
    # detector needs it, and it never leaves the server.
    await run_in_threadpool(
        _log,
        {
            "ts": time.time(),
            "api_key": api_key,
            "input": text,
            "predicted_label": label,
            "confidence": confidence,
            "latency_ms": latency_ms,
        },
    )
    return shape_response(label, confidence, RESPONSE_MODE)


def _infer(text: str):
    """Run the model under a lock; the HF pipeline is not thread-safe.

    truncation is required: DistilBERT accepts 512 tokens, and a 2000-character
    input can exceed that. Without it the pipeline raises and a legal request
    would surface as a 500.
    """
    with _MODEL_LOCK:
        return _MODEL(text, truncation=True, max_length=512)


async def _read_body(request: Request):
    """Return the decoded JSON body, or None if it is not parseable."""
    try:
        body = await request.body()
        return json.loads(body) if body else None
    except Exception:
        return None


# --- Liveness probe for the demo scripts and the dashboard. ---
@app.get("/health")
def health():
    return {"status": "ok", "model_loaded": _MODEL is not None}


# --- Per-key rollup over the current log file; feeds the detector dashboard. ---
@app.get("/stats")
def stats():
    counts, totals = defaultdict(int), defaultdict(float)
    if os.path.exists(LOG_PATH):
        with open(LOG_PATH, encoding="utf-8") as fh:
            for line in fh:
                try:
                    row = json.loads(line)
                    counts[row["api_key"]] += 1
                    totals[row["api_key"]] += float(row["confidence"])
                except Exception:
                    continue  # skip partially written or corrupt lines
    return {
        key: {"requests": n, "mean_confidence": totals[key] / n}
        for key, n in counts.items()
    }
