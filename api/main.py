"""Victim inference API for model-extraction research.

Exposes a sentiment classifier and logs every successful query so that a
downstream detector can look for extraction-shaped traffic patterns.
"""

import json
import os
import threading
import time
from collections import defaultdict
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from starlette.concurrency import run_in_threadpool

MODEL_NAME = "distilbert-base-uncased-finetuned-sst-2-english"
LOG_PATH = os.environ.get("LOG_PATH", "data/logs/requests.jsonl")
MAX_INPUT_CHARS = 2000

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


# --- Predict. Body is parsed by hand so auth is checked before validation and
# --- malformed JSON returns 422 rather than a framework stack trace.
@app.post("/predict")
async def predict(request: Request):
    api_key = (request.headers.get("X-API-Key") or "").strip()
    if not api_key:
        return _error(401, "missing or empty X-API-Key header")

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

    started = time.perf_counter()
    result = (await run_in_threadpool(_infer, text))[0]
    latency_ms = int((time.perf_counter() - started) * 1000)

    label, confidence = str(result["label"]), float(result["score"])
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
    return {"label": label, "confidence": confidence}


def _infer(text: str):
    """Run the model under a lock; the HF pipeline is not thread-safe."""
    with _MODEL_LOCK:
        return _MODEL(text)


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
        with open(LOG_PATH, "r", encoding="utf-8") as fh:
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
