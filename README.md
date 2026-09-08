# Project

## Quickstart

Nothing is required on the host except Docker Desktop (or Docker Engine with
the Compose plugin). Python, torch and the model weights all live inside the
image.

```bash
git clone https://github.com/adwaitm0106/extraction-detector.git
cd extraction-detector
docker compose up --build
```

The first build downloads the CPU-only torch wheels and bakes the
`distilbert-base-uncased-finetuned-sst-2-english` weights into the image, so it
takes several minutes. Later builds are cached and start in seconds.

The API is ready once `/health` reports `model_loaded: true`:

```bash
curl -s http://127.0.0.1:8000/health
# {"status":"ok","model_loaded":true}
```

Send a prediction. `X-API-Key` is required and identifies the caller in the
logs; any non-empty string works:

```bash
curl -s -X POST http://127.0.0.1:8000/predict \
  -H "Content-Type: application/json" \
  -H "X-API-Key: demo-key-1" \
  -d '{"input":"This movie was absolutely fantastic."}'
# {"label":"POSITIVE","confidence":0.9998722076416016}
```

Every successful request appends one JSON line to `data/logs/requests.jsonl`
on the host, via a bind mount, so the detector can tail it live:

```bash
tail -f data/logs/requests.jsonl
```

Per-key totals:

```bash
curl -s http://127.0.0.1:8000/stats
```

Stop the stack with `docker compose down`.

**On Windows PowerShell**, `curl` is an alias for `Invoke-WebRequest` and will
reject the flags above. Use `curl.exe`, or the native form:

```powershell
Invoke-RestMethod -Uri http://127.0.0.1:8000/predict -Method Post `
  -Headers @{"X-API-Key"="demo-key-1"} -ContentType "application/json" `
  -Body '{"input":"This movie was absolutely fantastic."}'
```

### Running without Docker

```bash
python -m venv .venv
.venv/Scripts/python.exe -m pip install -r api/requirements.txt   # Windows
.venv/Scripts/python.exe -m uvicorn api.main:app --host 127.0.0.1 --port 8000
```

Run all endpoint checks in one command (Windows):

```powershell
powershell -ExecutionPolicy Bypass -File scripts\smoke_test.ps1
```

## Architecture

## Running the demo

## Results

## Team
