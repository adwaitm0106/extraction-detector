# Victim inference API, CPU-only.
#
# The model weights are baked into the image at build time so the container
# needs no network access at runtime -- important for the attack simulation,
# where the container is run isolated.

FROM python:3.11-slim

# Keep Python from writing .pyc files and buffering logs, so `docker logs`
# shows output immediately.
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

# Torch first, pinned to the CPU-only wheel index. Installing it separately
# guarantees pip cannot resolve the default PyPI build, which drags in several
# hundred MB of CUDA runtime packages we would never use.
RUN pip install --no-cache-dir \
        --index-url https://download.pytorch.org/whl/cpu \
        torch==2.14.0

# Remaining dependencies. torch is already satisfied above, so this only adds
# fastapi, uvicorn and transformers. Copied on its own layer so that editing
# application code does not invalidate the (slow) dependency install.
COPY api/requirements.txt /app/api/requirements.txt
RUN pip install --no-cache-dir -r /app/api/requirements.txt

# Non-root runtime user. Created before the model download so the Hugging Face
# cache is written with the right ownership rather than needing a later chown.
RUN useradd --create-home --uid 10001 appuser \
    && mkdir -p /app/data/logs /opt/hf-cache \
    && chown -R appuser:appuser /app /opt/hf-cache

ENV HF_HOME=/opt/hf-cache

# Bake the weights into the image (~268MB). Done as appuser so the cache is
# readable by the runtime user.
USER appuser
RUN python -c "\
from transformers import pipeline; \
pipeline('sentiment-analysis', \
         model='distilbert-base-uncased-finetuned-sst-2-english', \
         device=-1)"

# With the weights cached, refuse any runtime call to the Hub. This turns a
# silent re-download into a hard failure, so a broken cache is caught at once.
ENV HF_HUB_OFFLINE=1 \
    TRANSFORMERS_OFFLINE=1

COPY --chown=appuser:appuser api/ /app/api/

ENV LOG_PATH=/app/data/logs/requests.jsonl
EXPOSE 8000

# urllib rather than curl: the slim base has no curl and adding it would only
# grow the image. Long start period because the model loads at startup.
HEALTHCHECK --interval=30s --timeout=5s --start-period=90s --retries=3 \
    CMD python -c "\
import sys, urllib.request; \
sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/health', timeout=3).status == 200 else 1)"

CMD ["python", "-m", "uvicorn", "api.main:app", "--host", "0.0.0.0", "--port", "8000"]
