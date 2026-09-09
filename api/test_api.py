"""Hostile-input test suite for the victim API.

Fires malformed, oversized and adversarial payloads at a running server and
asserts the status code of each. The point is not only that responses are
correct, but that the process survives all of them: the final checks confirm
the server is still answering after the abuse.

Usage:
    python api/test_api.py [--base-url http://127.0.0.1:8000]

Exits non-zero if any case fails. Standard library only, so it can run
against a container without installing anything.
"""

import argparse
import json
import sys
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor

KEY = {"X-API-Key": "test-key"}
results = []


# --- Transport. Returns the status code instead of raising, so a 4xx is data
# --- rather than an exception; -1 means the connection itself failed.
def call(base, path, method="GET", headers=None, body=None, timeout=30):
    url = base.rstrip("/") + path
    data = body.encode("utf-8") if isinstance(body, str) else body
    req = urllib.request.Request(url, data=data, method=method)
    req.add_header("Content-Type", "application/json")
    for k, v in (headers or {}).items():
        req.add_header(k, v)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, r.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace")
    except Exception as e:  # connection refused, timeout, reset
        return -1, f"{type(e).__name__}: {e}"


def record(name, expected, actual, detail=""):
    ok = expected == actual
    results.append((name, expected, actual, ok))
    print(
        f"{'PASS' if ok else 'FAIL'}  {name:<38} expected={expected:<5} actual={actual}"
        + (f"   {detail[:70]}" if not ok and detail else "")
    )
    return ok


def predict(base, body, headers=KEY):
    return call(base, "/predict", "POST", headers, body)


# --- Each entry is (case name, raw request body, expected status). Bodies are
# --- pre-serialised strings so malformed JSON can be sent verbatim.
def build_cases():
    cases = [
        ("valid request", json.dumps({"input": "A genuinely great film."}), 200),
        ("missing 'input' field", json.dumps({"text": "hello"}), 422),
        ("input is null", json.dumps({"input": None}), 422),
        ("input is a number", json.dumps({"input": 42}), 422),
        ("input is a list", json.dumps({"input": ["a", "b"]}), 422),
        ("input is a dict", json.dumps({"input": {"a": 1}}), 422),
        ("input is empty string", json.dumps({"input": ""}), 422),
        ("input is whitespace only", json.dumps({"input": "   "}), 422),
        ("input is 10000 chars", json.dumps({"input": "a" * 10000}), 422),
        ("input is exactly 2000 chars", json.dumps({"input": "a" * 2000}), 200),
        ("input is 2001 chars", json.dumps({"input": "a" * 2001}), 422),
        # 2000 legal characters but 1002 tokens -- double DistilBERT's 512-token
        # limit. Without truncation in the pipeline call this is a 500.
        ("2000 chars / 1002 tokens", json.dumps({"input": "a " * 1000}), 200),
        ("body is not valid JSON", '{"input": broken', 422),
        ("body is empty", "", 422),
        ("body is a JSON array", json.dumps(["input"]), 422),
        ("body is a bare string", json.dumps("hello"), 422),
    ]
    # Adversarial but legal strings: all must be served normally, not crash.
    hostile = {
        "unicode": "Es war wirklich schön — ausgezeichnet! Ω≈ç√",
        "emoji": "this movie 🎬🔥 was 😍 incredible 🚀",
        "newlines": "line one\nline two\r\nline three\ttabbed",
        "null bytes": "before\u0000after",
        "control chars": "bell\u0007esc\u001bnul\u0000end",
        "rtl text": "هذا فيلم رائع جدا",
        "cjk": "这部电影非常精彩，我很喜欢。",
        "html injection": "<script>alert('xss')</script> great movie",
        "sql-ish": "'; DROP TABLE requests; -- lovely film",
        "json in input": '{"nested": "value"}',
        "backslashes": "C:\\path\\to\\nowhere and \u0041",
        "combining marks": "e\u0301\u0301\u0301\u0301 wonderful",
    }
    for label, text in hostile.items():
        cases.append((f"hostile: {label}", json.dumps({"input": text}), 200))
    return cases


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--base-url", default="http://127.0.0.1:8000")
    args = ap.parse_args()
    base = args.base_url

    # --- Refuse to report failures that are really "server isn't running". ---
    status, body = call(base, "/health")
    if status != 200:
        print(f"Server not reachable at {base} (status={status}): {body}")
        return 2
    if not json.loads(body).get("model_loaded"):
        print(f"Server is up but the model is not loaded yet: {body}")
        return 2
    print(f"Testing {base}\n")

    # --- Auth cases: checked before body validation, so the body here is valid
    # --- and only the header varies.
    good = json.dumps({"input": "hello"})
    record("no X-API-Key header", 401, predict(base, good, headers={})[0])
    record("empty X-API-Key", 401, predict(base, good, headers={"X-API-Key": ""})[0])
    record(
        "whitespace X-API-Key", 401, predict(base, good, headers={"X-API-Key": "   "})[0]
    )

    for name, body, expected in build_cases():
        code, resp = predict(base, body)
        record(name, expected, code, resp)

    # --- Concurrency: 50 simultaneous requests must all resolve, none 500. ---
    payloads = [json.dumps({"input": f"concurrent request number {i}"}) for i in range(50)]
    with ThreadPoolExecutor(max_workers=50) as pool:
        codes = [c for c, _ in pool.map(lambda b: predict(base, b), payloads)]
    record("50 concurrent: all returned 200", 50, sum(c == 200 for c in codes), str(codes))
    record("50 concurrent: no 5xx", 0, sum(c >= 500 or c == -1 for c in codes), str(codes))

    # --- Survival: the whole point of the suite. ---
    print()
    status, body = call(base, "/health")
    record("server alive after abuse", 200, status, body)
    record(
        "model still loaded",
        True,
        status == 200 and json.loads(body).get("model_loaded") is True,
        body,
    )
    record("stats still serves", 200, call(base, "/stats")[0])

    failed = [r for r in results if not r[3]]
    print(f"\n{len(results) - len(failed)}/{len(results)} passed")
    if failed:
        print("\nFAILED:")
        for name, exp, act, _ in failed:
            print(f"  - {name}: expected {exp}, got {act}")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
