"""Live monitoring dashboard for the victim API.

Reads the request log and the benign baseline, scores every client, and serves
the verdicts as an auto-refreshing page. It is read-only: it never writes to
the log, so it can watch a running experiment without disturbing it.

    python -m uvicorn detector.dashboard:app --port 8050

Environment:
    LOG_PATH         request log to watch (default data/logs/requests.jsonl)
    THRESHOLDS_PATH  benign baseline from calibrate.py (default thresholds.json)

The page shows what the detector saw and why -- per-client flag counts and the
individual feature deviations behind them. A verdict with no explanation is
not much use to an operator deciding whether to revoke a key.
"""

import json
import os
import random
import sys
import time

from fastapi import FastAPI
from fastapi.responses import HTMLResponse

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from features import group_by_key, load_log  # noqa: E402
from score import MIN_FLAGS, Z_FLAG, score_client  # noqa: E402

LOG_PATH = os.environ.get("LOG_PATH", "data/logs/requests.jsonl")
THRESHOLDS_PATH = os.environ.get("THRESHOLDS_PATH", "thresholds.json")

app = FastAPI(title="Extraction Detector Dashboard")


# --- Scoring is re-run per poll rather than cached: the log is appended to
# --- continuously and a stale verdict is worse than a slow one at this scale.
def build_report():
    report = {
        "log_path": LOG_PATH,
        "thresholds_path": THRESHOLDS_PATH,
        "generated_at": time.time(),
        "calibrated": False,
        "clients": [],
        "totals": {"requests": 0, "clients": 0, "attacks": 0},
        "warning": None,
    }

    if not os.path.exists(LOG_PATH):
        report["warning"] = "No log at %s yet. Send some traffic first." % LOG_PATH
        return report

    rows = load_log(LOG_PATH)
    report["totals"]["requests"] = len(rows)
    by_key = group_by_key(rows)
    report["totals"]["clients"] = len(by_key)
    if not rows:
        report["warning"] = "Log is empty."
        return report

    if not os.path.exists(THRESHOLDS_PATH):
        report["warning"] = (
            "No baseline at %s. Run detector/calibrate.py on benign-only "
            "traffic to enable verdicts; showing traffic volume only."
            % THRESHOLDS_PATH
        )
        for key, client_rows in sorted(by_key.items()):
            report["clients"].append({
                "api_key": key, "requests": len(client_rows), "verdict": "unscored",
                "n_flags": 0, "flags": [], "z": {}, "n_windows": 0,
                "last_seen": max(float(r["ts"]) for r in client_rows),
            })
        return report

    with open(THRESHOLDS_PATH, encoding="utf-8") as fh:
        cal = json.load(fh)
    report["calibrated"] = True
    report["baseline"] = {
        "n_windows": cal.get("n_windows"), "n_clients": cal.get("n_clients"),
        "window": cal["window"], "stride": cal["stride"],
    }

    rng = random.Random(0)
    for key, client_rows in sorted(by_key.items()):
        r = score_client(client_rows, cal["features"], cal["window"],
                         cal["stride"], rng)
        entry = {
            "api_key": key,
            "requests": len(client_rows),
            "last_seen": max(float(row["ts"]) for row in client_rows),
        }
        if r is None:
            entry.update({"verdict": "insufficient", "n_flags": 0,
                          "flags": [], "z": {}, "n_windows": 0})
        else:
            entry.update({
                "verdict": r["verdict"], "n_flags": r["n_flags"],
                "flags": sorted(r["flags"], key=lambda n: -r["z"][n]),
                "z": {k: round(v, 2) for k, v in r["z"].items()},
                "n_windows": r["n_windows"],
            })
            if r["verdict"] == "ATTACK":
                report["totals"]["attacks"] += 1
        report["clients"].append(entry)

    report["clients"].sort(key=lambda c: (-c["n_flags"], -c["requests"]))
    return report


@app.get("/api/verdicts")
def verdicts():
    return build_report()


@app.get("/api/health")
def health():
    return {"status": "ok", "log_exists": os.path.exists(LOG_PATH),
            "calibrated": os.path.exists(THRESHOLDS_PATH)}


PAGE = """<!doctype html>
<html><head><meta charset="utf-8"><title>Extraction Detector</title>
<style>
:root {
  --bg:#f7f7f5; --panel:#fff; --ink:#1a1a19; --muted:#6b6b66; --line:#e2e2dd;
  --alert:#b3261e; --alert-bg:#fdeceb; --ok:#1f6d3f; --accent:#2f5bd0;
}
@media (prefers-color-scheme: dark) { :root {
  --bg:#16161a; --panel:#1e1e23; --ink:#eaeae6; --muted:#9a9a94; --line:#2f2f36;
  --alert:#ff8a80; --alert-bg:#3a1f1d; --ok:#7ddba3; --accent:#8fb0ff;
} }
* { box-sizing:border-box; }
body { margin:0; background:var(--bg); color:var(--ink);
  font:14px/1.5 ui-sans-serif,system-ui,-apple-system,Segoe UI,Roboto,sans-serif; }
.wrap { max-width:1100px; margin:0 auto; padding:24px 20px 60px; }
h1 { font-size:20px; margin:0 0 2px; letter-spacing:-.01em; }
.sub { color:var(--muted); font-size:13px; margin-bottom:20px; }
.cards { display:flex; gap:12px; flex-wrap:wrap; margin-bottom:20px; }
.card { background:var(--panel); border:1px solid var(--line); border-radius:10px;
  padding:12px 16px; min-width:120px; }
.card .n { font-size:24px; font-weight:600; font-variant-numeric:tabular-nums; }
.card .l { color:var(--muted); font-size:12px; text-transform:uppercase;
  letter-spacing:.06em; }
.card.alert .n { color:var(--alert); }
.warn { background:var(--alert-bg); border:1px solid var(--alert); color:var(--alert);
  padding:10px 14px; border-radius:8px; margin-bottom:18px; font-size:13px; }
.tablewrap { overflow-x:auto; background:var(--panel); border:1px solid var(--line);
  border-radius:10px; }
table { border-collapse:collapse; width:100%; min-width:760px; }
th { text-align:left; font-size:11px; text-transform:uppercase; letter-spacing:.06em;
  color:var(--muted); font-weight:600; padding:10px 14px;
  border-bottom:1px solid var(--line); white-space:nowrap; }
td { padding:10px 14px; border-bottom:1px solid var(--line);
  font-variant-numeric:tabular-nums; vertical-align:top; }
tr:last-child td { border-bottom:none; }
.key { font-family:ui-monospace,SFMono-Regular,Menlo,monospace; font-size:13px; }
.badge { display:inline-block; padding:2px 8px; border-radius:999px; font-size:11px;
  font-weight:600; letter-spacing:.04em; }
.badge.attack { background:var(--alert-bg); color:var(--alert); }
.badge.benign { background:transparent; color:var(--ok); border:1px solid var(--ok); }
.badge.other { background:transparent; color:var(--muted); border:1px solid var(--line); }
.feats { color:var(--muted); font-size:12px; font-family:ui-monospace,monospace; }
.feats b { color:var(--alert); font-weight:600; }
.foot { margin-top:16px; color:var(--muted); font-size:12px; }
.dot { display:inline-block; width:7px; height:7px; border-radius:50%;
  background:var(--ok); margin-right:6px; vertical-align:middle; }
</style></head>
<body><div class="wrap">
<h1>Extraction detector</h1>
<div class="sub" id="sub">loading&hellip;</div>
<div id="warn"></div>
<div class="cards" id="cards"></div>
<div class="tablewrap"><table>
<thead><tr><th>API key</th><th>Requests</th><th>Windows</th><th>Flags</th>
<th>Verdict</th><th>Features flagged (robust z)</th></tr></thead>
<tbody id="rows"></tbody></table></div>
<div class="foot" id="foot"></div>
</div>
<script>
const RULE = {zflag: __ZFLAG__, minflags: __MINFLAGS__};
function esc(s){ return String(s).replace(/[&<>]/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;'}[c])); }
function ago(ts){ const d = Date.now()/1000 - ts;
  if (d < 60) return Math.round(d)+'s ago';
  if (d < 3600) return Math.round(d/60)+'m ago';
  return Math.round(d/3600)+'h ago'; }
async function tick(){
  let r;
  try { r = await (await fetch('/api/verdicts')).json(); }
  catch(e){ document.getElementById('sub').textContent = 'dashboard cannot reach its own API'; return; }
  document.getElementById('sub').innerHTML = '<span class="dot"></span>watching <code>'
    + esc(r.log_path) + '</code> &middot; flag at z &ge; ' + RULE.zflag
    + ', attack at &ge; ' + RULE.minflags + ' flags'
    + (r.baseline ? ' &middot; baseline: ' + r.baseline.n_windows + ' benign windows from '
       + r.baseline.n_clients + ' clients, window ' + r.baseline.window : '');
  document.getElementById('warn').innerHTML = r.warning
    ? '<div class="warn">' + esc(r.warning) + '</div>' : '';
  document.getElementById('cards').innerHTML = [
    ['Requests', r.totals.requests, ''],
    ['Clients', r.totals.clients, ''],
    ['Flagged', r.totals.attacks, r.totals.attacks ? 'alert' : '']
  ].map(([l,n,c]) => '<div class="card '+c+'"><div class="n">'+n+'</div><div class="l">'+l+'</div></div>').join('');
  document.getElementById('rows').innerHTML = r.clients.map(c => {
    const cls = c.verdict === 'ATTACK' ? 'attack' : (c.verdict === 'benign' ? 'benign' : 'other');
    const feats = c.flags.length
      ? c.flags.map(f => '<b>' + esc(f) + '</b>(' + c.z[f] + ')').join(' &middot; ')
      : '<span style="opacity:.5">none</span>';
    return '<tr><td class="key">' + esc(c.api_key) + '</td><td>' + c.requests
      + '</td><td>' + c.n_windows + '</td><td>' + c.n_flags
      + '</td><td><span class="badge ' + cls + '">' + esc(c.verdict)
      + '</span></td><td class="feats">' + feats + '</td></tr>';
  }).join('') || '<tr><td colspan="6" style="opacity:.6">no traffic yet</td></tr>';
  document.getElementById('foot').textContent =
    'updated ' + new Date().toLocaleTimeString() + ' \\u00b7 refreshing every 3s';
}
tick(); setInterval(tick, 3000);
</script></body></html>"""


@app.get("/", response_class=HTMLResponse)
def index():
    return PAGE.replace("__ZFLAG__", str(Z_FLAG)).replace("__MINFLAGS__", str(MIN_FLAGS))
