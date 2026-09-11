<#
  Full end-to-end demo, built for screen recording.

  Runs the whole story in one command: starts the API, calibrates on benign
  traffic, then shows a quiet phase followed by an attacker being caught live
  in the console.

  Everything it starts, it stops -- including on Ctrl+C.

  Usage:
    powershell -ExecutionPolicy Bypass -File demo\run_demo.ps1
    powershell -ExecutionPolicy Bypass -File demo\run_demo.ps1 -SkipCalibration
#>

param(
    # Reuse an existing thresholds.json and benign_calib.jsonl instead of
    # regenerating them. Saves ~60s on a second take.
    [switch]$SkipCalibration,
    [int]$Port = 8000
)

$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $PSScriptRoot
$Python = Join-Path $Root ".venv\Scripts\python.exe"
$Base = "http://127.0.0.1:$Port"
$LogPath = Join-Path $Root "data\logs\requests.jsonl"
$CalibPath = Join-Path $Root "data\logs\benign_calib.jsonl"
$Thresholds = Join-Path $Root "thresholds.json"

# Every process this script starts, so the cleanup handler can find them.
$script:Started = @()

function Banner($text, $color = "Cyan") {
    $line = "=" * 74
    Write-Host ""
    Write-Host $line -ForegroundColor $color
    Write-Host ("  " + $text) -ForegroundColor $color
    Write-Host $line -ForegroundColor $color
    Write-Host ""
}

function Step($text) { Write-Host "  > $text" -ForegroundColor DarkGray }

# --- Cleanup runs from finally AND from Ctrl+C, so nothing is orphaned. ---
function Cleanup {
    Write-Host ""
    Write-Host "cleaning up..." -ForegroundColor DarkGray
    foreach ($p in $script:Started) {
        try {
            if ($p -and -not $p.HasExited) {
                Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue
                Write-Host "  stopped pid $($p.Id)" -ForegroundColor DarkGray
            }
        } catch { }
    }
    # Belt and braces: anything still holding the demo port.
    $conn = Get-NetTCPConnection -LocalPort $Port -State Listen -ErrorAction SilentlyContinue
    foreach ($c in $conn) {
        Stop-Process -Id $c.OwningProcess -Force -ErrorAction SilentlyContinue
        Write-Host "  released port $Port" -ForegroundColor DarkGray
    }
    $script:Started = @()
    Write-Host "done." -ForegroundColor DarkGray
}

# Ctrl+C in PowerShell raises a terminating error, which the trap catches;
# without this the API would survive the script.
trap { Cleanup; break }

# --- Live scoring, printed into THIS console so a screen recording catches
# --- it. Polls score.py --json and announces only newly-flagged keys, so the
# --- quiet phase stays quiet and the alert is unmissable when it lands.
function Watch-Inline($seconds, $announced) {
    $deadline = (Get-Date).AddSeconds($seconds)
    while ((Get-Date) -lt $deadline) {
        $scored = $false
        if (Test-Path $LogPath) {
            $raw = & $Python (Join-Path $Root "detector\score.py") `
                --log $LogPath --thresholds $Thresholds --json 2>$null
            if ($LASTEXITCODE -eq 0 -and $raw) {
                try { $v = ($raw -join "`n") | ConvertFrom-Json } catch { $v = $null }
                if ($v) {
                    $total = 0; $flagged = 0
                    foreach ($prop in $v.PSObject.Properties) {
                        $key = $prop.Name; $r = $prop.Value
                        $total += $r.n_requests
                        if ($r.verdict -ne "ATTACK") { continue }
                        $flagged++
                        $fp = ($r.flags | Sort-Object) -join ","
                        if ($announced[$key] -ne $fp) {
                            $announced[$key] = $fp
                            $sig = ($r.flags | Sort-Object { -$r.z.$_ } |
                                    ForEach-Object { "{0}({1:N1})" -f $_, $r.z.$_ }) -join ", "
                            Write-Host ""
                            Write-Host ("  [ALERT $(Get-Date -Format HH:mm:ss)] " +
                                "EXTRACTION SUSPECTED  api_key=$key  " +
                                "flags=$($r.n_flags)/10  requests=$($r.n_requests)") `
                                -ForegroundColor Red
                            Write-Host "      signals: $sig" -ForegroundColor Red
                            Write-Host ""
                        }
                    }
                    if ($flagged -eq 0) {
                        Write-Host "  [$(Get-Date -Format HH:mm:ss)] $total requests scored - all clean" `
                            -ForegroundColor Green
                    }
                    $scored = $true
                }
            }
        }
        # No client has a full window yet. Say so, rather than leaving the
        # screen dead for 20s while the first window fills.
        if (-not $scored) {
            $n = 0
            if (Test-Path $LogPath) {
                $n = @(Get-Content $LogPath | Where-Object { $_.Trim() }).Count
            }
            Write-Host ("  [$(Get-Date -Format HH:mm:ss)] $n requests seen - " +
                "collecting (need 30 per client before scoring)") -ForegroundColor DarkGray
        }
        Start-Sleep -Seconds 3
    }
}


function Start-Tracked($exe, $argList, $window = "Hidden") {
    $p = Start-Process -FilePath $exe -ArgumentList $argList `
        -WorkingDirectory $Root -PassThru -WindowStyle $window
    $script:Started += $p
    return $p
}

try {
    if (-not (Test-Path $Python)) {
        Write-Host "No virtualenv at $Python" -ForegroundColor Red
        Write-Host "Run:  python -m venv .venv"
        Write-Host "      .\.venv\Scripts\python.exe -m pip install -r api\requirements.txt"
        exit 1
    }

    Banner "EXTRACTION DETECTOR - LIVE DEMO" "Magenta"
    Write-Host "  A sentiment API is about to be cloned by an attacker."
    Write-Host "  The attacker will run at roughly one query per second --"
    Write-Host "  the same rate as a normal customer. No rate limit would fire."
    Write-Host ""

    # ---------------------------------------------------------------- API ---
    Step "starting the victim API on port $Port"
    $api = Start-Tracked $Python @("-m","uvicorn","api.main:app","--host","127.0.0.1","--port","$Port")

    Step "waiting for the model to load (first run downloads ~268MB)"
    $ready = $false
    foreach ($i in 1..150) {
        if ($api.HasExited) { throw "API exited early with code $($api.ExitCode)" }
        try {
            $h = Invoke-RestMethod -Uri "$Base/health" -TimeoutSec 2
            if ($h.model_loaded) { $ready = $true; break }
        } catch { }
        Start-Sleep -Seconds 2
    }
    if (-not $ready) { throw "API did not become ready within 300s." }
    Write-Host "  API ready: model_loaded=true" -ForegroundColor Green

    # -------------------------------------------------------- CALIBRATION ---
    if ($SkipCalibration -and (Test-Path $Thresholds)) {
        Step "reusing existing baseline (--SkipCalibration)"
    } else {
        Banner "CALIBRATION: learning what normal looks like" "Yellow"
        Write-Host "  Four ordinary customers, 45 queries each."
        Write-Host "  The detector sees ONLY benign traffic here -- it never"
        Write-Host "  learns any attack signature. That is what keeps the"
        Write-Host "  evaluation honest."
        Write-Host ""
        if (Test-Path $LogPath) { Remove-Item $LogPath -Force }
        $jobs = @()
        foreach ($i in 0..3) {
            $jobs += Start-Tracked $Python @("traffic/generate.py","--profile","benign",
                "--n","45","--rate","6","--jitter","0.5","--api-key","cal-user-$i",
                "--seed","$(100+$i)")
        }
        $jobs | ForEach-Object { $_.WaitForExit() }
        Move-Item $LogPath $CalibPath -Force
        Step "fitting the baseline"
        & $Python (Join-Path $Root "detector\calibrate.py") --log $CalibPath --out $Thresholds |
            Select-Object -First 1
        if (-not (Test-Path $Thresholds)) { throw "Calibration produced no thresholds.json" }
    }

    if (Test-Path $LogPath) { Remove-Item $LogPath -Force }

    # ------------------------------------------------------------ PHASE 1 ---
    Banner "PHASE 1: Normal traffic - watch the console" "Green"
    Write-Host "  Two ordinary customers are now querying the API."
    Write-Host "  The detector is watching live. Expect NO alerts." -ForegroundColor Green
    Write-Host ""

    $announced = @{}
    Step "two customers sending traffic; detector scoring live every 3s"
    foreach ($i in 0..1) {
        Start-Tracked $Python @("traffic/generate.py","--profile","benign",
            "--n","30","--rate","1.5","--jitter","0.5","--api-key","customer-$i",
            "--seed","$(200+$i)") | Out-Null
    }
    Watch-Inline 26 $announced
    Write-Host ""
    Write-Host "  Phase 1 over: no alerts, as expected." -ForegroundColor Green

    # ------------------------------------------------------------ PHASE 2 ---
    Banner "PHASE 2: Attacker starts now" "Red"
    Write-Host "  Same rate as the customers above. Poisson-spaced, so the"
    Write-Host "  timing looks human too. The only difference is WHAT it asks:"
    Write-Host "  systematic probes around the model's decision boundary."
    Write-Host ""
    Write-Host "  Watch for the ALERT line." -ForegroundColor Red
    Write-Host ""

    Start-Tracked $Python @("traffic/generate.py","--profile","boundary",
        "--n","40","--rate","1.5","--attacker-pacing","poisson",
        "--api-key","extraction-attacker","--seed","303") | Out-Null
    Watch-Inline 32 $announced

    # ------------------------------------------------------------- RESULT ---
    Banner "RESULT" "Magenta"
    & $Python (Join-Path $Root "detector\score.py") --log $LogPath --thresholds $Thresholds
    Write-Host ""
    & $Python (Join-Path $Root "eval\evaluate.py") --log $LogPath `
        --thresholds $Thresholds --attack-prefix extraction-
    Banner "DEMO COMPLETE" "Magenta"
}
finally {
    Cleanup
}
