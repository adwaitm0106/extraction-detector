<#
  End-to-end smoke test for the victim API.

  Resolves the repo root from its own location, so it works no matter which
  directory you run it from. Starts the server on a spare port, waits for the
  model to load, exercises every documented request path, prints a pass/fail
  table, and always shuts the server down again.

  Usage:  powershell -ExecutionPolicy Bypass -File scripts\smoke_test.ps1
#>

$ErrorActionPreference = "Stop"

# --- Locate the project and its virtualenv, independent of the caller's cwd. ---
$Root   = Split-Path -Parent $PSScriptRoot
$Python = Join-Path $Root ".venv\Scripts\python.exe"
$Port   = 8071
$Base   = "http://127.0.0.1:$Port"

if (-not (Test-Path $Python)) {
    Write-Host "No virtualenv found at $Python" -ForegroundColor Red
    Write-Host "Create it first:" -ForegroundColor Yellow
    Write-Host "  cd `"$Root`""
    Write-Host "  python -m venv .venv"
    Write-Host "  .\.venv\Scripts\python.exe -m pip install -r api\requirements.txt"
    exit 1
}

# --- Log to a scratch file so a test run never pollutes the real capture. ---
$TestLog = Join-Path $env:TEMP "smoke_requests.jsonl"
if (Test-Path $TestLog) { Remove-Item $TestLog -Force }
$env:LOG_PATH = $TestLog

$results = @()
function Check($name, $expected, $actual, $detail) {
    $ok = ($expected -eq $actual)
    $script:results += [pscustomobject]@{
        Test = $name; Expect = $expected; Got = $actual
        Result = $(if ($ok) { "PASS" } else { "FAIL" }); Detail = $detail
    }
}

# --- Call the API and return status code + body. Windows PowerShell 5.1 throws
# --- on 4xx/5xx and has no -SkipHttpErrorCheck, so the status is recovered from
# --- the exception's response object instead.
function Call($method, $path, $headers, $body) {
    try {
        $r = Invoke-WebRequest -Uri "$Base$path" -Method $method -Headers $headers `
             -ContentType "application/json" -Body $body -TimeoutSec 30 -UseBasicParsing
        return @{ code = [int]$r.StatusCode; body = $r.Content }
    } catch {
        $resp = $_.Exception.Response
        if ($null -eq $resp) { return @{ code = -1; body = $_.Exception.Message } }
        $code = [int]$resp.StatusCode
        $text = ""
        try {
            $stream = $resp.GetResponseStream()
            $stream.Position = 0
            $text = (New-Object System.IO.StreamReader($stream)).ReadToEnd()
        } catch { }
        return @{ code = $code; body = $text }
    }
}

Write-Host "Starting API on port $Port ..." -ForegroundColor Cyan
$proc = Start-Process -FilePath $Python `
    -ArgumentList "-m","uvicorn","api.main:app","--host","127.0.0.1","--port","$Port" `
    -WorkingDirectory $Root -PassThru -WindowStyle Hidden

try {
    # --- Wait for startup; the first ever run downloads ~268MB of weights. ---
    $ready = $false
    Write-Host "Waiting for model to load (first run downloads ~268MB)..." -ForegroundColor Cyan
    foreach ($i in 1..150) {
        if ($proc.HasExited) { throw "Server exited early with code $($proc.ExitCode)." }
        try {
            $h = Invoke-RestMethod -Uri "$Base/health" -TimeoutSec 2
            if ($h.model_loaded) { $ready = $true; break }
        } catch { }
        Start-Sleep -Seconds 2
    }
    if (-not $ready) { throw "Server did not become ready in 300s." }
    Write-Host "Model loaded.`n" -ForegroundColor Green

    $key = @{ "X-API-Key" = "smoke-key" }

    $r = Call GET  "/health"  @{} $null
    Check "health returns ok" 200 $r.code $r.body

    $r = Call POST "/predict" $key '{"input":"This movie was absolutely fantastic."}'
    Check "valid request" 200 $r.code $r.body

    $r = Call POST "/predict" @{} '{"input":"hello"}'
    Check "missing API key" 401 $r.code $r.body

    $r = Call POST "/predict" @{ "X-API-Key" = "" } '{"input":"hello"}'
    Check "empty API key" 401 $r.code $r.body

    $r = Call POST "/predict" $key '{"input":"   "}'
    Check "whitespace-only input" 422 $r.code $r.body

    $r = Call POST "/predict" $key '{"input": broken'
    Check "malformed JSON" 422 $r.code $r.body

    $r = Call POST "/predict" $key '{"input": 42}'
    Check "non-string input" 422 $r.code $r.body

    $r = Call POST "/predict" $key '{"text":"hi"}'
    Check "missing input field" 422 $r.code $r.body

    $long = '{"input":"' + ("a" * 2001) + '"}'
    $r = Call POST "/predict" $key $long
    Check "input over 2000 chars" 422 $r.code $r.body

    $r = Call GET  "/stats" @{} $null
    Check "stats returns ok" 200 $r.code $r.body

    # --- Only the one successful /predict may appear in the log. ---
    # [string[]] is load-bearing: PowerShell 5.1 unwraps a single-element array
    # returned from an if-expression, which would turn $lines into a bare string
    # and make $lines[0] a single character.
    [string[]]$lines = @()
    if (Test-Path $TestLog) {
        $lines = @(Get-Content $TestLog | Where-Object { $_.Trim() })
    }
    Check "failed requests not logged" 1 $lines.Count "$($lines.Count) line(s) written"

    if ($lines.Count -ge 1) {
        $keys = ($lines[0] | ConvertFrom-Json).PSObject.Properties.Name | Sort-Object
        $want = @("api_key","confidence","input","latency_ms","predicted_label","ts")
        Check "log line has exactly 6 keys" ($want -join ",") ($keys -join ",") $lines[0]
    }
}
finally {
    if ($proc -and -not $proc.HasExited) { Stop-Process -Id $proc.Id -Force }
    Remove-Item Env:\LOG_PATH -ErrorAction SilentlyContinue
    if (Test-Path $TestLog) { Remove-Item $TestLog -Force }
}

# --- Report. Exit non-zero on any failure so CI can consume this later. ---
$results | Format-Table Test, Expect, Got, Result -AutoSize
$failed = @($results | Where-Object { $_.Result -eq "FAIL" })
if ($failed.Count -gt 0) {
    Write-Host "$($failed.Count) of $($results.Count) checks FAILED" -ForegroundColor Red
    $failed | ForEach-Object { Write-Host "  - $($_.Test): $($_.Detail)" -ForegroundColor Red }
    exit 1
}
Write-Host "All $($results.Count) checks passed." -ForegroundColor Green
