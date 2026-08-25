# Brings GuardGraph AI up in the order its dependencies actually require.
#
# This exists because the failure it prevents already happened: the Neo4j
# container was stopped, `restart: unless-stopped` deliberately does not restart
# an explicitly-stopped container, and the app came up perfectly happy - hot-path
# caching, sample correlation and the threat landscape all returning empty
# without raising anything. On demo day that looks like a working system with
# nothing in it.
#
#   .\demo.ps1              start everything and run the API in the foreground
#   .\demo.ps1 -NoServe     bring dependencies up and check them, then stop
#
# Safe to re-run. The ontology load is MERGE-based, so it is idempotent.

param([switch]$NoServe)

$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot

$python = ".\.venv\Scripts\python.exe"
if (-not (Test-Path $python)) {
    Write-Host "No virtualenv at $python. Create it first: python -m venv .venv" -ForegroundColor Red
    exit 1
}

Write-Host "`n[1/4] Starting Neo4j..." -ForegroundColor Cyan
docker compose up -d
if ($LASTEXITCODE -ne 0) {
    Write-Host "docker compose failed. Is Docker Desktop running?" -ForegroundColor Red
    exit 1
}

# Bolt accepts connections a few seconds after the container reports running, so
# poll the port rather than sleeping a guessed amount.
Write-Host "[2/4] Waiting for bolt on 127.0.0.1:7687..." -ForegroundColor Cyan
$deadline = (Get-Date).AddSeconds(90)
$ready = $false
while ((Get-Date) -lt $deadline) {
    try {
        $probe = New-Object System.Net.Sockets.TcpClient
        $probe.Connect("127.0.0.1", 7687)
        $probe.Close()
        $ready = $true
        break
    } catch {
        Start-Sleep -Seconds 2
    }
}
if (-not $ready) {
    Write-Host "Bolt did not open within 90s. Check: docker compose logs neo4j" -ForegroundColor Red
    exit 1
}
Write-Host "      bolt is open." -ForegroundColor DarkGray

Write-Host "[3/4] Loading the MITRE ATT&CK Mobile ontology (idempotent)..." -ForegroundColor Cyan
& $python scripts\load_ontology.py
if ($LASTEXITCODE -ne 0) {
    Write-Host "Ontology load failed. Reports will fall back to the local JSON ontology." -ForegroundColor Yellow
}

# Report what is actually in the graph before serving, so an empty or partial
# database is visible now rather than during a demo.
Write-Host "[4/4] Graph contents:" -ForegroundColor Cyan
# Single-quoted on purpose. PowerShell rewrites double quotes when it builds the
# argument list for a native executable, so "." reaches python as a bare . and the
# snippet dies with a SyntaxError. Python treats the two quote styles identically.
& $python -c @'
import sys
sys.path.insert(0, '.')
from app.graph.ontology import graph_health
h = graph_health()
print('      ' + h['detail'])
sys.exit(0 if h['reachable'] and h['grounded_techniques'] else 1)
'@
if ($LASTEXITCODE -ne 0) {
    Write-Host "      Graph is unreachable or ungrounded - see the message above." -ForegroundColor Yellow
}

if ($NoServe) {
    Write-Host "`nDependencies are up. Start the API with:" -ForegroundColor Green
    Write-Host "  .\.venv\Scripts\python.exe -m uvicorn app.main:app --port 8000`n"
    exit 0
}

Write-Host "`nStarting the API on http://localhost:8000 (Ctrl+C to stop)." -ForegroundColor Green
Write-Host "The first report pays a one-time Ollama model load; the header pills show when it is ready.`n" -ForegroundColor DarkGray
& $python -m uvicorn app.main:app --port 8000
