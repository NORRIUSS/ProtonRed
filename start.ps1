<#
.SYNOPSIS
    ProtonRed Pentest Tool - self-contained launcher.

.DESCRIPTION
    Single script that bootstraps a fully portable runtime and launches the API.
    First run: downloads an embeddable Python into .\.runtime\python, bootstraps
    pip, installs requirements.txt locally. Subsequent runs reuse the cached
    runtime and start in seconds. Nothing is installed system-wide; the whole
    runtime lives inside the project folder, so the tool works on any Windows
    box without manual setup.

.PARAMETER Port
    TCP port to bind (default 8000).

.PARAMETER BindHost
    Address to bind (default 127.0.0.1). Use 0.0.0.0 to expose on the network.

.PARAMETER Reload
    Enable uvicorn --reload (dev auto-restart on file change).

.PARAMETER Reinstall
    Force re-install of Python dependencies even if already cached.

.PARAMETER NoBrowser
    Do not open the browser after the server is up.

.PARAMETER Force
    If the port is already in use, kill the listening process before starting.

.EXAMPLE
    .\start.ps1
.EXAMPLE
    .\start.ps1 -Port 8080 -Reload
#>
[CmdletBinding()]
param(
    [int]    $Port       = 8000,
    [string] $BindHost   = "0.0.0.0",
    [switch] $Reload,
    [switch] $Reinstall,
    [switch] $NoBrowser,
    [switch] $Force
)

$ErrorActionPreference = "Stop"
$ProgressPreference     = "SilentlyContinue"   # speeds up Invoke-WebRequest massively

# ---------------------------------------------------------------------------
# Pinned portable runtime
# ---------------------------------------------------------------------------
$PyVersion   = "3.11.9"
$GetPipUrl   = "https://bootstrap.pypa.io/get-pip.py"

$Root        = Split-Path -Parent $MyInvocation.MyCommand.Definition
$RuntimeDir  = Join-Path $Root ".runtime"
$PyDir       = Join-Path $RuntimeDir "python"
$PyExe       = Join-Path $PyDir "python.exe"
$ReqFile     = Join-Path $Root "requirements.txt"
$DepsMarker  = Join-Path $RuntimeDir ".deps.sha256"
$AtomicsDir  = Join-Path $Root "atomics"

function Write-Step($msg) { Write-Host "==> $msg" -ForegroundColor Cyan }
function Write-Ok  ($msg) { Write-Host "    $msg"  -ForegroundColor Green }
function Write-Warn2($msg){ Write-Host "    $msg"  -ForegroundColor Yellow }

# ---------------------------------------------------------------------------
# 1. Portable Python (embeddable distribution, vendored into the project)
# ---------------------------------------------------------------------------
function Initialize-Python {
    if (Test-Path $PyExe) { Write-Ok "Python runtime present: $PyExe"; return }

    Write-Step "Bootstrapping portable Python $PyVersion (first run only)..."
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

    $arch = if ($env:PROCESSOR_ARCHITECTURE -eq "ARM64") { "arm64" } else { "amd64" }
    $zipName = "python-$PyVersion-embed-$arch.zip"
    $zipUrl  = "https://www.python.org/ftp/python/$PyVersion/$zipName"
    $zipPath = Join-Path $RuntimeDir $zipName

    New-Item -ItemType Directory -Force -Path $RuntimeDir | Out-Null

    Write-Ok "Downloading $zipUrl"
    Invoke-WebRequest -Uri $zipUrl -OutFile $zipPath

    Write-Ok "Extracting -> $PyDir"
    if (Test-Path $PyDir) { Remove-Item -Recurse -Force $PyDir }
    Expand-Archive -Path $zipPath -DestinationPath $PyDir -Force
    Remove-Item $zipPath -Force

    # Embeddable Python disables `site` by default; enable it so pip + installed
    # packages in Lib\site-packages are importable.
    $pth = Get-ChildItem -Path $PyDir -Filter "python*._pth" | Select-Object -First 1
    if ($pth) {
        $lines = Get-Content $pth.FullName
        $lines = $lines | ForEach-Object { $_ -replace '^\s*#\s*import\s+site', 'import site' }
        if (-not ($lines -match 'Lib\\site-packages')) { $lines += 'Lib\site-packages' }
        Set-Content -Path $pth.FullName -Value $lines -Encoding ASCII
    }

    Write-Ok "Bootstrapping pip..."
    $getPip = Join-Path $RuntimeDir "get-pip.py"
    Invoke-WebRequest -Uri $GetPipUrl -OutFile $getPip
    & $PyExe $getPip --no-warn-script-location
    if ($LASTEXITCODE -ne 0) { throw "get-pip failed (exit $LASTEXITCODE)" }
    Remove-Item $getPip -Force

    & $PyExe -m pip install --upgrade pip setuptools wheel --no-warn-script-location
    if ($LASTEXITCODE -ne 0) { throw "pip/setuptools bootstrap failed (exit $LASTEXITCODE)" }

    Write-Ok "Portable Python ready."
}

# ---------------------------------------------------------------------------
# 2. Dependencies (cached via requirements.txt hash)
# ---------------------------------------------------------------------------
function Initialize-Deps {
    if (-not (Test-Path $ReqFile)) { throw "requirements.txt not found at $ReqFile" }

    $reqHash = (Get-FileHash -Path $ReqFile -Algorithm SHA256).Hash
    $cached  = if (Test-Path $DepsMarker) { (Get-Content $DepsMarker -Raw).Trim() } else { "" }

    if (-not $Reinstall -and $reqHash -eq $cached) {
        Write-Ok "Dependencies up to date (cached)."
        return
    }

    Write-Step "Installing dependencies from requirements.txt..."
    & $PyExe -m pip install -r $ReqFile --no-warn-script-location
    if ($LASTEXITCODE -ne 0) { throw "pip install -r requirements.txt failed (exit $LASTEXITCODE)" }

    Set-Content -Path $DepsMarker -Value $reqHash -Encoding ASCII
    Write-Ok "Dependencies installed."
}

# ---------------------------------------------------------------------------
# 3. Atomic Red Team data
# ---------------------------------------------------------------------------
function Initialize-Atomics {
    $hasData = (Test-Path $AtomicsDir) -and `
               ((Get-ChildItem $AtomicsDir -Directory -ErrorAction SilentlyContinue | Measure-Object).Count -gt 0)
    if ($hasData) {
        $n = (Get-ChildItem $AtomicsDir -Directory).Count
        Write-Ok "Atomics present ($n technique folders)."
        return
    }

    Write-Warn2 "Atomics missing at $AtomicsDir"
    $git = Get-Command git -ErrorAction SilentlyContinue
    if (-not $git) {
        Write-Warn2 "git not found - clone manually:"
        Write-Warn2 "  git clone https://github.com/redcanaryco/atomic-red-team atomics-repo"
        Write-Warn2 "  then move atomics-repo\atomics -> $AtomicsDir"
        return
    }
    Write-Step "Cloning Atomic Red Team (shallow)..."
    $tmp = Join-Path $RuntimeDir "atomics-repo"
    if (Test-Path $tmp) { Remove-Item -Recurse -Force $tmp }
    & git clone --depth 1 https://github.com/redcanaryco/atomic-red-team $tmp
    if ($LASTEXITCODE -ne 0) { throw "git clone failed (exit $LASTEXITCODE)" }
    Move-Item (Join-Path $tmp "atomics") $AtomicsDir
    Remove-Item -Recurse -Force $tmp
    Write-Ok "Atomics ready."
}

# ---------------------------------------------------------------------------
# 4. Port check
# ---------------------------------------------------------------------------
function Test-Port {
    $conn = Get-NetTCPConnection -LocalPort $Port -State Listen -ErrorAction SilentlyContinue | Select-Object -First 1
    if (-not $conn) { return }

    $procId = $conn.OwningProcess
    $pname = (Get-Process -Id $procId -ErrorAction SilentlyContinue).ProcessName
    if ($Force) {
        Write-Warn2 "Port $Port in use by PID $procId ($pname) - killing (-Force)."
        Stop-Process -Id $procId -Force
        Start-Sleep -Milliseconds 500
    } else {
        throw "Port $Port already in use by PID $procId ($pname). Use -Force to kill it, or -Port <n> for another port."
    }
}

# ---------------------------------------------------------------------------
# Run
# ---------------------------------------------------------------------------
Push-Location $Root
try {
    Write-Host ""
    Write-Host "  ProtonRed Pentest Tool - launcher" -ForegroundColor Magenta
    Write-Host "  -------------------------------------------" -ForegroundColor Magenta

    Initialize-Python
    Initialize-Deps
    Initialize-Atomics
    Test-Port

    # Ensure firewall allows inbound on the chosen port.
    $ruleName = "ProtonRed Pentest Tool port $Port"
    $existing = Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue
    if (-not $existing) {
        try {
            New-NetFirewallRule -DisplayName $ruleName -Direction Inbound -Protocol TCP -LocalPort $Port -Action Allow | Out-Null
            Write-Ok "Firewall rule added: TCP $Port inbound allowed."
        } catch {
            Write-Warn2 "Could not add firewall rule (run as admin to allow network access): $_"
        }
    }

    $url = "http://$BindHost`:$Port"
    if ($BindHost -eq "0.0.0.0") { $url = "http://localhost`:$Port" }

    Write-Step "Starting server at $url"
    if (-not $NoBrowser) {
        Start-Job -ScriptBlock {
            param($u)
            Start-Sleep -Seconds 3
            Start-Process $u
        } -ArgumentList $url | Out-Null
    }

    $uvArgs = @("-m", "uvicorn", "api.main:app", "--host", $BindHost, "--port", "$Port")
    if ($Reload) { $uvArgs += "--reload" }

    Write-Ok "Ctrl+C to stop."
    Write-Host ""
    & $PyExe @uvArgs
}
finally {
    Pop-Location
}
