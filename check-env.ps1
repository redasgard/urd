# Pre-flight environment check for the Urd lab -- no Python required to run this.
#
# Tells you which of the three lab paths (Docker / local Python / static
# traces) you're actually on, before you spend your 3 minutes finding out the
# hard way. See TACTIC_GUIDE.md for what each path means.

Write-Host "Urd lab -- environment check"
Write-Host ""

function Test-PythonCmd {
    param($Exe, $ExtraArgs)
    if (-not (Get-Command $Exe -ErrorAction SilentlyContinue)) { return $null }
    try {
        $allArgs = $ExtraArgs + @("-c", "import sys; print(f'{sys.version_info[0]}.{sys.version_info[1]}')")
        $ver = & $Exe @allArgs 2>$null
        return $ver
    } catch {
        return $null
    }
}

function Test-VersionOk {
    # >= 3.11, and forward-compatible with a hypothetical Python 4.0+
    param($Parts)
    $major = [int]$Parts[0]
    $minor = [int]$Parts[1]
    return ($major -gt 3) -or ($major -eq 3 -and $minor -ge 11)
}

$dockerOk = $false
if (Get-Command docker -ErrorAction SilentlyContinue) {
    docker info *> $null
    if ($LASTEXITCODE -eq 0) {
        $dockerOk = $true
        Write-Host "  [x] Docker found and daemon is running"
    } else {
        Write-Host "  [ ] Docker found but daemon is not running (start Docker Desktop)"
    }
} else {
    Write-Host "  [ ] Docker not found"
}

$pythonOk = $false
$pythonLabel = $null

$ver = Test-PythonCmd -Exe "py" -ExtraArgs @("-3")
if ($ver) {
    $parts = $ver -split "\."
    if (Test-VersionOk $parts) {
        $pythonOk = $true
        $pythonLabel = "py -3"
        Write-Host "  [x] py -3 -> Python $ver found (>= 3.11)"
    } else {
        Write-Host "  [ ] py -3 -> Python $ver found, but too old (need 3.11+)"
    }
}

if (-not $pythonOk) {
    foreach ($exe in @("python3", "python")) {
        $ver = Test-PythonCmd -Exe $exe -ExtraArgs @()
        if ($ver) {
            $parts = $ver -split "\."
            if (Test-VersionOk $parts) {
                $pythonOk = $true
                $pythonLabel = $exe
                Write-Host "  [x] $exe -> Python $ver found (>= 3.11)"
                break
            } else {
                Write-Host "  [ ] $exe -> Python $ver found, but too old (need 3.11+)"
            }
        }
    }
}

if (-not $pythonOk -and -not $pythonLabel) {
    Write-Host "  [ ] No Python 3.11+ found"
}

Write-Host ""
if ($dockerOk) {
    Write-Host "-> Use Docker:"
    Write-Host "     docker compose build"
    Write-Host "     docker compose run --rm urd-lab ./lab.sh run"
} elseif ($pythonOk) {
    Write-Host "-> Use local Python ($pythonLabel):"
    Write-Host "     .\lab.ps1 run"
} else {
    Write-Host "-> Neither found. That's fine -- read the attack instead:"
    Write-Host "     see 'No laptop? Read the attack instead' in TACTIC_GUIDE.md"
}
