$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $Root
$oldPath = [Environment]::GetEnvironmentVariable("PYTHONPATH", "Process")
if ([string]::IsNullOrEmpty($oldPath)) {
  $env:PYTHONPATH = $Root
} else {
  $env:PYTHONPATH = "$Root;$oldPath"
}
py -3 scripts/run_lab.py @args
