@echo off
setlocal
cd /d "%~dp0"
if "%PYTHONPATH%"=="" (
  set "PYTHONPATH=%CD%"
) else (
  set "PYTHONPATH=%CD%;%PYTHONPATH%"
)
py -3 scripts\run_lab.py %*
endlocal
