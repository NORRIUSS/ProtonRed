@echo off
REM Double-click launcher. Bypasses PowerShell execution policy for this run only.
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0start.ps1" %*
