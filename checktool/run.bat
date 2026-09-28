@echo off
REM Launch the AuthGlow checktool from cmd.exe or by double-click.
REM Passes every argument through to run.ps1, e.g.:
REM   run.bat --all
REM   run.bat --groups auth,rbac
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0run.ps1" %*
