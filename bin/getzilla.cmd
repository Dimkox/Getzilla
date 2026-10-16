@echo off
rem getzilla: one command for the Getzilla tools; see `getzilla help`.
if exist "%~dp0..\.venv\Scripts\python.exe" (
  "%~dp0..\.venv\Scripts\python.exe" "%~dp0..\scripts\getzilla_cli.py" %*
) else (
  python "%~dp0..\scripts\getzilla_cli.py" %*
)
exit /b %ERRORLEVEL%
