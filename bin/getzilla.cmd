@echo off
rem getzilla: one command for the Getzilla tools; see `getzilla help`.
python "%~dp0..\scripts\getzilla_cli.py" %*
exit /b %ERRORLEVEL%
