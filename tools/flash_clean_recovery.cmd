@echo off
setlocal
uv run --no-project --with esptool==5.6.0 python "%~dp0flash_app.py" --factory-reset %*
exit /b %errorlevel%
