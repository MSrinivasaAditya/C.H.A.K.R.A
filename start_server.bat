@echo off
setlocal EnableDelayedExpansion

cd /d "%~dp0"

:: ── Virtualenv ────────────────────────────────────────────────────────────────
if not exist "venv\" (
    echo [CHAKRA] Creating Python virtual environment...
    python -m venv venv
    if errorlevel 1 (
        echo [CHAKRA] ERROR: Failed to create venv. Is Python 3.11+ installed?
        pause
        exit /b 1
    )
)

:: ── Activate ──────────────────────────────────────────────────────────────────
call venv\Scripts\activate.bat

:: ── Dependencies ──────────────────────────────────────────────────────────────
echo [CHAKRA] Installing dependencies...
pip install -q -r requirements.txt
if errorlevel 1 (
    echo [CHAKRA] ERROR: pip install failed. Check your internet connection.
    pause
    exit /b 1
)

:: ── Environment file ──────────────────────────────────────────────────────────
if not exist ".env" (
    echo [CHAKRA] No .env found - copying .env.example to .env
    copy /Y ".env.example" ".env" >nul
    echo [CHAKRA] Edit .env to set your ANTHROPIC_API_KEY before using.
)

:: ── Start server ──────────────────────────────────────────────────────────────
echo [CHAKRA] Starting server... (logs: chakra.log)

:: Use start /B with pythonw so the terminal can be closed
set PORT=7777
for /f "tokens=2 delims==" %%A in ('findstr /i "^PORT=" .env 2^>nul') do set PORT=%%A

start /B pythonw -m backend.chakra_server >> chakra.log 2>&1

timeout /t 2 /nobreak >nul

echo.
echo   C.H.A.K.R.A is running  -^>  http://127.0.0.1:%PORT%
echo   Dashboard               -^>  http://127.0.0.1:%PORT%/dashboard
echo   Logs: %~dp0chakra.log
echo.
echo   You may close this window. The server continues running in the background.
echo.
pause
