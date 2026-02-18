@echo off
chcp 65001 > nul
echo ============================================
echo  Sacabambaspis v3.0 Forensic Scanner
echo ============================================
echo.
if exist "%~dp0Sacabambaspis.exe" (
    echo [*] Starting Sacabambaspis.exe...
    "%~dp0Sacabambaspis.exe"
) else if exist "%~dp0dist\Sacabambaspis.exe" (
    echo [*] Starting dist\Sacabambaspis.exe...
    "%~dp0dist\Sacabambaspis.exe"
) else (
    echo [!] EXE not found. Starting dev mode...
    cd /d "%~dp0"
    python main.py
)
if %ERRORLEVEL% neq 0 (
    echo.
    echo [!] Error occurred.
    pause
)
