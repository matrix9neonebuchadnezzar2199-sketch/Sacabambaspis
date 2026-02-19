@echo off
chcp 65001 > nul
echo ========================================
echo   Sacabambaspis Build Script v3.2
echo ========================================
echo.

where pyinstaller >nul 2>nul
if errorlevel 1 (
    echo [ERROR] ERR-BUILD-001: PyInstaller ga mitsukarimasen.
    echo   pip install pyinstaller wo jikkou shitekudasai.
    echo.
    pause
    exit /b 1
)

if not exist "main.py" (
    echo [ERROR] ERR-BUILD-002: main.py ga mitsukarimasen.
    echo   Sacabambaspis no root folder de jikkou shitekudasai.
    echo.
    pause
    exit /b 1
)

if not exist "Sacabambaspis.spec" (
    echo [ERROR] ERR-BUILD-003: Sacabambaspis.spec ga mitsukarimasen.
    echo.
    pause
    exit /b 1
)

echo Build start...
echo.
pyinstaller Sacabambaspis.spec --clean

echo.
if exist "dist\Sacabambaspis.exe" (
    echo ========================================
    echo   Build OK
    echo ========================================
    for %%A in ("dist\Sacabambaspis.exe") do echo   Size: %%~zA bytes
    echo   Output: dist\Sacabambaspis.exe
) else (
    echo ========================================
    echo   ERR-BUILD-004: Build FAILED
    echo ========================================
    echo   Check build folder logs.
)
echo.
pause
