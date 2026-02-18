@echo off
chcp 65001 > nul
echo ============================================
echo  Sacabambaspis v3.1 - Build Script
echo ============================================
echo.
if exist "dist\Sacabambaspis.exe" (
    echo [*] Cleaning previous build...
    del /f "dist\Sacabambaspis.exe"
)
if exist "build" (
    echo [*] Cleaning build folder...
    rmdir /s /q build
)
echo [*] PyInstaller build starting...
echo.
pyinstaller main.spec --clean --noconfirm
if exist "dist\Sacabambaspis.exe" (
    echo.
    echo ============================================
    echo  BUILD SUCCESS
    echo ============================================
    echo.
    for %%A in ("dist\Sacabambaspis.exe") do echo  File: %%~fA
    for %%A in ("dist\Sacabambaspis.exe") do echo  Size: %%~zA bytes
    echo.
    echo  Copy to USB and run as Administrator.
    echo ============================================
) else (
    echo.
    echo ============================================
    echo  BUILD FAILED - Check error log
    echo ============================================
)
echo.
pause
