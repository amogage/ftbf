@echo off
REM ============================================
REM Build FTBF Framework for x86 (IA32)
REM ============================================

setlocal enabledelayedexpansion

REM Get the directory where this script is located
set "SCRIPT_DIR=%~dp0"
set "FTBF_DIR=%SCRIPT_DIR%source\tools\FTBF"
set "RUST_DIR=%FTBF_DIR%\ftbf_rust"

echo ============================================
echo Building FTBF Framework for x86
echo ============================================
echo.

REM Step 1: Build Rust library
echo [1/4] Building Rust library for i686-pc-windows-msvc...
cd /d "%RUST_DIR%"
if errorlevel 1 (
    echo ERROR: Failed to change to Rust directory
    exit /b 1
)
cargo build --release --target i686-pc-windows-msvc
if errorlevel 1 (
    echo ERROR: Rust build failed
    exit /b 1
)
echo Rust build successful.
echo.

REM Step 2: Copy the Rust library to target directory
echo [2/4] Copying Rust library...
if not exist "%RUST_DIR%\target" mkdir "%RUST_DIR%\target"
copy /Y "%RUST_DIR%\target\i686-pc-windows-msvc\release\ftbf_rust.lib" "%RUST_DIR%\target\ftbf_rust.lib"
if errorlevel 1 (
    echo ERROR: Failed to copy Rust library
    exit /b 1
)
echo Library copied successfully.
echo.

REM Step 3: Remove build folder if it exists
echo [3/4] Cleaning obj-ia32 build folder...
cd /d "%FTBF_DIR%"
if exist "obj-ia32" (
    rmdir /s /q "obj-ia32"
    echo Build folder removed.
) else (
    echo Build folder does not exist, skipping.
)
echo.

REM Step 4: Set up Visual Studio environment and build with make
echo [4/4] Building PIN tool with Visual Studio x86 environment...
REM Try different VS versions - adjust path as needed for your installation
if exist "C:\Program Files\Microsoft Visual Studio\18\Community\VC\Auxiliary\Build\vcvars32.bat" (
    call "C:\Program Files\Microsoft Visual Studio\18\Community\VC\Auxiliary\Build\vcvars32.bat"
) else if exist "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars32.bat" (
    call "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars32.bat"
) else if exist "C:\Program Files\Microsoft Visual Studio\2019\Community\VC\Auxiliary\Build\vcvars32.bat" (
    call "C:\Program Files\Microsoft Visual Studio\2019\Community\VC\Auxiliary\Build\vcvars32.bat"
) else if exist "C:\Program Files (x86)\Microsoft Visual Studio\2019\BuildTools\VC\Auxiliary\Build\vcvars32.bat" (
    call "C:\Program Files (x86)\Microsoft Visual Studio\2019\BuildTools\VC\Auxiliary\Build\vcvars32.bat"
) else (
    echo ERROR: Could not find Visual Studio installation
    exit /b 1
)
if errorlevel 1 (
    echo ERROR: Failed to set up Visual Studio environment
    exit /b 1
)

make obj-ia32/FTBF.dll
if errorlevel 1 (
    echo ERROR: PIN tool build failed
    exit /b 1
)

echo.
echo ============================================
echo Build completed successfully!
echo Output: %FTBF_DIR%\obj-ia32\FTBF.dll
echo ============================================

endlocal

