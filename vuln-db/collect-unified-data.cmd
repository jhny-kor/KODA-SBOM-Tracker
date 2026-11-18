@echo off
setlocal DisableDelayedExpansion
pushd "%~dp0" || exit /b 1

py.exe -3 -c "import sys; sys.exit(sys.version_info < (3, 12))" >nul 2>&1
if not errorlevel 1 goto run_py

for /d %%D in ("%LOCALAPPDATA%\Programs\Python\Python3*" "%ProgramFiles%\Python3*") do (
    "%%~fD\python.exe" -c "import sys; sys.exit(sys.version_info < (3, 12))" >nul 2>&1
    if not errorlevel 1 (
        set "PYTHON_EXE=%%~fD\python.exe"
        goto run_python
    )
)

python.exe -c "import sys; sys.exit(sys.version_info < (3, 12))" >nul 2>&1
if not errorlevel 1 (
    set "PYTHON_EXE=python.exe"
    goto run_python
)

echo Python 3.12 or newer is required. Install it and run this file again. 1>&2
set "RESULT=1"
goto finish

:run_py
py.exe -3 "%~dp0collect-windows-vulnerability-data.py" %*
set "RESULT=%ERRORLEVEL%"
goto finish

:run_python
"%PYTHON_EXE%" "%~dp0collect-windows-vulnerability-data.py" %*
set "RESULT=%ERRORLEVEL%"

:finish
popd
if "%~1"=="" pause
exit /b %RESULT%
