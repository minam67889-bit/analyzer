@echo off
setlocal
cd /d "%~dp0"
title Adversary Lab

echo Adversary Lab setup and launcher
echo.

if exist ".venv\Scripts\python.exe" goto install

rem Prefer the Windows Python launcher, but also support Python on PATH.
where py >nul 2>&1
if errorlevel 1 goto try_python
py -3 -c "import sys; sys.exit(sys.version_info[:2] < (3, 11))" >nul 2>&1
if errorlevel 1 goto try_python
py -3 -m venv .venv
if errorlevel 1 goto venv_error
goto install

:try_python
where python >nul 2>&1
if errorlevel 1 goto python_error
python -c "import sys; sys.exit(sys.version_info[:2] < (3, 11))" >nul 2>&1
if errorlevel 1 goto python_error
python -m venv .venv
if errorlevel 1 goto venv_error

:install
.venv\Scripts\python.exe -c "import sys; sys.exit(sys.version_info[:2] < (3, 11))" >nul 2>&1
if errorlevel 1 goto python_error

echo Installing or updating project dependencies. Internet may be required...
.venv\Scripts\python.exe -m pip install -e ".[windows,ui,crypto]"
if errorlevel 1 goto install_error

if exist "config\lab.toml" goto launch
copy "config\lab.example.toml" "config\lab.toml" >nul
if errorlevel 1 goto config_error
echo Created config\lab.toml from the example. Edit it for your authorized lab.

:launch
echo.
echo Starting the desktop app in dry-run mode.
echo Live hardware capabilities require separate setup and validation.
.venv\Scripts\python.exe -m adversarylab.ui.app --config config\lab.toml
if errorlevel 1 goto launch_error
exit /b 0

:python_error
echo ERROR: Python 3.11 or newer was not found or the virtual environment is invalid.
echo Install Python from https://www.python.org/downloads/windows/ and try again.
goto failed

:venv_error
echo ERROR: Could not create the Python virtual environment.
goto failed

:install_error
echo ERROR: Dependency installation failed. Check the messages above and your internet connection.
goto failed

:config_error
echo ERROR: Could not create config\lab.toml. Check folder permissions.
goto failed

:launch_error
echo ERROR: The application could not start. Check the messages above.

:failed
echo.
pause
exit /b 1
