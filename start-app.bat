@echo off
setlocal
cd /d "%~dp0"
call :launch .venv
if not errorlevel 1 exit /b 0
call :launch tools
if not errorlevel 1 exit /b 0
echo Remote MCP could not start. Use Python 3.11+ with Tcl/Tk support and prepare a project environment:
echo   uv venv --python 3.11
echo   uv pip install -r requirements.txt
echo Fix the error above, then run start-app.bat again.
pause
exit /b 1

:launch
if not exist "%~1\Scripts\python.exe" exit /b 1
if not exist "%~1\Scripts\pythonw.exe" exit /b 1
"%~1\Scripts\python.exe" -B -c "import sys; assert sys.version_info >= (3, 11), 'Python 3.11+ is required'; import app, uvicorn; root = app.tk.Tk(); root.withdraw(); root.destroy()"
if errorlevel 1 exit /b 1
start "" "%~1\Scripts\pythonw.exe" -B app.py
exit /b %errorlevel%
