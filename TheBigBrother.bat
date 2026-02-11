@echo off
cls
echo.
echo  Launching The Big Brother...
echo.
cd "%~dp0"
start http://127.0.0.1:31337
python -m uvicorn the_big_brother.gui.main:app --port 31337
exit