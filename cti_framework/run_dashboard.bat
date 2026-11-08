@echo off
title CTI SOC Operations Dashboard
echo ========================================================
echo   KHOI CHAY CTI SOC OPERATIONS DASHBOARD
echo   Local AI Agent Framework - Port 9090
echo ========================================================
echo.
cd /d "%~dp0"
echo Dang khoi dong may chu backend FastAPI va Dashboard...
start http://localhost:9090/
python web/app.py
pause
