@echo off
echo.
echo  ╔══════════════════════════════════════════════════╗
echo  ║         DPIForge — Starting All Services         ║
echo  ╚══════════════════════════════════════════════════╝
echo.

echo  [1/2] Starting Python FastAPI backend on http://localhost:8000 ...
start "DPIForge Backend" cmd /k "cd /d %~dp0backend && python -m uvicorn api.main:app --host 0.0.0.0 --port 8000 --reload"

timeout /t 2 /nobreak >nul

echo  [2/2] Starting Next.js frontend on http://localhost:3000 ...
start "DPIForge Frontend" cmd /k "cd /d %~dp0frontend && npm run dev"

echo.
echo  Both services are starting in separate windows.
echo  Frontend: http://localhost:3000
echo  Backend:  http://localhost:8000
echo  API Docs: http://localhost:8000/docs
echo.
pause
