@echo off
echo.
echo ============================================================
echo  Starting Secure ML Prediction API
echo ============================================================
echo.

cd /d "%~dp0"

REM Activate virtual environment if it exists
if exist venv\Scripts\activate.bat (
    call venv\Scripts\activate.bat
)

REM Start the secure API
python security/SECURITY_6_secure_ml_api.py

pause
