@echo off
REM Installation script for Threat Intelligence MCP Server (Windows)

echo Installing Threat Intelligence MCP Server...

REM Check prerequisites
echo Checking prerequisites...

REM Check Python
python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo Python 3 is required but not installed.
    echo Please install Python 3 and try again.
    pause
    exit /b 1
)

echo All prerequisites met!

REM Create virtual environment
echo Creating Python virtual environment...
python -m venv venv

REM Activate virtual environment
call venv\Scripts\activate.bat

REM Install Python dependencies
echo Installing Python dependencies...
python -m pip install --upgrade pip
pip install -r requirements.txt

REM Copy environment configuration
if not exist .env (
    echo Creating environment configuration...
    copy .env.example .env
    echo Please edit .env file with your API keys before starting the server.
)

REM Create intel logs directory
if not exist intel_logs mkdir intel_logs

REM Create cache directory
if not exist intel_cache mkdir intel_cache

echo Installation complete!
echo.
echo Next steps:
echo 1. Get API keys from threat intelligence providers:
echo    - VirusTotal: https://www.virustotal.com/gui/join-us
echo    - Shodan: https://account.shodan.io/
echo    - Have I Been Pwned: https://haveibeenpwned.com/API/Key
echo    - AbuseIPDB: https://www.abuseipdb.com/api
echo    - And others listed in README.md
echo.
echo 2. Edit .env file with your API keys
echo 3. Review config.yaml for server settings
echo 4. Start the server with: python -m threat_intel_mcp_server.main
echo 5. Or use Docker: docker-compose up -d
echo.
echo For more information, see README.md

pause