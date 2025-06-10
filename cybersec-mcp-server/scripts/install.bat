@echo off
REM Installation script for Cybersecurity MCP Server (Windows)

echo Installing Cybersecurity MCP Server...

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

REM Check Docker
docker --version >nul 2>&1
if %errorlevel% neq 0 (
    echo Docker is required but not installed.
    echo Please install Docker Desktop and try again.
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
    echo Please edit .env file with your configuration before starting the server.
)

REM Pull Docker images
echo Pulling Docker images...
docker pull kalilinux/kali-rolling

REM Create audit logs directory
if not exist audit_logs mkdir audit_logs

echo Installation complete!
echo.
echo Next steps:
echo 1. Edit .env file with your configuration
echo 2. Review config.yaml for security settings  
echo 3. Start the server with: docker-compose up -d
echo 4. Test with: python -m cybersec_mcp_server.main
echo.
echo For more information, see README.md

pause
