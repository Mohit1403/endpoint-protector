# AutoPentrix Server Startup Script
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  AutoPentrix Penetration Testing Tool" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# Check if Node.js is installed
try {
    $nodeVersion = node --version
    Write-Host "✓ Node.js version: $nodeVersion" -ForegroundColor Green
} catch {
    Write-Host "✗ Node.js is not installed or not in PATH" -ForegroundColor Red
    Write-Host "  Please install Node.js from https://nodejs.org/" -ForegroundColor Yellow
    exit 1
}

# Check if dependencies are installed
if (-not (Test-Path "node_modules")) {
    Write-Host "Installing dependencies..." -ForegroundColor Yellow
    npm install
}

Write-Host ""
Write-Host "Starting server on http://localhost:3000" -ForegroundColor Green
Write-Host ""
Write-Host "Dashboard URL: http://localhost:3000" -ForegroundColor Cyan
Write-Host ""
Write-Host "To start the Python endpoint agent in another terminal:" -ForegroundColor Yellow
Write-Host "  python3 enterprise_endpoint_agent.py" -ForegroundColor White
Write-Host ""
Write-Host "Press Ctrl+C to stop the server" -ForegroundColor Yellow
Write-Host ""

# Start the server
node index.js

