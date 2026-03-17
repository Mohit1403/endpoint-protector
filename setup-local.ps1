# PowerShell script to set up the tool locally without Docker

Write-Host "Setting up Penetration Testing Tool locally..." -ForegroundColor Green

# Check if Node.js is installed
try {
    $nodeVersion = node --version
    Write-Host "Node.js version: $nodeVersion" -ForegroundColor Green
} catch {
    Write-Host "Node.js is not installed. Please install Node.js from https://nodejs.org/" -ForegroundColor Red
    exit 1
}

# Check if npm is installed
try {
    $npmVersion = npm --version
    Write-Host "npm version: $npmVersion" -ForegroundColor Green
} catch {
    Write-Host "npm is not installed. Please install Node.js which includes npm." -ForegroundColor Red
    exit 1
}

# Check if nmap is installed (optional for development)
try {
    nmap --version | Out-Null
    Write-Host "Nmap is available" -ForegroundColor Green
} catch {
    Write-Host "Warning: Nmap is not installed. Some scan features may not work." -ForegroundColor Yellow
    Write-Host "You can download Nmap from https://nmap.org/download.html" -ForegroundColor Yellow
}

# Install dependencies
Write-Host "Installing Node.js dependencies..." -ForegroundColor Yellow
npm install

if ($LASTEXITCODE -eq 0) {
    Write-Host "Dependencies installed successfully!" -ForegroundColor Green
    
    # Create necessary directories
    New-Item -ItemType Directory -Force -Path "reports", "logs", "uploads", "temp" | Out-Null
    Write-Host "Created necessary directories" -ForegroundColor Green
    
    # Start the application
    Write-Host "Starting the application..." -ForegroundColor Green
    Write-Host "The application will be available at http://localhost:3000" -ForegroundColor Cyan
    Write-Host "Press Ctrl+C to stop the application" -ForegroundColor Yellow
    
    node index.js
} else {
    Write-Host "Failed to install dependencies. Please check your npm configuration." -ForegroundColor Red
    exit 1
}
