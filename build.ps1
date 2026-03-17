# PowerShell script to build and run the penetration testing tool

Write-Host "Building Penetration Testing Tool..." -ForegroundColor Green

# Check if Docker is running
try {
    docker version | Out-Null
    Write-Host "Docker is running..." -ForegroundColor Green
} catch {
    Write-Host "Docker is not running. Please start Docker Desktop." -ForegroundColor Red
    exit 1
}

# Try building with Node.js base image first (more reliable)
Write-Host "Attempting to build with Node.js base image..." -ForegroundColor Yellow
try {
    docker-compose -f docker-compose.node.yml build
    if ($LASTEXITCODE -eq 0) {
        Write-Host "Build successful with Node.js base image!" -ForegroundColor Green
        Write-Host "Starting the application..." -ForegroundColor Green
        docker-compose -f docker-compose.node.yml up -d
        Write-Host "Application is running at http://localhost:3000" -ForegroundColor Green
        exit 0
    }
} catch {
    Write-Host "Node.js build failed, trying Ubuntu base image..." -ForegroundColor Yellow
}

# Fallback to Ubuntu base image
Write-Host "Attempting to build with Ubuntu base image..." -ForegroundColor Yellow
try {
    docker-compose build
    if ($LASTEXITCODE -eq 0) {
        Write-Host "Build successful with Ubuntu base image!" -ForegroundColor Green
        Write-Host "Starting the application..." -ForegroundColor Green
        docker-compose up -d
        Write-Host "Application is running at http://localhost:3000" -ForegroundColor Green
    } else {
        Write-Host "Build failed. Please check your internet connection and Docker configuration." -ForegroundColor Red
        exit 1
    }
} catch {
    Write-Host "Both builds failed. Please check your Docker setup." -ForegroundColor Red
    exit 1
}
