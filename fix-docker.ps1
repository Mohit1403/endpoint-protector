# PowerShell script to fix Docker connectivity issues

Write-Host "Docker Connectivity Troubleshooting Tool" -ForegroundColor Cyan
Write-Host "=======================================" -ForegroundColor Cyan

# Test basic Docker functionality
Write-Host "`n1. Testing Docker installation..." -ForegroundColor Yellow
try {
    $dockerVersion = docker --version
    Write-Host "✓ Docker is installed: $dockerVersion" -ForegroundColor Green
} catch {
    Write-Host "✗ Docker is not installed or not in PATH" -ForegroundColor Red
    Write-Host "Please install Docker Desktop from https://www.docker.com/products/docker-desktop" -ForegroundColor Yellow
    exit 1
}

# Test Docker daemon
Write-Host "`n2. Testing Docker daemon..." -ForegroundColor Yellow
try {
    docker info | Out-Null
    Write-Host "✓ Docker daemon is running" -ForegroundColor Green
} catch {
    Write-Host "✗ Docker daemon is not running" -ForegroundColor Red
    Write-Host "Please start Docker Desktop" -ForegroundColor Yellow
    exit 1
}

# Test internet connectivity
Write-Host "`n3. Testing internet connectivity..." -ForegroundColor Yellow
try {
    $response = Test-NetConnection -ComputerName "docker.io" -Port 443 -WarningAction SilentlyContinue
    if ($response.TcpTestSucceeded) {
        Write-Host "✓ Can connect to docker.io" -ForegroundColor Green
    } else {
        Write-Host "✗ Cannot connect to docker.io" -ForegroundColor Red
        Write-Host "This might be a firewall or network issue" -ForegroundColor Yellow
    }
} catch {
    Write-Host "✗ Network connectivity test failed" -ForegroundColor Red
}

# Try to pull a small image to test registry connectivity
Write-Host "`n4. Testing Docker registry connectivity..." -ForegroundColor Yellow
try {
    Write-Host "Attempting to pull hello-world image..." -ForegroundColor Gray
    docker pull hello-world:latest 2>$null
    if ($LASTEXITCODE -eq 0) {
        Write-Host "✓ Docker registry is accessible" -ForegroundColor Green
        docker rmi hello-world:latest 2>$null | Out-Null
    } else {
        Write-Host "✗ Cannot pull from Docker registry" -ForegroundColor Red
    }
} catch {
    Write-Host "✗ Registry connectivity test failed" -ForegroundColor Red
}

Write-Host "`n5. Suggested Solutions:" -ForegroundColor Cyan
Write-Host "========================" -ForegroundColor Cyan

Write-Host "`nOption 1: Fix DNS Settings" -ForegroundColor Yellow
Write-Host "- Open Network Settings > Change adapter options" -ForegroundColor Gray
Write-Host "- Right-click your network adapter > Properties" -ForegroundColor Gray
Write-Host "- Select 'Internet Protocol Version 4 (TCP/IPv4)' > Properties" -ForegroundColor Gray
Write-Host "- Use these DNS servers: 8.8.8.8 and 8.8.4.4" -ForegroundColor Gray

Write-Host "`nOption 2: Configure Docker Desktop" -ForegroundColor Yellow
Write-Host "- Open Docker Desktop" -ForegroundColor Gray
Write-Host "- Go to Settings > Resources > Network" -ForegroundColor Gray
Write-Host "- If behind a proxy, configure proxy settings" -ForegroundColor Gray
Write-Host "- Restart Docker Desktop" -ForegroundColor Gray

Write-Host "`nOption 3: Use Local Setup Instead" -ForegroundColor Yellow
Write-Host "- Install Node.js from https://nodejs.org/" -ForegroundColor Gray
Write-Host "- Run: npm install" -ForegroundColor Gray
Write-Host "- Run: node index.js" -ForegroundColor Gray

Write-Host "`nOption 4: Try Alternative Docker Build" -ForegroundColor Yellow
Write-Host "- Run: docker build --network=host ." -ForegroundColor Gray
Write-Host "- Or: docker-compose -f docker-compose.node.yml build" -ForegroundColor Gray

Write-Host "`nPress any key to continue..." -ForegroundColor Cyan
$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
