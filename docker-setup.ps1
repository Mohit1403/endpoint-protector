# Complete Docker setup script for Windows
param(
    [switch]$Force
)

Write-Host "=== Docker Setup for Penetration Testing Tool ===" -ForegroundColor Cyan

# Function to test network connectivity
function Test-NetworkConnectivity {
    Write-Host "Testing network connectivity..." -ForegroundColor Yellow
    
    # Test DNS resolution
    try {
        $dnsTest = Resolve-DnsName "docker.io" -ErrorAction Stop
        Write-Host "✓ DNS resolution working" -ForegroundColor Green
    } catch {
        Write-Host "✗ DNS resolution failed" -ForegroundColor Red
        Write-Host "Configuring alternative DNS..." -ForegroundColor Yellow
        
        # Try to configure Docker daemon with alternative DNS
        $dockerConfigPath = "$env:USERPROFILE\.docker\daemon.json"
        $dockerConfig = @{
            "dns" = @("8.8.8.8", "8.8.4.4", "1.1.1.1")
            "registry-mirrors" = @("https://mirror.gcr.io")
        }
        
        if (Test-Path $dockerConfigPath) {
            $existingConfig = Get-Content $dockerConfigPath | ConvertFrom-Json -ErrorAction SilentlyContinue
            if ($existingConfig) {
                $existingConfig.dns = $dockerConfig.dns
                $existingConfig."registry-mirrors" = $dockerConfig."registry-mirrors"
                $dockerConfig = $existingConfig
            }
        }
        
        New-Item -ItemType Directory -Force -Path (Split-Path $dockerConfigPath) | Out-Null
        $dockerConfig | ConvertTo-Json -Depth 10 | Set-Content $dockerConfigPath
        Write-Host "Docker daemon configuration updated. Please restart Docker Desktop." -ForegroundColor Yellow
    }
}

# Function to configure Windows for Docker
function Set-WindowsDockerConfig {
    Write-Host "Configuring Windows for Docker..." -ForegroundColor Yellow
    
    # Check if running as administrator
    $isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")
    
    if (-not $isAdmin) {
        Write-Host "Note: Running as administrator would allow better network configuration" -ForegroundColor Yellow
    }
    
    # Configure PowerShell execution policy if needed
    try {
        Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser -Force -ErrorAction SilentlyContinue
        Write-Host "✓ PowerShell execution policy configured" -ForegroundColor Green
    } catch {
        Write-Host "! Could not configure execution policy" -ForegroundColor Yellow
    }
}

# Function to build Docker image with retries
function Build-DockerImage {
    param($ComposeFile, $MaxRetries = 3)
    
    for ($i = 1; $i -le $MaxRetries; $i++) {
        Write-Host "Build attempt $i of $MaxRetries..." -ForegroundColor Yellow
        
        try {
            # Clean up any previous failed builds
            docker system prune -f 2>$null | Out-Null
            
            # Build with specific settings for network issues
            $env:DOCKER_BUILDKIT = "0"  # Disable BuildKit temporarily
            $env:COMPOSE_DOCKER_CLI_BUILD = "0"
            
            Write-Host "Starting Docker build (this may take several minutes)..." -ForegroundColor Cyan
            docker-compose -f $ComposeFile build --no-cache --force-rm
            
            if ($LASTEXITCODE -eq 0) {
                Write-Host "✓ Docker build successful!" -ForegroundColor Green
                return $true
            } else {
                Write-Host "✗ Build failed (attempt $i)" -ForegroundColor Red
                if ($i -lt $MaxRetries) {
                    Write-Host "Waiting 30 seconds before retry..." -ForegroundColor Yellow
                    Start-Sleep -Seconds 30
                }
            }
        } catch {
            Write-Host "✗ Build error: $($_.Exception.Message)" -ForegroundColor Red
        }
    }
    
    return $false
}

# Main execution
try {
    # Check Docker installation
    docker --version | Out-Null
    Write-Host "✓ Docker is installed" -ForegroundColor Green
} catch {
    Write-Host "✗ Docker is not installed or not accessible" -ForegroundColor Red
    Write-Host "Please install Docker Desktop from https://www.docker.com/products/docker-desktop" -ForegroundColor Yellow
    exit 1
}

# Check Docker daemon
try {
    docker info | Out-Null
    Write-Host "✓ Docker daemon is running" -ForegroundColor Green
} catch {
    Write-Host "✗ Docker daemon is not running" -ForegroundColor Red
    Write-Host "Please start Docker Desktop and wait for it to be ready" -ForegroundColor Yellow
    exit 1
}

# Configure Windows and network
Set-WindowsDockerConfig
Test-NetworkConnectivity

# Stop any existing containers
Write-Host "Stopping any existing containers..." -ForegroundColor Yellow
docker-compose -f docker-compose.fixed.yml down 2>$null | Out-Null

# Build the image
$buildSuccess = Build-DockerImage -ComposeFile "docker-compose.fixed.yml"

if ($buildSuccess) {
    Write-Host "Starting the application..." -ForegroundColor Green
    docker-compose -f docker-compose.fixed.yml up -d
    
    if ($LASTEXITCODE -eq 0) {
        Write-Host "" -ForegroundColor Green
        Write-Host "🎉 SUCCESS! The Penetration Testing Tool is now running!" -ForegroundColor Green
        Write-Host "" -ForegroundColor Green
        Write-Host "Access the application at: http://localhost:3000" -ForegroundColor Cyan
        Write-Host "" -ForegroundColor Green
        Write-Host "To stop the application, run:" -ForegroundColor Yellow
        Write-Host "docker-compose -f docker-compose.fixed.yml down" -ForegroundColor Gray
        Write-Host "" -ForegroundColor Green
        Write-Host "To view logs, run:" -ForegroundColor Yellow
        Write-Host "docker-compose -f docker-compose.fixed.yml logs -f" -ForegroundColor Gray
    } else {
        Write-Host "✗ Failed to start the application" -ForegroundColor Red
    }
} else {
    Write-Host "" -ForegroundColor Red
    Write-Host "Docker build failed after multiple attempts." -ForegroundColor Red
    Write-Host "This is likely due to network connectivity issues." -ForegroundColor Yellow
    Write-Host "" -ForegroundColor Yellow
    Write-Host "Possible solutions:" -ForegroundColor Yellow
    Write-Host "1. Check your internet connection" -ForegroundColor Gray
    Write-Host "2. Restart Docker Desktop" -ForegroundColor Gray
    Write-Host "3. Try running as Administrator" -ForegroundColor Gray
    Write-Host "4. Configure corporate proxy if applicable" -ForegroundColor Gray
    Write-Host "5. Try again during off-peak hours" -ForegroundColor Gray
}
}
