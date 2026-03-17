#!/usr/bin/env pwsh

# Penetration Testing Tool - Docker Deployment Script (PowerShell)
# This script handles building, running, and managing the containerized tool on Windows

param(
    [Parameter(Position=0)]
    [ValidateSet("build", "start", "stop", "restart", "logs", "status", "health", "update", "backup", "cleanup", "help", "")]
    [string]$Command = ""
)

# Script configuration
$APP_NAME = "pentest-tool"
$CONTAINER_NAME = "pentest-tool"
$IMAGE_NAME = "pentest-tool:latest"
$COMPOSE_FILE = "docker-compose.yml"

# Functions for colored output
function Write-Status {
    param($Message)
    Write-Host "[INFO] $Message" -ForegroundColor Blue
}

function Write-Success {
    param($Message)
    Write-Host "[SUCCESS] $Message" -ForegroundColor Green
}

function Write-Warning {
    param($Message)
    Write-Host "[WARNING] $Message" -ForegroundColor Yellow
}

function Write-Error {
    param($Message)
    Write-Host "[ERROR] $Message" -ForegroundColor Red
}

# Function to check if Docker is running
function Test-Docker {
    try {
        docker info | Out-Null
        if (-not (Get-Command docker-compose -ErrorAction SilentlyContinue)) {
            Write-Error "Docker Compose is not installed. Please install Docker Compose and try again."
            exit 1
        }
        Write-Success "Docker and Docker Compose are available"
        return $true
    }
    catch {
        Write-Error "Docker is not running. Please start Docker and try again."
        exit 1
    }
}

# Function to create environment file if it doesn't exist
function Initialize-Environment {
    if (-not (Test-Path ".env")) {
        Write-Warning ".env file not found. Creating from template..."
        if (Test-Path ".env.example") {
            Copy-Item ".env.example" ".env"
            Write-Status "Please edit .env file with your configuration before running the application"
            Write-Warning "Don't forget to set your VirusTotal API key and JWT secret!"
        } else {
            Write-Error ".env.example template not found"
            exit 1
        }
    } else {
        Write-Success "Environment file exists"
    }
}

# Function to create necessary directories
function New-AppDirectories {
    Write-Status "Creating necessary directories..."
    $directories = @("reports", "history", "uploads", "logs", "temp")
    foreach ($dir in $directories) {
        if (-not (Test-Path $dir)) {
            New-Item -ItemType Directory -Path $dir -Force | Out-Null
        }
    }
    Write-Success "Directories created successfully"
}

# Function to build the Docker image
function Build-Image {
    Write-Status "Building Docker image..."
    docker-compose build --no-cache
    if ($LASTEXITCODE -eq 0) {
        Write-Success "Docker image built successfully"
    } else {
        Write-Error "Failed to build Docker image"
        exit 1
    }
}

# Function to start the application
function Start-App {
    Write-Status "Starting the application..."
    docker-compose up -d
    
    if ($LASTEXITCODE -eq 0) {
        # Wait for the application to be ready
        Write-Status "Waiting for application to be ready..."
        $timeout = 60
        $ready = $false
        
        while ($timeout -gt 0 -and -not $ready) {
            try {
                $response = Invoke-WebRequest -Uri "http://localhost:3000" -UseBasicParsing -TimeoutSec 2
                if ($response.StatusCode -eq 200) {
                    $ready = $true
                    Write-Success "Application is ready!"
                    break
                }
            }
            catch {
                # Continue waiting
            }
            Start-Sleep -Seconds 2
            $timeout -= 2
        }
        
        if (-not $ready) {
            Write-Error "Application failed to start within 60 seconds"
            docker-compose logs
            exit 1
        }
        
        Write-Success "Application started successfully"
        Write-Status "Access your penetration testing tool at: http://localhost:3000"
    } else {
        Write-Error "Failed to start application"
        exit 1
    }
}

# Function to stop the application
function Stop-App {
    Write-Status "Stopping the application..."
    docker-compose down
    if ($LASTEXITCODE -eq 0) {
        Write-Success "Application stopped"
    }
}

# Function to restart the application
function Restart-App {
    Stop-App
    Start-App
}

# Function to view logs
function Show-Logs {
    Write-Status "Viewing application logs (press Ctrl+C to exit)..."
    docker-compose logs -f
}

# Function to update the application
function Update-App {
    Write-Status "Updating the application..."
    try {
        git pull origin main
    }
    catch {
        Write-Warning "Could not pull latest changes (not a git repository?)"
    }
    Build-Image
    Restart-App
    Write-Success "Application updated successfully"
}

# Function to cleanup
function Remove-AppResources {
    Write-Status "Cleaning up Docker resources..."
    docker-compose down -v --remove-orphans
    docker image prune -f
    docker volume prune -f
    Write-Success "Cleanup completed"
}

# Function to run health check
function Test-AppHealth {
    Write-Status "Running health check..."
    $containers = docker-compose ps -q
    if ($containers) {
        try {
            $response = Invoke-WebRequest -Uri "http://localhost:3000" -UseBasicParsing -TimeoutSec 5
            if ($response.StatusCode -eq 200) {
                Write-Success "Application is healthy and responding"
                return $true
            }
        }
        catch {
            Write-Error "Application is running but not responding on port 3000"
            return $false
        }
    } else {
        Write-Error "Application containers are not running"
        return $false
    }
}

# Function to show application status
function Show-Status {
    Write-Status "Application Status:"
    docker-compose ps
    Write-Host ""
    Write-Status "Docker Image Info:"
    docker images | Select-String "pentest-tool"
    Write-Host ""
    Write-Status "Resource Usage:"
    docker stats --no-stream --format "table {{.Container}}`t{{.CPUPerc}}`t{{.MemUsage}}`t{{.NetIO}}`t{{.BlockIO}}"
}

# Function to backup data
function Backup-Data {
    Write-Status "Creating backup of application data..."
    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $backupDir = "backup_$timestamp"
    
    New-Item -ItemType Directory -Path $backupDir -Force | Out-Null
    
    $dataDirectories = @("reports", "history", "logs")
    foreach ($dir in $dataDirectories) {
        if (Test-Path $dir) {
            Copy-Item -Path $dir -Destination $backupDir -Recurse -Force
        }
    }
    
    # Create archive
    Compress-Archive -Path $backupDir -DestinationPath "$backupDir.zip" -Force
    Remove-Item -Path $backupDir -Recurse -Force
    
    Write-Success "Backup created: $backupDir.zip"
}

# Function to show help
function Show-Help {
    Write-Host "Penetration Testing Tool - Docker Deployment Script (PowerShell)"
    Write-Host ""
    Write-Host "Usage: .\deploy.ps1 [COMMAND]"
    Write-Host ""
    Write-Host "Commands:"
    Write-Host "  build       Build the Docker image"
    Write-Host "  start       Start the application"
    Write-Host "  stop        Stop the application"
    Write-Host "  restart     Restart the application"
    Write-Host "  logs        View application logs"
    Write-Host "  status      Show application status"
    Write-Host "  health      Run health check"
    Write-Host "  update      Update and restart the application"
    Write-Host "  backup      Backup application data"
    Write-Host "  cleanup     Clean up Docker resources"
    Write-Host "  help        Show this help message"
    Write-Host ""
    Write-Host "Examples:"
    Write-Host "  .\deploy.ps1 build; .\deploy.ps1 start    # Build and start the application"
    Write-Host "  .\deploy.ps1 logs                         # View real-time logs"
    Write-Host "  .\deploy.ps1 backup                       # Create a backup of your data"
}

# Main script logic
switch ($Command) {
    "build" {
        Test-Docker
        Initialize-Environment
        New-AppDirectories
        Build-Image
    }
    "start" {
        Test-Docker
        Initialize-Environment
        New-AppDirectories
        Start-App
    }
    "stop" {
        Test-Docker
        Stop-App
    }
    "restart" {
        Test-Docker
        Restart-App
    }
    "logs" {
        Test-Docker
        Show-Logs
    }
    "status" {
        Test-Docker
        Show-Status
    }
    "health" {
        Test-Docker
        Test-AppHealth
    }
    "update" {
        Test-Docker
        Update-App
    }
    "backup" {
        Backup-Data
    }
    "cleanup" {
        Test-Docker
        Remove-AppResources
    }
    "help" {
        Show-Help
    }
    "" {
        Write-Status "Setting up and starting the penetration testing tool..."
        Test-Docker
        Initialize-Environment
        New-AppDirectories
        Build-Image
        Start-App
    }
    default {
        Write-Error "Unknown command: $Command"
        Show-Help
        exit 1
    }
}
