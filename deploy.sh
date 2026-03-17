#!/bin/bash

# Penetration Testing Tool - Docker Deployment Script
# This script handles building, running, and managing the containerized tool

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Script configuration
APP_NAME="pentest-tool"
CONTAINER_NAME="pentest-tool"
IMAGE_NAME="pentest-tool:latest"
COMPOSE_FILE="docker-compose.yml"

# Function to print colored output
print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Function to check if Docker is running
check_docker() {
    if ! docker info >/dev/null 2>&1; then
        print_error "Docker is not running. Please start Docker and try again."
        exit 1
    fi
    
    if ! command -v docker-compose >/dev/null 2>&1; then
        print_error "Docker Compose is not installed. Please install Docker Compose and try again."
        exit 1
    fi
    
    print_success "Docker and Docker Compose are available"
}

# Function to create environment file if it doesn't exist
setup_environment() {
    if [ ! -f .env ]; then
        print_warning ".env file not found. Creating from template..."
        if [ -f .env.example ]; then
            cp .env.example .env
            print_status "Please edit .env file with your configuration before running the application"
            print_warning "Don't forget to set your VirusTotal API key and JWT secret!"
        else
            print_error ".env.example template not found"
            exit 1
        fi
    else
        print_success "Environment file exists"
    fi
}

# Function to create necessary directories
create_directories() {
    print_status "Creating necessary directories..."
    mkdir -p reports history uploads logs temp
    
    # Set proper permissions (if running as root)
    if [ "$EUID" -eq 0 ]; then
        chown -R 1000:1000 reports history uploads logs temp
    fi
    
    print_success "Directories created successfully"
}

# Function to build the Docker image
build_image() {
    print_status "Building Docker image..."
    docker-compose build --no-cache
    print_success "Docker image built successfully"
}

# Function to start the application
start_app() {
    print_status "Starting the application..."
    docker-compose up -d
    
    # Wait for the application to be ready
    print_status "Waiting for application to be ready..."
    timeout=60
    while [ $timeout -gt 0 ]; do
        if curl -s http://localhost:3000 >/dev/null 2>&1; then
            print_success "Application is ready!"
            break
        fi
        sleep 2
        timeout=$((timeout-2))
    done
    
    if [ $timeout -le 0 ]; then
        print_error "Application failed to start within 60 seconds"
        docker-compose logs
        exit 1
    fi
    
    print_success "Application started successfully"
    print_status "Access your penetration testing tool at: http://localhost:3000"
}

# Function to stop the application
stop_app() {
    print_status "Stopping the application..."
    docker-compose down
    print_success "Application stopped"
}

# Function to restart the application
restart_app() {
    stop_app
    start_app
}

# Function to view logs
view_logs() {
    print_status "Viewing application logs (press Ctrl+C to exit)..."
    docker-compose logs -f
}

# Function to update the application
update_app() {
    print_status "Updating the application..."
    git pull origin main || print_warning "Could not pull latest changes (not a git repository?)"
    build_image
    restart_app
    print_success "Application updated successfully"
}

# Function to cleanup
cleanup() {
    print_status "Cleaning up Docker resources..."
    docker-compose down -v --remove-orphans
    docker image prune -f
    docker volume prune -f
    print_success "Cleanup completed"
}

# Function to run health check
health_check() {
    print_status "Running health check..."
    if docker-compose ps | grep -q "Up"; then
        if curl -s http://localhost:3000 >/dev/null 2>&1; then
            print_success "Application is healthy and responding"
        else
            print_error "Application is running but not responding on port 3000"
            return 1
        fi
    else
        print_error "Application containers are not running"
        return 1
    fi
}

# Function to show application status
show_status() {
    print_status "Application Status:"
    docker-compose ps
    echo ""
    print_status "Docker Image Info:"
    docker images | grep pentest-tool || echo "No images found"
    echo ""
    print_status "Resource Usage:"
    docker stats --no-stream --format "table {{.Container}}\t{{.CPUPerc}}\t{{.MemUsage}}\t{{.NetIO}}\t{{.BlockIO}}"
}

# Function to backup data
backup_data() {
    print_status "Creating backup of application data..."
    backup_dir="backup_$(date +%Y%m%d_%H%M%S)"
    mkdir -p "$backup_dir"
    
    cp -r reports "$backup_dir/" 2>/dev/null || true
    cp -r history "$backup_dir/" 2>/dev/null || true
    cp -r logs "$backup_dir/" 2>/dev/null || true
    
    tar -czf "${backup_dir}.tar.gz" "$backup_dir"
    rm -rf "$backup_dir"
    
    print_success "Backup created: ${backup_dir}.tar.gz"
}

# Function to show help
show_help() {
    echo "Penetration Testing Tool - Docker Deployment Script"
    echo ""
    echo "Usage: $0 [COMMAND]"
    echo ""
    echo "Commands:"
    echo "  build       Build the Docker image"
    echo "  start       Start the application"
    echo "  stop        Stop the application"
    echo "  restart     Restart the application"
    echo "  logs        View application logs"
    echo "  status      Show application status"
    echo "  health      Run health check"
    echo "  update      Update and restart the application"
    echo "  backup      Backup application data"
    echo "  cleanup     Clean up Docker resources"
    echo "  help        Show this help message"
    echo ""
    echo "Examples:"
    echo "  $0 build && $0 start    # Build and start the application"
    echo "  $0 logs                 # View real-time logs"
    echo "  $0 backup              # Create a backup of your data"
}

# Main script logic
case "${1:-}" in
    "build")
        check_docker
        setup_environment
        create_directories
        build_image
        ;;
    "start")
        check_docker
        setup_environment
        create_directories
        start_app
        ;;
    "stop")
        check_docker
        stop_app
        ;;
    "restart")
        check_docker
        restart_app
        ;;
    "logs")
        check_docker
        view_logs
        ;;
    "status")
        check_docker
        show_status
        ;;
    "health")
        check_docker
        health_check
        ;;
    "update")
        check_docker
        update_app
        ;;
    "backup")
        backup_data
        ;;
    "cleanup")
        check_docker
        cleanup
        ;;
    "help"|"--help"|"-h")
        show_help
        ;;
    "")
        print_status "Setting up and starting the penetration testing tool..."
        check_docker
        setup_environment
        create_directories
        build_image
        start_app
        ;;
    *)
        print_error "Unknown command: $1"
        show_help
        exit 1
        ;;
esac
