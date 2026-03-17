# Manual Setup Instructions

## Prerequisites

### 1. Install Node.js
1. Visit https://nodejs.org/
2. Download the LTS version for Windows
3. Run the installer and follow the setup wizard
4. Restart your terminal/PowerShell after installation

### 2. Install Nmap (Optional for development)
1. Visit https://nmap.org/download.html
2. Download Nmap for Windows
3. Run the installer with default settings

## Setup Steps

### 1. Install Dependencies
```powershell
npm install
```

### 2. Create Required Directories
```powershell
mkdir reports, logs, uploads, temp
```

### 3. Run the Application
```powershell
node index.js
```

The application will be available at http://localhost:3000

## Docker Connectivity Issues

If you're experiencing Docker connectivity issues, try these solutions:

### Solution 1: Configure DNS
Add these DNS servers to your network adapter:
- Primary: 8.8.8.8
- Secondary: 8.8.4.4

### Solution 2: Docker Desktop Settings
1. Open Docker Desktop
2. Go to Settings > Resources > Network
3. Enable "Manual proxy configuration" if behind a corporate firewall
4. Restart Docker Desktop

### Solution 3: Use Alternative Registry
Create a `.dockerignore` file and try building with:
```powershell
docker build --no-cache --network=host .
```

### Solution 4: Offline Docker Build
If you have the base images cached, you can build offline:
```powershell
docker build --no-cache --pull=false .
```

## Troubleshooting

### Port 3000 Already in Use
```powershell
# Find process using port 3000
netstat -ano | findstr :3000

# Kill the process (replace PID with actual process ID)
taskkill /PID <PID> /F
```

### Permission Issues
Run PowerShell as Administrator if you encounter permission errors.

### Nmap Not Found
If Nmap commands fail, ensure Nmap is installed and added to your system PATH.
