# Automated Penetration Testing Tool

A comprehensive web-based penetration testing tool with real-time scanning, professional reporting, and containerized deployment.

## 🚀 Features

### Core Functionality
- **Real-time Network Scanning**: Nmap integration with live progress updates
- **Professional PDF Reports**: Auto-generated detailed reports with pentester information
- **Cryptography Tools**: Encryption/decryption with DES, 3DES, and AES
- **VirusTotal Integration**: File, URL, and hash scanning
- **Scan History Management**: Complete audit trail of all scans
- **Report Management**: Centralized report storage and access

### User Interface
- **Cybersecurity Theme**: Dark tech aesthetic with matrix-style animations
- **Real-time Progress Tracking**: Smart progress bars with timestamp updates
- **Responsive Design**: Works on desktop, tablet, and mobile
- **Interactive Dashboard**: Easy navigation between tools and features

### Security & Deployment
- **Containerized Deployment**: Docker support with security hardening
- **Privilege Management**: Automatic handling of Windows privilege issues
- **Unprivileged Scanning**: Optimized scan options that work without root
- **Data Persistence**: Secure storage of reports and scan history

## 📋 Prerequisites

- **Node.js** 16+ and npm
- **Nmap** (automatically handled in Docker)
- **Docker** & Docker Compose (for containerized deployment)
- **VirusTotal API Key** (optional, for malware scanning)

## 🐳 Quick Start with Docker (Recommended)

### Windows (PowerShell)
```powershell
# Clone the repository
git clone https://github.com/your-username/penetration_testing_tool.git
cd penetration_testing_tool

# Build and start with one command
.\deploy.ps1

# Or step by step
.\deploy.ps1 build
.\deploy.ps1 start
```

### Linux/macOS (Bash)
```bash
# Clone the repository
git clone https://github.com/your-username/penetration_testing_tool.git
cd penetration_testing_tool

# Make script executable and run
chmod +x deploy.sh
./deploy.sh

# Or step by step
./deploy.sh build
./deploy.sh start
```

### Access the Application
Open your browser and navigate to: **http://localhost:3000**

## 💻 Manual Installation

### 1. Install Dependencies
```bash
# Install Node.js dependencies
npm install

# Install Nmap (if not using Docker)
# Windows: Download from https://nmap.org/download.html
# Ubuntu/Debian: sudo apt-get install nmap
# macOS: brew install nmap
```

### 2. Configuration
```bash
# Copy environment template
cp .env.example .env

# Edit configuration (set API keys, pentester name, etc.)
nano .env
```

### 3. Start the Application
```bash
# Development mode
npm run dev

# Production mode
npm start
```

## ⚙️ Configuration

### Environment Variables (.env)
```bash
# Application Settings
NODE_ENV=production
PORT=3000
PENTESTER_NAME=Your Name Here
COMPANY_NAME=Your Company

# Security
JWT_SECRET=your_secure_jwt_secret_here

# API Keys
VIRUSTOTAL_API_KEY=your_virustotal_api_key

# Timezone
TZ=America/New_York
```

### Scan Options
The tool now includes unprivileged scan options that work without root:

- **Quick TCP Connect Scan**: Fast service detection
- **Standard Service Detection**: Version and script scanning
- **Comprehensive Scan**: Full analysis with OS detection
- **Full Port TCP Scan**: All 65,535 ports
- **Top 1000 Ports**: Most common services
- **Ping Sweep**: Network discovery
- **Common Ports**: Web, SSH, FTP, mail services

## 📊 Features Overview

### 1. Network Scanner
- Real-time Nmap integration
- Live progress updates with timestamps
- Smart progress estimation based on scan activity
- Professional PDF report generation
- Automatic privilege handling on Windows
- Support for custom Nmap commands and NSE scripts

### 2. Report Generation
- **PDF Reports**: Professional formatting with:
  - Executive summary
  - Discovered services analysis
  - Security recommendations
  - Raw scan output
  - Pentester and target information
  - Timestamp and duration tracking

### 3. Cryptography Module
- **Encryption Algorithms**: DES, 3DES, AES
- **Real-time Processing**: Immediate results
- **User-friendly Interface**: Simple input/output design

### 4. VirusTotal Scanner
- **File Scanning**: Upload and analyze files
- **URL Analysis**: Website reputation checking
- **Hash Lookup**: MD5, SHA1, SHA256 queries
- **Detailed Results**: Threat detection summaries

### 5. History & Reports Management
- **Scan History**: Complete audit trail
- **Report Storage**: Organized by date and type
- **Easy Access**: Download and view previous scans
- **Search & Filter**: Find specific scans quickly

## 🐳 Docker Management

### Available Commands
```bash
# PowerShell (Windows)
.\deploy.ps1 [command]

# Bash (Linux/macOS)
./deploy.sh [command]
```

| Command | Description |
|---------|-------------|
| `build` | Build Docker image |
| `start` | Start the application |
| `stop` | Stop the application |
| `restart` | Restart the application |
| `logs` | View real-time logs |
| `status` | Show container status |
| `health` | Run health check |
| `backup` | Backup data |
| `cleanup` | Clean Docker resources |

### Data Persistence
Docker volumes ensure data persists across container restarts:
- `reports/` - Generated PDF reports
- `history/` - Scan history data
- `uploads/` - VirusTotal file uploads
- `logs/` - Application logs

**Render-specific setup**
- Add a persistent disk in `render.yaml` (already configured) or via the dashboard.
- The service reads `PERSISTENT_STORAGE_PATH` (defaults to the project root) to decide where to store reports/history/uploads/logs.
- On Render the disk is mounted at `/var/pentest-data`, so nothing is lost on dyno restarts.

### Endpoint Protector Agents
- The former IDS dashboard is now the **Endpoint Protector** control plane with live telemetry, fleet health, and security findings.
- Deploy lightweight agents using the bundled `endpoint-protector-agent.js` script to stream CPU/memory/process insights over Socket.IO.
- Quick start on an endpoint:
  ```bash
  npm install socket.io-client
  ENDPOINT_PROTECTOR_URL="https://your-render-app.onrender.com" \
  ENDPOINT_AGENT_TOKEN="shared-token" \
  node endpoint-protector-agent.js
  ```
- Optional env vars: `ENDPOINT_AGENT_TAGS`, `ENDPOINT_AGENT_OWNER`, `ENDPOINT_AGENT_ID`, `ENDPOINT_TELEMETRY_INTERVAL_MS`.
- Agents send telemetry (`endpoint-agent:telemetry`) and enriched alerts (`endpoint-agent:alert`) which the backend rebroadcasts to the dashboard in real time.

## 🔧 Development

### Project Structure
```
penetration_testing_tool/
├── public/                 # Frontend assets
│   ├── index.html         # Main UI
│   ├── app.js            # Client-side JavaScript
│   └── styles.css        # Cybersecurity theme
├── utils/                 # Backend utilities
│   ├── nmapRunner.js     # Nmap execution
│   ├── reportGenerator.js # PDF report creation
│   └── historyManager.js # Data management
├── reports/              # Generated reports
├── history/              # Scan history
├── index.js              # Main server
├── Dockerfile            # Container configuration
├── docker-compose.yml    # Multi-container setup
└── deploy.sh/ps1         # Deployment scripts
```

### Adding New Features
1. **Frontend**: Modify `public/app.js` and `public/index.html`
2. **Backend**: Add routes in `index.js`
3. **Utilities**: Create modules in `utils/`
4. **Styling**: Update `public/styles.css`

## 🛡️ Security Considerations

### Container Security
- Runs as non-root user (node:1000)
- No privilege escalation allowed
- Resource limits enforced
- Network isolation enabled
- Only required capabilities granted

### Application Security
- JWT token authentication ready
- Input validation and sanitization
- Secure file handling
- Rate limiting support
- CORS protection

### Network Security
- Unprivileged scan options
- Automatic privilege fallback
- Safe default scan configurations
- Output sanitization

## 📚 Documentation

- **[DOCKER.md](DOCKER.md)** - Comprehensive Docker deployment guide
- **[.env.example](.env.example)** - Configuration template
- **API Documentation** - Built-in help in the web interface

## 🐛 Troubleshooting

### Common Issues

#### 1. Scan Failures
```bash
# Check Nmap installation
nmap --version

# Test with simple scan
nmap -sn 127.0.0.1
```

#### 2. Docker Issues
```bash
# Check Docker status
docker --version
docker-compose --version

# View container logs
.\deploy.ps1 logs
```

#### 3. Permission Problems (Windows)
The tool automatically handles Windows privilege issues by:
- Converting privileged scans to unprivileged alternatives
- Providing fallback scan options
- Using TCP connect scans instead of SYN scans

#### 4. Report Generation Issues
```bash
# Check reports directory
ls -la reports/

# Verify permissions
docker exec pentest-tool ls -la /usr/src/app/reports/
```

## 🔄 Updates

### Automatic Updates (Docker)
```bash
# Pull latest code and rebuild
.\deploy.ps1 update
```

### Manual Updates
```bash
git pull origin main
npm install
.\deploy.ps1 restart
```

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch: `git checkout -b feature-name`
3. Make your changes
4. Test thoroughly
5. Submit a pull request

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- **Nmap** - Network scanning capabilities
- **jsPDF** - PDF report generation
- **Socket.IO** - Real-time communication
- **Bootstrap** - UI framework
- **Docker** - Containerization platform

## 📞 Support

For support and questions:
1. Check the troubleshooting section
2. Review Docker documentation in `DOCKER.md`
3. Check application logs: `.\deploy.ps1 logs`
4. Create an issue on GitHub

---

**⚠️ Disclaimer**: This tool is for authorized penetration testing and security research only. Users are responsible for complying with applicable laws and obtaining proper authorization before scanning networks or systems.

The containerized deployment makes it easy to run the tool consistently across different environments while maintaining security best practices.
