📘 Autopentrix – Documentation
🔷 1. Introduction

Autopentrix is a web-based cybersecurity platform designed to automate penetration testing and endpoint monitoring. It combines network scanning, malware intelligence, and endpoint control into a single unified system.

The platform is built to assist security analysts in identifying vulnerabilities, analyzing threats, and maintaining visibility over connected systems in real time.

🔷 2. System Architecture

Autopentrix follows a distributed architecture consisting of three main layers:

Frontend Dashboard: Provides an interactive interface for managing scans and monitoring systems

Backend Server (Node.js): Handles API requests, scan execution, and real-time communication

Endpoint Agent (Python): Runs on client machines to collect telemetry and execute remote commands

Data flows between these components using REST APIs and WebSocket connections for real-time updates.

🔷 3. Key Components
🖥 Backend Server

The backend is built using Node.js and Express, with Socket.IO for real-time communication.

Core responsibilities include:

Managing scan execution workflows

Handling API requests for VirusTotal and endpoint control

Generating reports

Maintaining scan history

Reference:

🧠 Endpoint Agent

The endpoint agent is a Python-based service deployed on monitored systems.

Its responsibilities include:

Collecting system and network telemetry

Monitoring device activity

Executing commands received from the server

Sending alerts and logs

Reference:

🌐 Frontend Interface

The frontend provides a user-friendly dashboard that allows users to:

Initiate scans

View real-time outputs

Monitor endpoints

Access reports

Reference:

🔷 4. Core Features
🔍 Network Scanning

Integration with Nmap for host and service discovery

Support for different scan types and custom commands

Real-time progress tracking

🦠 Threat Intelligence (VirusTotal)

File analysis via upload

URL reputation checks

Hash-based threat lookup

🛡 Endpoint Monitoring

Continuous telemetry collection

Device and network visibility

Remote administrative commands (e.g., blocking USB, terminating processes)

🔐 Cryptographic Utilities

Encryption and decryption using standard algorithms

Designed for quick testing and validation

📊 Reporting

Automated generation of structured reports

Storage and retrieval of historical scan data

🔷 5. API Overview
VirusTotal Integration

POST /api/virustotal/file → Scan uploaded file

POST /api/virustotal/url → Analyze URL

POST /api/virustotal/hash → Lookup hash

Endpoint Management

GET /api/endpoint-protector/overview → System summary

GET /api/endpoint-protector/agents → List agents

GET /api/endpoint-protector/alerts → Retrieve alerts

POST /api/endpoint-protector/agents/:agentId/command → Send command

🔷 6. Installation Guide
Backend Setup
git clone <repository-url>
cd autopentrix
npm install
npm start
Endpoint Agent Setup
pip install -r requirements.txt
python enterprise_endpoint_agent.py

Reference:

🔷 7. Configuration

Environment variables are used to configure the system:

PORT=3000
JWT_SECRET=your_secret_key
VIRUSTOTAL_API_KEY=your_api_key
ENDPOINT_PROTECTOR_URL=https://your-backend-url
🔷 8. Deployment (Render)

Autopentrix can be deployed on Render as a web service.

Key steps:

Connect GitHub repository

Set environment variables

Enable persistent storage (for reports and logs)

Use /health endpoint for monitoring

🔷 9. Usage Guidelines

This tool is intended strictly for:

Authorized penetration testing

Security research in controlled environments

Unauthorized usage against systems without permission is prohibited.

🔷 10. Future Enhancements

Planned improvements include:

AI-driven vulnerability detection

Expanded reporting capabilities

Integration with additional security tools

Role-based access control enhancements
