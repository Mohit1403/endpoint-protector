# AutoPentrix - Quick Start Guide

## 🚀 Starting the Application

### Option 1: Using PowerShell Script (Recommended)
```powershell
.\start-server.ps1
```

### Option 2: Manual Start
```powershell
node index.js
```

The server will start on **http://localhost:3000**

---

## 📊 Accessing the Dashboard

### Local
Open your web browser and navigate to:
```
http://localhost:3000
```

### On Render (Hosted)
After deploying with `render.yaml`, Render will give you a URL like:
```
https://autopentrix-dashboard.onrender.com
```
Use that URL for both the browser and remote agents.

---

## 🔌 Starting the Python Endpoint Agent

To see live endpoint data, start the Python agent in a **separate terminal**:

### Windows PowerShell:
```powershell
python enterprise_endpoint_agent.py
```

### Linux/Mac:
```bash
python3 enterprise_endpoint_agent.py
```

### With Custom Configuration (Local or Render):
```powershell
$env:ENDPOINT_PROTECTOR_URL="https://autopentrix-dashboard.onrender.com"  # use your Render URL in the cloud
$env:ENDPOINT_AGENT_TOKEN="dev-agent"
python enterprise_endpoint_agent.py
```

---

## ✨ What's New - Recent Changes

### ✅ Fixed Real-Time Data Streaming
- Endpoint agents now stream live telemetry data to the dashboard
- Auto-refresh every 5 seconds when viewing Endpoint Protector section
- Real-time updates for CPU, memory, processes, and network data

### ✅ Enhanced Endpoint Display
- **Detailed Telemetry**: CPU usage with progress bars, memory stats, top processes
- **Network Information**: All network interfaces with IP addresses
- **Risk Scoring**: Color-coded risk scores based on system health
- **Process Monitoring**: Top processes with suspicious process detection

### ✅ Device Control Features
- **View Details**: Click dropdown menu → "View Details" for full agent information
- **Refresh Data**: Force immediate telemetry update
- **Restart Agent**: Restart telemetry collection
- **Stop Monitoring**: Stop agent monitoring (acknowledgment only)

### ✅ Professional UI
- Modern card-based layout for each endpoint
- Color-coded status indicators (Online/Offline/Degraded)
- Real-time notifications for agent connections
- Detailed modal views with system information

---

## 📋 Features Available

1. **Scanner** - Network scanning with Nmap
2. **Cryptography** - Encryption, decryption, encoding, hashing
3. **VirusTotal** - File, URL, and hash scanning
4. **Endpoint Protector** - Real-time endpoint monitoring and control ⭐ NEW
5. **Reports** - Generate PDF reports
6. **History** - View scan history

---

## 🐛 Troubleshooting

### Server won't start?
- Check if port 3000 is already in use
- Ensure Node.js is installed: `node --version`
- Install dependencies: `npm install`

### Endpoint agent not connecting?
- Check that the backend server is running
- Verify the URL: `ENDPOINT_PROTECTOR_URL=http://localhost:3000`
- Check firewall settings
- Look for connection errors in the agent output

### No data showing in dashboard?
- Ensure the Python agent is running
- Check browser console for errors (F12)
- Verify Socket.IO connection in Network tab

---

## 📝 Notes

- The Python endpoint agent (`enterprise_endpoint_agent.py`) is now the primary agent
- The JavaScript agent has been removed to avoid conflicts
- All telemetry data is now properly formatted and displayed in real-time
- Device control commands are sent via Socket.IO to the Python agent

---

## 🎯 Testing the Changes

1. Start the server: `node index.js`
2. Open dashboard: http://localhost:3000
3. Start Python agent: `python enterprise_endpoint_agent.py`
4. Navigate to "Endpoint Protector" section
5. You should see:
   - Agent card with live telemetry
   - CPU and memory usage with progress bars
   - Top processes listed
   - Network interfaces displayed
   - Real-time updates every few seconds
   - Device control dropdown menu

Enjoy! 🎉

