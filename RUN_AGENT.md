# Running the Python Endpoint Agent

## ✅ Dependencies Installed!

All required Python packages have been installed:
- ✅ python-socketio[client]
- ✅ psutil
- ✅ watchdog

---

## 🚀 Running the Agent

### Important: Use `py` command

On your system, use the `py` launcher instead of `python`:

```powershell
py enterprise_endpoint_agent.py
```

**NOT** `python enterprise_endpoint_agent.py` (this won't work)

---

## 📋 Prerequisites

1. **Backend server must be running:**
   ```powershell
   node index.js
   ```
   Server should be on: http://localhost:3000

2. **Agent will connect automatically** to: http://localhost:3000

---

## 🔧 Configuration (Optional)

You can customize the agent with environment variables:

```powershell
# Set backend URL (default: http://localhost:3000)
$env:ENDPOINT_PROTECTOR_URL="http://localhost:3000"

# Set agent token (default: dev-agent)
$env:ENDPOINT_AGENT_TOKEN="dev-agent"

# Set telemetry interval in seconds (default: 10)
$env:ENDPOINT_TELEMETRY_INTERVAL="10"

# Set custom agent ID (default: auto-generated)
$env:ENDPOINT_AGENT_ID="my-custom-agent-id"

# Run the agent
py enterprise_endpoint_agent.py
```

---

## ✅ What to Expect

When you run the agent, you should see:

```
[agent] Connected to backend at http://localhost:3000
[agent] Telemetry send error: ...
```

The agent will:
1. Connect to the backend server
2. Register itself
3. Send telemetry every 10 seconds
4. Monitor file changes and USB devices
5. Send alerts when events occur

---

## 🎯 Testing

1. **Start backend** (if not running):
   ```powershell
   node index.js
   ```

2. **Start agent** (in another terminal):
   ```powershell
   cd E:\pentesting_tool-main
   py enterprise_endpoint_agent.py
   ```

3. **Open dashboard**: http://localhost:3000

4. **Navigate to**: "Endpoint Protector" section

5. **You should see**:
   - Agent card appears
   - Live CPU and memory data
   - Top processes listed
   - Network interfaces
   - Real-time updates

---

## 🐛 Troubleshooting

### "ModuleNotFoundError: No module named 'socketio'"
- **Solution**: Install packages:
  ```powershell
  py -m pip install python-socketio[client] psutil watchdog
  ```

### "Connection refused" or "Cannot connect"
- **Solution**: Make sure backend server is running:
  ```powershell
  node index.js
  ```

### Agent connects but no data shows
- Check browser console (F12) for errors
- Verify Socket.IO connection in Network tab
- Check backend server logs

### "py is not recognized"
- Python might not be installed
- See INSTALL_PYTHON.md for installation instructions

---

## 📝 Notes

- Use `py` command, not `python` or `python3`
- Agent runs continuously until stopped (Ctrl+C)
- Telemetry is sent every 10 seconds by default
- File monitoring watches your home directory
- USB monitoring works on Windows (via psutil)

---

## 🎉 Success!

If everything works, you'll see the agent in the dashboard with live telemetry data updating in real-time!

