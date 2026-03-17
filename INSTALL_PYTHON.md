# Installing Python and Dependencies for Endpoint Agent

## 🚨 Error: Python or socketio module not found

The Python endpoint agent requires Python 3.7+ and several packages. Follow these steps:

---

## 📥 Step 1: Install Python

### Option A: Using Windows Store (Easiest)
1. Open Microsoft Store
2. Search for "Python 3.12" or "Python 3.11"
3. Click "Install"
4. Wait for installation

### Option B: Download from python.org (Recommended)
1. Go to: **https://www.python.org/downloads/**
2. Download **Python 3.11** or **Python 3.12** (latest stable)
3. Run the installer
4. **IMPORTANT**: Check ✅ "Add Python to PATH" during installation
5. Complete installation

### Option C: Using Winget (If available)
```powershell
winget install Python.Python.3.12
```

---

## ✅ Step 2: Verify Python Installation

**Close and reopen PowerShell**, then run:
```powershell
python --version
```

You should see something like: `Python 3.12.0`

---

## 📦 Step 3: Install Required Packages

Once Python is installed, install the dependencies:

```powershell
# Navigate to project directory
cd E:\pentesting_tool-main

# Install all required packages
pip install python-socketio[client] psutil watchdog

# For Linux only (optional):
pip install pyudev
```

Or install from requirements file:
```powershell
pip install -r requirements.txt
```

---

## 🔍 Required Packages

The endpoint agent needs:
- **python-socketio[client]** - Socket.IO client for Python
- **psutil** - System and process utilities (for CPU, memory, USB detection)
- **watchdog** - File system monitoring (for file change alerts)
- **pyudev** - USB device monitoring (Linux only, optional)

---

## 🚀 Step 4: Run the Agent

After installing Python and packages:

```powershell
python enterprise_endpoint_agent.py
```

Or:
```powershell
py enterprise_endpoint_agent.py
```

---

## 🐛 Troubleshooting

### "python is not recognized"
- **Solution**: Python is not in PATH
- Add Python to PATH (see below) or reinstall with "Add to PATH" checked

### "pip is not recognized"
- **Solution**: pip comes with Python, but might not be in PATH
- Try: `python -m pip install ...` instead of `pip install ...`

### "ModuleNotFoundError: No module named 'socketio'"
- **Solution**: Install the package:
  ```powershell
  pip install python-socketio[client]
  ```

### Using py launcher (Windows)
If you have Python installed but `python` doesn't work, try:
```powershell
py -3 enterprise_endpoint_agent.py
py -3 -m pip install python-socketio[client] psutil watchdog
```

---

## 🔧 Adding Python to PATH (If Already Installed)

1. Find Python installation (usually `C:\Python312` or `C:\Users\Admin\AppData\Local\Programs\Python\Python312`)
2. Press `Win + X` → System → Advanced system settings
3. Click "Environment Variables"
4. Under "System variables", find "Path" → Edit
5. Add these paths:
   - `C:\Python312` (or your Python folder)
   - `C:\Python312\Scripts` (for pip)
6. Click OK, close and reopen PowerShell

---

## ✅ Quick Check

Run this to verify everything is ready:
```powershell
python --version
pip --version
pip list | Select-String "socketio|psutil|watchdog"
```

---

## 📝 Alternative: Use Virtual Environment (Recommended)

For better package management:

```powershell
# Create virtual environment
python -m venv venv

# Activate it
.\venv\Scripts\Activate.ps1

# Install packages
pip install python-socketio[client] psutil watchdog

# Run agent
python enterprise_endpoint_agent.py
```

---

## 🎯 Next Steps

Once Python and packages are installed:

1. **Start the backend server** (if not running):
   ```powershell
   node index.js
   ```

2. **Start the Python agent**:
   ```powershell
   python enterprise_endpoint_agent.py
   ```

3. **Open dashboard**: http://localhost:3000
4. **Navigate to**: Endpoint Protector section
5. **See live data**: Agent should appear with telemetry

---

## 📚 Resources

- Python Downloads: https://www.python.org/downloads/
- pip Documentation: https://pip.pypa.io/
- python-socketio: https://python-socketio.readthedocs.io/

