# Installing Node.js for AutoPentrix

## 🚨 Error: Node.js/npm not found

Node.js is required to run this application. Follow these steps to install it:

---

## 📥 Option 1: Install Node.js (Recommended)

### Step 1: Download Node.js
1. Go to: **https://nodejs.org/**
2. Download the **LTS (Long Term Support)** version
3. Choose the **Windows Installer (.msi)** for your system (64-bit recommended)

### Step 2: Install Node.js
1. Run the downloaded `.msi` file
2. Follow the installation wizard
3. **Important**: Make sure "Add to PATH" is checked during installation
4. Complete the installation

### Step 3: Verify Installation
Open a **NEW** PowerShell window (important - close and reopen) and run:
```powershell
node --version
npm --version
```

You should see version numbers. If you do, Node.js is installed correctly!

---

## 🔧 Option 2: Using Chocolatey (If you have it)

If you have Chocolatey package manager installed:
```powershell
choco install nodejs-lts
```

---

## 🔍 Option 3: Check if Node.js is Already Installed

Sometimes Node.js is installed but not in PATH. Check these locations:

```powershell
# Check common installation paths
Test-Path "C:\Program Files\nodejs\node.exe"
Test-Path "C:\Program Files (x86)\nodejs\node.exe"
Test-Path "$env:APPDATA\npm\node.exe"
```

If Node.js exists in one of these locations, you need to add it to PATH.

---

## 🛠️ Adding Node.js to PATH (If Already Installed)

### Method 1: Using System Properties
1. Press `Win + X` and select "System"
2. Click "Advanced system settings"
3. Click "Environment Variables"
4. Under "System variables", find "Path" and click "Edit"
5. Click "New" and add:
   - `C:\Program Files\nodejs`
   - `C:\Users\Admin\AppData\Roaming\npm` (if exists)
6. Click "OK" on all dialogs
7. **Restart PowerShell** (close and reopen)

### Method 2: Using PowerShell (Temporary - Current Session Only)
```powershell
$env:PATH += ";C:\Program Files\nodejs"
```

---

## ✅ After Installation

1. **Close and reopen PowerShell** (important!)
2. Navigate to your project:
   ```powershell
   cd E:\pentesting_tool-main
   ```
3. Install dependencies:
   ```powershell
   npm install
   ```
4. Start the server:
   ```powershell
   node index.js
   ```

---

## 🐛 Troubleshooting

### "npm is not recognized" after installing Node.js
- **Solution**: Close and reopen PowerShell/Command Prompt
- Node.js installer adds to PATH, but existing terminals don't see it

### Still not working?
1. Check if Node.js is actually installed:
   ```powershell
   Get-ChildItem "C:\Program Files" -Filter "nodejs" -Directory
   ```

2. Manually add to PATH (see Method 1 above)

3. Verify PATH includes Node.js:
   ```powershell
   $env:PATH -split ';' | Select-String "node"
   ```

---

## 📝 Quick Check Script

Run this to check your Node.js installation:

```powershell
Write-Host "Checking Node.js installation..." -ForegroundColor Cyan
Write-Host ""

# Check if node exists
$nodePath = Get-Command node -ErrorAction SilentlyContinue
if ($nodePath) {
    Write-Host "✓ Node.js found at: $($nodePath.Source)" -ForegroundColor Green
    Write-Host "  Version: $(node --version)" -ForegroundColor Green
} else {
    Write-Host "✗ Node.js not found in PATH" -ForegroundColor Red
    Write-Host "  Please install Node.js from https://nodejs.org/" -ForegroundColor Yellow
}

Write-Host ""

# Check if npm exists
$npmPath = Get-Command npm -ErrorAction SilentlyContinue
if ($npmPath) {
    Write-Host "✓ npm found at: $($npmPath.Source)" -ForegroundColor Green
    Write-Host "  Version: $(npm --version)" -ForegroundColor Green
} else {
    Write-Host "✗ npm not found in PATH" -ForegroundColor Red
}

Write-Host ""
```

---

## 🎯 Next Steps

Once Node.js is installed:
1. Run `npm install` to install dependencies
2. Run `node index.js` to start the server
3. Open http://localhost:3000 in your browser

---

## 📚 Additional Resources

- Node.js Official Site: https://nodejs.org/
- Node.js Documentation: https://nodejs.org/docs/
- npm Documentation: https://docs.npmjs.com/

