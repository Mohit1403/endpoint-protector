# Quick Node.js Installation Guide

## 🚀 Fastest Way to Install Node.js

### Step 1: Download Node.js
**Direct Download Link:**
- **Windows 64-bit LTS**: https://nodejs.org/dist/v20.11.0/node-v20.11.0-x64.msi
- **Or visit**: https://nodejs.org/ and click "Download Node.js (LTS)"

### Step 2: Install
1. Run the downloaded `.msi` file
2. Click "Next" through the installer
3. **IMPORTANT**: Make sure "Add to PATH" checkbox is checked ✅
4. Click "Install"
5. Wait for installation to complete
6. Click "Finish"

### Step 3: Verify (IMPORTANT!)
1. **Close your current PowerShell window completely**
2. **Open a NEW PowerShell window**
3. Run these commands:
   ```powershell
   node --version
   npm --version
   ```
4. You should see version numbers (like `v20.11.0` and `10.2.4`)

### Step 4: Install Project Dependencies
Once Node.js is installed, run:
```powershell
cd E:\pentesting_tool-main
npm install
```

### Step 5: Start the Server
```powershell
node index.js
```

---

## ⚡ Alternative: Using Winget (Windows Package Manager)

If you have Windows 10/11 with winget:
```powershell
winget install OpenJS.NodeJS.LTS
```

Then close and reopen PowerShell.

---

## 🔍 Check Installation

After installing, run this in a NEW PowerShell window:
```powershell
node --version
npm --version
```

If you see version numbers, you're good to go! ✅

---

## ❗ Common Issues

### "Still says npm not recognized"
- **Solution**: Close PowerShell completely and open a new window
- The PATH is updated, but existing windows don't see it

### "Installation failed"
- Run PowerShell as Administrator
- Try downloading the installer again
- Check Windows Defender/antivirus isn't blocking it

---

## 📞 Need Help?

See `INSTALL_NODEJS.md` for detailed troubleshooting steps.

