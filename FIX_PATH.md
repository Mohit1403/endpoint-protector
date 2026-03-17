# Fix Node.js PATH Issue

## ✅ Good News!
Node.js **IS installed** on your system at:
```
C:\Program Files\nodejs
```

However, it's **not in your PATH**, which is why PowerShell can't find it.

---

## 🔧 Quick Fix (Current Session Only)

I've already added Node.js to PATH for your current PowerShell session. You can now run:
```powershell
npm install
node index.js
```

**Note**: This only works in the current PowerShell window. If you close it, you'll need to add it again.

---

## 🎯 Permanent Fix (Recommended)

To make Node.js available in all PowerShell windows:

### Method 1: Using System Properties (Easiest)

1. Press `Win + X` and select **"System"**
2. Click **"Advanced system settings"** (on the right)
3. Click **"Environment Variables"** button (at the bottom)
4. Under **"System variables"** (bottom section), find **"Path"** and click **"Edit"**
5. Click **"New"** button
6. Add this path: `C:\Program Files\nodejs`
7. Click **"OK"** on all dialogs
8. **Close and reopen PowerShell** (important!)

### Method 2: Using PowerShell (Run as Administrator)

```powershell
# Run PowerShell as Administrator, then:
[Environment]::SetEnvironmentVariable(
    "Path",
    [Environment]::GetEnvironmentVariable("Path", "Machine") + ";C:\Program Files\nodejs",
    "Machine"
)
```

Then close and reopen PowerShell.

---

## ✅ Verify It Works

After adding to PATH permanently, open a **NEW** PowerShell window and run:
```powershell
node --version
npm --version
```

You should see version numbers. If you do, it's working! ✅

---

## 🚀 Next Steps

Once Node.js is in PATH:

1. **Install dependencies:**
   ```powershell
   cd E:\pentesting_tool-main
   npm install
   ```

2. **Start the server:**
   ```powershell
   node index.js
   ```

3. **Open browser:**
   ```
   http://localhost:3000
   ```

---

## 💡 Why This Happened

Sometimes Node.js installer doesn't properly add to PATH, or the PATH was modified after installation. This is a common Windows issue.

---

## 🆘 Still Not Working?

If you still have issues after adding to PATH:

1. Make sure you **closed and reopened PowerShell** completely
2. Check PATH includes Node.js:
   ```powershell
   $env:PATH -split ';' | Select-String "nodejs"
   ```
3. If it's there but still not working, try restarting your computer

