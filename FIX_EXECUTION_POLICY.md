# Fix PowerShell Execution Policy for npm

## 🔒 Issue
PowerShell is blocking npm scripts because execution policy is too restrictive.

Error message:
```
File C:\Program Files\nodejs\npm.ps1 cannot be loaded because running scripts is disabled on this system.
```

---

## ✅ Solution

### Option 1: Change Execution Policy (Recommended)

Run PowerShell **as Administrator** and execute:
```powershell
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```

Then type `Y` when prompted.

**What this does:**
- Allows local scripts to run
- Requires downloaded scripts to be signed
- Only affects your user account (safe)

### Option 2: Use npm.cmd Instead

You can use the `.cmd` version which doesn't require script execution:
```powershell
& "C:\Program Files\nodejs\npm.cmd" install
```

Or create an alias:
```powershell
Set-Alias npm "C:\Program Files\nodejs\npm.cmd"
npm install
```

### Option 3: Bypass for Single Command

```powershell
powershell -ExecutionPolicy Bypass -Command "npm install"
```

---

## 🎯 Quick Fix (Already Applied)

I've already updated your execution policy for the current session. You should now be able to run:
```powershell
npm install
```

---

## ✅ Verify It Works

After fixing, test with:
```powershell
npm --version
```

You should see a version number (like `10.2.4`).

---

## 📝 Execution Policy Levels

- **Restricted** - No scripts allowed (default on some systems)
- **RemoteSigned** - Local scripts OK, remote must be signed (recommended)
- **Unrestricted** - All scripts allowed (less secure)

**RemoteSigned** is the recommended setting for most users.

---

## 🚀 Next Steps

Once npm works:

1. **Install dependencies:**
   ```powershell
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

## ⚠️ Note

The execution policy change I made is for the **current session only**. For permanent fix, run as Administrator:
```powershell
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```

