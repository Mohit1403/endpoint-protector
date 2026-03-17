# Critical Fixes and File Restoration Guide

## ⚠️ IMPORTANT: Agent File Restoration Required

The `enterprise_endpoint_agent.py` file was accidentally overwritten during editing. You need to restore it from your backup or version control.

## Quick Restoration Steps

1. **If you have a backup or version control:**
   ```powershell
   # Restore from backup or git
   # Then apply the fixes below
   ```

2. **If you don't have a backup:**
   - The file should be approximately 1900+ lines
   - Check if you have it in another location
   - The original file structure includes all the functions we've been working with

## All Required Fixes

### Fix 1: CPU Usage Calculation (Process CPU showing 100%)

**Problem**: Windows processes show 100% CPU because it's using cumulative CPU time instead of percentage.

**Solution**: In `collect_process_summary()` function, replace Windows section with:

```python
elif SYSTEM == "windows":
    # Use psutil for accurate CPU percentage on Windows
    if psutil_lib:
        try:
            processes = []
            for proc in psutil_lib.process_iter(['pid', 'name', 'cpu_percent', 'memory_info']):
                try:
                    proc_info = proc.info
                    # Get CPU percent with a small interval for accuracy
                    cpu_percent = proc.cpu_percent(interval=0.1)
                    processes.append({
                        "pid": proc_info['pid'],
                        "name": proc_info['name'],
                        "cpu_pct": cpu_percent,  # This is the percentage, not cumulative time
                        "cpu_time": None,
                        "working_set": proc_info['memory_info'].rss if proc_info.get('memory_info') else 0
                    })
                except (psutil_lib.NoSuchProcess, psutil_lib.AccessDenied, psutil_lib.ZombieProcess):
                    continue
            
            summary["total_processes"] = len(processes)
            summary["top_cpu"] = sorted(processes, key=lambda x: x["cpu_pct"], reverse=True)[:5]
            summary["top_memory"] = sorted(processes, key=lambda x: x.get("working_set", 0), reverse=True)[:5]
        except Exception as e:
            logging.debug(f"psutil process collection failed: {e}")
            # Fallback to PowerShell (but won't have accurate CPU %)
```

**Also fix** in `send_telemetry()` around line 303:

```python
for proc in top_cpu[:5]:
    # Get CPU percentage - prefer cpu_pct, fallback to 0 if not available
    cpu_pct = proc.get("cpu_pct")
    if cpu_pct is None:
        cpu_pct = 0.0
    else:
        cpu_pct = float(cpu_pct)
    
    formatted_proc = {
        "pid": proc.get("pid") or proc.get("Id"),
        "name": proc.get("name") or proc.get("ProcessName") or proc.get("comm", "Unknown"),
        "cpu": clamp_percent(cpu_pct),  # Use cpu_pct directly, NOT cpu_time
        "memoryMB": 0.0
    }
    # Handle memory conversion...
```

### Fix 2: USB Blocking Implementation

**Problem**: USB blocking command only sets a flag but doesn't actually block USB devices.

**Solution**: Add these functions after `update_agent_config()`:

```python
def block_usb_devices() -> bool:
    """Block USB devices using Windows registry or system commands."""
    try:
        if SYSTEM == "windows":
            # Method 1: Disable USB storage via registry (requires admin)
            reg_cmd = """
            $regPath = "HKLM:\\SYSTEM\\CurrentControlSet\\Services\\USBSTOR"
            if (Test-Path $regPath) {
                Set-ItemProperty -Path $regPath -Name "Start" -Value 4 -Type DWord -Force
                Write-Host "USB storage disabled via registry"
            }
            # Method 2: Disable USB controllers
            Get-PnpDevice -Class USB | Where-Object {$_.Status -eq 'OK'} | Disable-PnpDevice -Confirm:$false -ErrorAction SilentlyContinue
            """
            result = run_powershell(reg_cmd, timeout=15)
            return bool(result)
        elif SYSTEM == "linux":
            run_cmd(["sudo", "modprobe", "-r", "usb_storage"], timeout=5)
            return True
        elif SYSTEM == "darwin":
            run_cmd(["sudo", "kextunload", "-b", "com.apple.iokit.IOUSBMassStorageClass"], timeout=5)
            return True
        return False
    except Exception as e:
        logging.error(f"Failed to block USB devices: {e}")
        return False

def unblock_usb_devices() -> bool:
    """Unblock USB devices."""
    try:
        if SYSTEM == "windows":
            reg_cmd = """
            $regPath = "HKLM:\\SYSTEM\\CurrentControlSet\\Services\\USBSTOR"
            if (Test-Path $regPath) {
                Set-ItemProperty -Path $regPath -Name "Start" -Value 3 -Type DWord -Force
                Write-Host "USB storage enabled via registry"
            }
            Get-PnpDevice -Class USB | Where-Object {$_.Status -eq 'Error'} | Enable-PnpDevice -Confirm:$false -ErrorAction SilentlyContinue
            """
            result = run_powershell(reg_cmd, timeout=15)
            return bool(result)
        elif SYSTEM == "linux":
            run_cmd(["sudo", "modprobe", "usb_storage"], timeout=5)
            return True
        elif SYSTEM == "darwin":
            run_cmd(["sudo", "kextload", "-b", "com.apple.iokit.IOUSBMassStorageClass"], timeout=5)
            return True
        return False
    except Exception as e:
        logging.error(f"Failed to unblock USB devices: {e}")
        return False
```

**Update** the command handler around line 197:

```python
elif command == "block_usb":
    print("[agent] Executing block USB devices command")
    AGENT_STATE["usb_blocked"] = True
    success = block_usb_devices()  # Actually block USB
    if success:
        send_alert("USB_BLOCKING_ENABLED", "CRITICAL", "USB device blocking has been enabled by administrator")
    else:
        send_alert("USB_BLOCKING_FAILED", "WARNING", "USB blocking command executed but may require administrator privileges")

elif command == "unblock_usb":
    print("[agent] Executing unblock USB devices command")
    AGENT_STATE["usb_blocked"] = False
    success = unblock_usb_devices()  # Actually unblock USB
    if success:
        send_alert("USB_BLOCKING_DISABLED", "INFO", "USB device blocking has been disabled by administrator")
    else:
        send_alert("USB_UNBLOCKING_FAILED", "WARNING", "USB unblocking command executed but may require administrator privileges")
```

**Note**: USB blocking requires administrator/root privileges on Windows.

### Fix 3: IP Address Detection

**Problem**: IP address shown doesn't match the actual system IP from `ipconfig`.

**Solution**: Replace IP detection in `connect()` function:

```python
# Get IP address - improved detection to match actual system IP
ip_address = None
try:
    # Method 1: Connect to external server to get local IP (most reliable)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(("8.8.8.8", 80))
    ip_address = s.getsockname()[0]
    s.close()
except Exception:
    try:
        # Method 2: Get primary network interface IP (platform-specific)
        if SYSTEM == "windows":
            # Use PowerShell to get the primary IP (exclude loopback and APIPA)
            ip_result = run_powershell("(Get-NetIPAddress -AddressFamily IPv4 | Where-Object {$_.InterfaceAlias -notlike '*Loopback*' -and $_.IPAddress -notlike '169.254.*' -and $_.IPAddress -notlike '127.*'} | Sort-Object InterfaceIndex | Select-Object -First 1).IPAddress")
            if ip_result and ip_result.strip():
                ip_address = ip_result.strip()
        elif SYSTEM == "linux":
            ip_result = run_cmd(["/usr/sbin/ip", "-4", "addr", "show"])
            for line in ip_result.splitlines():
                if "inet " in line and "127.0.0.1" not in line and "169.254" not in line:
                    parts = line.strip().split()
                    if len(parts) >= 2:
                        ip_address = parts[1].split("/")[0]
                        break
        elif SYSTEM == "darwin":
            ip_result = run_cmd(["/sbin/ifconfig"])
            for line in ip_result.splitlines():
                if "inet " in line and "127.0.0.1" not in line and "169.254" not in line:
                    parts = line.strip().split()
                    if len(parts) >= 2:
                        ip_address = parts[1]
                        break
    except Exception:
        pass
    
    # Fallback: use psutil to get network interfaces
    if not ip_address:
        try:
            if psutil_lib:
                addrs = psutil_lib.net_if_addrs()
                for iface_name, iface_addrs in addrs.items():
                    if "Loopback" not in iface_name and "lo" not in iface_name:
                        for addr in iface_addrs:
                            if addr.family == socket.AF_INET and addr.address != "127.0.0.1" and not addr.address.startswith("169.254"):
                                ip_address = addr.address
                                break
                        if ip_address:
                            break
        except Exception:
            pass
    
    if not ip_address:
        ip_address = "0.0.0.0"
```

### Fix 4: Add Network Traffic to Telemetry

**Location**: In `send_telemetry()` around line 430, update network section:

```python
"network": {
    "interfaces": formatted_interfaces,
    "hostname": socket.gethostname(),
    "external_ip": network_info.get("external_ip"),
    "primaryIp": primary_ip,
    "dns_servers": network_info.get("dns_servers", []),
    "traffic": network_info.get("network_traffic", {}),  # Add this
    "connection_history": network_info.get("connection_history", []),  # Add this
    "firewall_status": network_info.get("firewall_status", False)  # Add this
},
```

### Fix 5: Windows Event Log Monitoring

**Add at the end of the file** (before `if __name__ == "__main__"`):

```python
# Windows Event Log monitoring (optional - requires pywin32)
if SYSTEM == "windows":
    try:
        import win32evtlog
        import win32evtlogutil
        import win32con
        WINDOWS_EVENT_LOG_AVAILABLE = True
        
        def monitor_windows_events():
            """Monitor Windows Event Log and send events via WebSocket."""
            try:
                log_types = ["Security", "System", "Application"]
                for log_type in log_types:
                    try:
                        hand = win32evtlog.OpenEventLog(None, log_type)
                        flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
                        events = win32evtlog.ReadEventLog(hand, flags, 0)
                        
                        for event in events:
                            if event.EventType in [win32con.EVENTLOG_ERROR_TYPE, win32con.EVENTLOG_WARNING_TYPE]:
                                try:
                                    message = win32evtlogutil.SafeFormatMessage(event, log_type)
                                except Exception:
                                    message = f"Event ID {event.EventID}"
                                
                                event_data = {
                                    "alertType": "WINDOWS_EVENT",
                                    "severity": "HIGH" if event.EventType == win32con.EVENTLOG_ERROR_TYPE else "MEDIUM",
                                    "type": "WINDOWS_EVENT",
                                    "message": f"Windows Event: {log_type} - {message}",
                                    "details": {
                                        "log_type": log_type,
                                        "event_id": event.EventID,
                                        "event_type": event.EventType,
                                        "source": event.SourceName
                                    },
                                    "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat().replace("+00:00", "Z")
                                }
                                safe_emit("endpoint-agent:alert", {"agentId": AGENT_ID, "events": [event_data]})
                        
                        win32evtlog.CloseEventLog(hand)
                    except Exception as e:
                        logging.debug(f"Windows Event Log monitoring failed for {log_type}: {e}")
            except Exception as e:
                logging.debug(f"Windows Event Log monitoring setup failed: {e}")
        
        def windows_event_monitor_thread():
            while True:
                try:
                    monitor_windows_events()
                except Exception as e:
                    logging.debug(f"Windows event monitor error: {e}")
                time.sleep(30)  # Check every 30 seconds
        
        threading.Thread(target=windows_event_monitor_thread, daemon=True, name="WindowsEventMonitor").start()
    except ImportError:
        logging.info("Windows Event Log monitoring not available (pywin32 not installed)")
        WINDOWS_EVENT_LOG_AVAILABLE = False
```

**Install pywin32 for Windows Event Log:**
```powershell
pip install pywin32
```

## Frontend Improvements Already Applied

✅ Chart.js library added for graphs
✅ Performance metrics graphs section added
✅ Windows Event Log display section added
✅ Graph initialization and update functions added
✅ Windows events rendering function added

## Next Steps

1. **Restore the agent file** from backup
2. **Apply all fixes** listed above
3. **Install pywin32** for Windows Event Log: `pip install pywin32`
4. **Test the agent** to ensure everything works
5. **Check the dashboard** for graphs and Windows Event Log

## Testing Checklist

After restoration and fixes:
- [ ] Agent starts without errors
- [ ] Agent connects to backend
- [ ] CPU usage shows correct percentages (not 100%)
- [ ] USB blocking actually blocks USB devices (requires admin)
- [ ] IP address matches `ipconfig` output
- [ ] Network traffic stats appear in telemetry
- [ ] Graphs show CPU, memory, and network usage
- [ ] Windows Event Log events appear (if pywin32 installed)
- [ ] All commands work from dashboard

## Contact

If you need help restoring the file, please provide:
- The original file if you have it
- Any error messages you're seeing
- Your Python version

