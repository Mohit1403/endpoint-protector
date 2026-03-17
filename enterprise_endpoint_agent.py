#!/usr/bin/env python3
"""
Enterprise Endpoint Agent (macOS / Windows / Linux)
---------------------------------------------------
- Collects hardware identifiers, OS & patch info, network interfaces (internal/external IP, MAC, SSID, state),
  security posture (firewall, disk encryption, SIP/Secure Boot, Gatekeeper, EDR), installed software inventory,
  process summary, compliance checks (MDM, disk encryption, screen lock, updates), and more.
- Produces normalized JSON with SHA-256 checksum.
- Includes robust error handling/fallback logic and an extension hook for future capabilities.
- Jamf deployment instructions preserved for macOS; Windows/Linux endpoints can run via scheduled task/cron.
"""

import datetime
import hashlib
import json
import pathlib
import platform
import shutil
import socket
import subprocess
from typing import Any, Callable, Dict, List, Optional, Set
from urllib import request as urlrequest
import threading
import time
import socketio
import os
import logging

# Enable informative logging for troubleshooting connection issues (kept minimal)
logging.basicConfig(level=logging.INFO)
logging.getLogger("socketio").setLevel(logging.WARNING)
logging.getLogger("engineio").setLevel(logging.WARNING)

try:
    from watchdog.observers import Observer
    from watchdog.events import FileSystemEventHandler
except ImportError:
    FileSystemEventHandler = object  # Dummy for code completeness
    Observer = None

# USB detection:
try:
    import pyudev  # Linux specific
except ImportError:
    pyudev = None

try:
    import psutil  # USB polling for Windows (mass storage)
    import psutil as psutil_lib  # Alias for consistency
except ImportError:
    psutil = None
    psutil_lib = None

SYSTEM = platform.system().lower()
EXTENSIONS: List[Callable[[], Dict[str, Any]]] = []

SOCKETIO_URL = os.environ.get("ENDPOINT_PROTECTOR_URL", "http://localhost:3000")
AGENT_TOKEN = os.environ.get("ENDPOINT_AGENT_TOKEN", "dev-agent")

def load_or_create_agent_uuid() -> str:
    """
    Stable, persistent UUID used for endpoint identity (prevents duplicate agents on restarts).
    Stored in the user's home directory.
    """
    uuid_str = os.environ.get("ENDPOINT_AGENT_UUID")
    if uuid_str:
        return uuid_str
    uuid_file = pathlib.Path.home() / ".endpoint_agent_uuid"
    try:
        if uuid_file.exists():
            val = uuid_file.read_text(encoding="utf-8").strip()
            if val:
                return val
    except Exception:
        pass
    try:
        import uuid as _uuid
        uuid_str = str(_uuid.uuid4())
        uuid_file.write_text(uuid_str, encoding="utf-8")
        return uuid_str
    except Exception:
        return f"{socket.gethostname()}-{int(time.time())}"

AGENT_UUID = load_or_create_agent_uuid()

# Prefer UUID as agentId; allow override via env var
AGENT_ID = os.environ.get("ENDPOINT_AGENT_ID", AGENT_UUID)
TELEMETRY_INTERVAL = int(os.environ.get("ENDPOINT_TELEMETRY_INTERVAL", "10"))

# Agent state management
AGENT_STATE = {
    "usb_blocked": False,
    "network_blocked": {},
    "users_blocked": set(),
    "process_cache": {},
    "network_connections_history": [],
    "file_changes_history": [],
    "windows_events": [],
    "pending_operations": [],
    "last_connection_time": 0,
    "connection_attempts": 0
}

sio = socketio.Client(reconnection=True, reconnection_attempts=0, reconnection_delay=2, reconnection_delay_max=10)

# ---------------------
# Utility: safe emit
# ---------------------
def safe_emit(event: str, payload: Any) -> None:
    """Emit safely — does nothing if not connected and catches errors."""
    try:
        if getattr(sio, "connected", False):
            sio.emit(event, payload)
        else:
            logging.debug(f"[agent] not connected; dropping event {event}")
    except Exception as e:
        error_msg = str(e)
        if "not a connected namespace" in error_msg or "namespace" in error_msg:
            # Critical namespace error - disconnect to force reconnection
            logging.warning(f"[agent] namespace error for {event}: {e}. Forcing reconnection...")
            try:
                sio.disconnect()
            except:
                pass
        else:
            logging.warning(f"[agent] safe_emit error for {event}: {e}")


# ---------------------
# Socket.IO handlers
# ---------------------
@sio.event
def connect():
    print(f"[agent] Connected to backend at {SOCKETIO_URL}")
    
    # Update connection state
    global AGENT_STATE
    AGENT_STATE["last_connection_time"] = time.time()
    AGENT_STATE["connection_attempts"] = 0
    
    # Wait a brief moment to ensure connection is fully established
    time.sleep(0.5)  # Increased from 0.2 to 0.5 for more stable connection
    
    # Use more robust connection checking - Socket.IO connection state can be complex
    # Check both the connected attribute and socketio internal state
    is_connected = getattr(sio, "connected", False)
    
    # If not connected by attribute, use a safer check without emitting
    if not is_connected:
        # Instead of emitting (which can cause namespace errors), check transport state
        try:
            # Check if the engine is actually connected
            transport_connected = getattr(sio, "transport", "") != ""
            is_connected = transport_connected
        except:
            is_connected = False
    
    if not is_connected:
        print("[agent] Connection not fully established, waiting a bit longer...")
        time.sleep(1.0)  # Additional wait for connection stabilization
        # Re-check connection status
        is_connected = getattr(sio, "connected", False)
    
    # ---------------------------------------------------------
    # Optimization: Perform registration handshake immediately
    # ---------------------------------------------------------
    
    # Quick hostname check (fast)
    hostname = socket.gethostname()
    
    # Fastest IP check (synchronous but short timeout)
    ip_address = "0.0.0.0"
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(0.5) # Fast 500ms timeout
        s.connect(("8.8.8.8", 80))
        ip_address = s.getsockname()[0]
        s.close()
    except Exception:
        try:
            ip_address = socket.gethostbyname(hostname)
        except Exception:
            pass

    # Quick system info (lightweight calls)
    identifiers = collect_identifiers()
    cpu_info = identifiers.get("cpu", {})
    mem_info = identifiers.get("memory", {})
    
    # Send registration payload immediately
    payload = {
        "agentId": AGENT_ID,
        "uuid": AGENT_UUID,
        "hostname": hostname,
        "platform": f"{platform.system()} {platform.release()}",
        "ipAddress": ip_address, 
        "version": "4.0.0",
        "tags": [platform.system().lower()],
        "owner": os.environ.get("ENDPOINT_AGENT_OWNER", os.getenv("USER", "Unknown")),
        "organizationId": os.environ.get("ENDPOINT_ORGANIZATION_ID"),
        "apiKey": os.environ.get("ENDPOINT_API_KEY", "dev-agent"),
        "agentToken": AGENT_TOKEN,
        # Provide basic telemetry immediately in registration for instant dashboard population
        "telemetry": {
            "cpu": {"model": cpu_info.get("model"), "cores": cpu_info.get("cores")},
            "memory": {"total_bytes": mem_info.get("total_bytes")},
            "status": "ONLINE"
        }
    }
    
    def on_register_ack(response):
        if isinstance(response, dict) and response.get("success"):
            print(f"[agent] Registration successful (Ack): {response}")
            # Start full telemetry only after successful registration
            try:
                # Run IP detection in background/thread to not block
                threading.Thread(target=send_telemetry, daemon=True).start()
                send_alerts()
            except Exception as e:
                logging.warning(f"[agent] initial send_telemetry failed: {e}")
        else:
            print(f"[agent] Registration failed or no ack: {response}")

    # Emit with callback to ensure server processed it
    try:
        # Always attempt registration - let the server handle it even if connection seems unstable
        sio.emit("endpoint-agent:register", payload, callback=on_register_ack)
        print("[agent] Registration request sent to backend")
    except Exception as e:
        error_msg = str(e)
        print(f"[agent] Registration emit failed: {e}")
        
        # Handle specific namespace errors differently
        if "not a connected namespace" in error_msg or "namespace" in error_msg:
            print("[agent] Namespace error detected - forcing reconnection...")
            try:
                sio.disconnect()
            except:
                pass
        else:
            # For other errors, wait a bit and retry registration
            print("[agent] Retrying registration in 2 seconds...")
            time.sleep(2)
            try:
                sio.emit("endpoint-agent:register", payload, callback=on_register_ack)
                print("[agent] Registration retry sent")
            except Exception as retry_error:
                print(f"[agent] Registration retry also failed: {retry_error}")



@sio.event
def connect_error(err):
    error_msg = str(err)
    print(f"[agent] Connection error to backend: {error_msg}")
    
    # Handle namespace errors specifically
    if "namespace" in error_msg or "not a connected namespace" in error_msg:
        print("[agent] Namespace error detected - attempting to fix namespace configuration")
        # Add a small delay before reconnection to prevent rapid reconnection loops
        time.sleep(2.0)
        
        # Force a clean disconnect and reconnect to fix namespace issues
        try:
            sio.disconnect()
        except:
            pass
        
        # Wait a moment before attempting to reconnect
        time.sleep(1.0)
        
        # Reinitialize the connection with proper namespace
        try:
            sio.connect(SOCKETIO_URL, namespaces=['/'])
        except Exception as reconnect_err:
            print(f"[agent] Reconnection attempt failed: {reconnect_err}")
    else:
        # For other connection errors, just log them
        print(f"[agent] General connection error: {error_msg}")


@sio.event
def disconnect():
    print("[agent] Disconnected from backend...")
    # Clear any pending operations that might interfere with reconnection
    global AGENT_STATE
    AGENT_STATE["pending_operations"] = []


def send_alert(alert_type: str, severity: str, message: str, details: Dict[str, Any] = None):
    """Helper to send alerts to the backend."""
    alert_payload = {
        "agentId": AGENT_ID,
        "events": [{
            "alertType": alert_type,
            "severity": severity,
            "type": alert_type,
            "message": message,
            "details": details or {},
            "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat().replace("+00:00", "Z")
        }]
    }
    safe_emit("endpoint-agent:alert", alert_payload)


def execute_command(command, params, timestamp):
    print(f"[agent] Received command: {command} with params: {params} at {timestamp or 'now'}")
    if command == "refresh":
        print("[agent] Executing refresh command - pushing telemetry immediately")
        try:
            send_telemetry()
            send_alerts()
        except Exception as e:
            logging.warning(f"[agent] Error during refresh: {e}")
    elif command == "restart":
        print("[agent] Executing restart command - restarting telemetry collection")
        try:
            send_telemetry()
            send_alerts()
        except Exception as e:
            logging.warning(f"[agent] Error during restart: {e}")
    elif command == "stop":
        print("[agent] Executing stop command - telemetry will continue but agent acknowledges stop request")
    elif command == "block_usb":
        AGENT_STATE["usb_blocked"] = True
        success = block_usb_devices()
        if success:
            send_alert("USB_BLOCKING_ENABLED", "CRITICAL", "USB device blocking has been enabled by administrator")
        else:
            send_alert("USB_BLOCKING_FAILED", "WARNING", "USB blocking command executed but may require administrator privileges")
        print("[agent] USB blocking enabled")
    elif command == "unblock_usb":
        AGENT_STATE["usb_blocked"] = False
        success = unblock_usb_devices()
        if success:
            send_alert("USB_BLOCKING_DISABLED", "INFO", "USB device blocking has been disabled by administrator")
        else:
            send_alert("USB_UNBLOCKING_FAILED", "WARNING", "USB unblocking command executed but may require administrator privileges")
        print("[agent] USB blocking disabled")
    elif command == "block_network":
        interface = params.get("interface", "")
        if interface:
            AGENT_STATE["network_blocked"][interface] = True
            try:
                if SYSTEM == "windows":
                    run_powershell(f'Disable-NetAdapter -Name "{interface}" -Confirm:$false')
                elif SYSTEM == "linux":
                    run_cmd(["sudo", "ifdown", interface])
                elif SYSTEM == "darwin":
                    run_cmd(["/sbin/ifconfig", interface, "down"])
                send_alert("NETWORK_BLOCKED", "CRITICAL", f"Network interface {interface} has been blocked", {"interface": interface})
            except Exception as e:
                logging.error(f"[agent] Failed to block network interface {interface}: {e}")
    elif command == "unblock_network":
        interface = params.get("interface", "")
        if interface:
            AGENT_STATE["network_blocked"].pop(interface, None)
            try:
                if SYSTEM == "windows":
                    run_powershell(f'Enable-NetAdapter -Name "{interface}" -Confirm:$false')
                elif SYSTEM == "linux":
                    run_cmd(["sudo", "ifup", interface])
                elif SYSTEM == "darwin":
                    run_cmd(["/sbin/ifconfig", interface, "up"])
                send_alert("NETWORK_UNBLOCKED", "INFO", f"Network interface {interface} has been unblocked", {"interface": interface})
            except Exception as e:
                logging.error(f"[agent] Failed to unblock network interface {interface}: {e}")
    elif command == "block_user":
        username = params.get("username", "")
        if username:
            AGENT_STATE["users_blocked"].add(username)
            try:
                if SYSTEM == "windows":
                    run_powershell(f'Disable-LocalUser -Name "{username}"')
                elif SYSTEM == "linux":
                    run_cmd(["sudo", "usermod", "-L", username])
                elif SYSTEM == "darwin":
                    run_cmd(["sudo", "dscl", ".", "-create", f"/Users/{username}", "UserShell", "/usr/bin/false"])
                send_alert("USER_BLOCKED", "CRITICAL", f"User {username} has been blocked", {"username": username})
            except Exception as e:
                logging.error(f"[agent] Failed to block user {username}: {e}")
    elif command == "unblock_user":
        username = params.get("username", "")
        if username:
            AGENT_STATE["users_blocked"].discard(username)
            try:
                if SYSTEM == "windows":
                    run_powershell(f'Enable-LocalUser -Name "{username}"')
                elif SYSTEM == "linux":
                    run_cmd(["sudo", "usermod", "-U", username])
                elif SYSTEM == "darwin":
                    run_cmd(["sudo", "dscl", ".", "-create", f"/Users/{username}", "UserShell", "/bin/bash"])
                send_alert("USER_UNBLOCKED", "INFO", f"User {username} has been unblocked", {"username": username})
            except Exception as e:
                logging.error(f"[agent] Failed to unblock user {username}: {e}")
    elif command == "terminate_process":
        pid = params.get("pid")
        process_name = params.get("process_name", "")
        try:
            if pid:
                if SYSTEM == "windows":
                    run_powershell(f'Stop-Process -Id {pid} -Force')
                else:
                    run_cmd(["kill", "-9", str(pid)])
                send_alert("PROCESS_TERMINATED", "WARNING", f"Process {pid} has been terminated", {"pid": pid})
            elif process_name:
                if SYSTEM == "windows":
                    run_powershell(f'Stop-Process -Name "{process_name}" -Force')
                else:
                    run_cmd(["pkill", "-9", process_name])
                send_alert("PROCESS_TERMINATED", "WARNING", f"Process {process_name} has been terminated", {"process_name": process_name})
        except Exception as e:
            logging.error(f"[agent] Failed to terminate process: {e}")
    elif command == "update_config":
        config = params.get("config", {})
        if config:
            if "telemetry_interval" in config:
                global TELEMETRY_INTERVAL
                TELEMETRY_INTERVAL = int(config["telemetry_interval"])
            send_alert("CONFIG_UPDATED", "INFO", "Agent configuration has been updated", {"config": config})
    else:
        print(f"[agent] Unknown command: {command}")


@sio.on("endpoint-protector:command")
def handle_command(data):
    try:
        command = data.get("command", "").lower() if isinstance(data, dict) else str(data).lower()
        params = data.get("params", {}) if isinstance(data, dict) else {}
        timestamp = data.get("timestamp") if isinstance(data, dict) else None
        
        # Log received command for debugging
        logging.info(f"[agent] Received command: {command} with params: {params}")
        
        # Execute command in separate thread with error handling
        def safe_execute():
            try:
                execute_command(command, params, timestamp)
            except Exception as e:
                logging.error(f"[agent] Command execution failed: {e}")
                # Send error alert instead of disconnecting
                send_alert("COMMAND_EXECUTION_FAILED", "WARNING", 
                         f"Failed to execute command {command}", 
                         {"error": str(e), "command": command})
        
        threading.Thread(target=safe_execute, daemon=True).start()
        
    except Exception as e:
        logging.error(f"[agent] Command handling error: {e}")
        # Don't crash the agent - just log the error
        send_alert("COMMAND_HANDLING_FAILED", "WARNING", 
                  f"Failed to process command", 
                  {"error": str(e), "raw_data": str(data)[:100]})


def periodic_telemetry_thread():
    import time
    while True:
        try:
            send_telemetry()
            send_alerts()
        except Exception as e:
            print("[agent] Telemetry send error:", e)
        time.sleep(TELEMETRY_INTERVAL)


def heartbeat_thread():
    import time
    while True:
        safe_emit("endpoint-agent:heartbeat", {"agentId": AGENT_ID, "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat().replace("+00:00", "Z")})
        time.sleep(20)


def send_telemetry():
    try:
        def clamp_percent(value):
            try:
                numeric = float(value)
            except (TypeError, ValueError):
                numeric = 0.0
            return max(0.0, min(100.0, numeric))

        # Gather full telemetry and convert to JS agent shape
        system_info = collect_identifiers()
        os_info = collect_os_info()
        network_info = collect_network()
        security_posture = collect_security_posture()
        installed_apps = collect_installed_apps()
        security_tools = collect_security_tools(installed_apps)
        process_summary = collect_process_summary()
        user_info = collect_user_info()
        disk_info = collect_disk_usage()
        endpoint_protection = collect_endpoint_protection_state()
        compliance = collect_compliance(os_info, security_posture)
        # Format processes to match frontend expectations
        formatted_processes = []
        top_cpu = process_summary.get("top_cpu", [])
        for proc in top_cpu[:10]:  # Top 10 processes
            # Get CPU percentage - prefer cpu_pct, fallback to 0
            cpu_pct = proc.get("cpu_pct", 0) or 0
            # Ensure it's a valid percentage (not cumulative time)
            if cpu_pct > 100:
                cpu_pct = 0  # If it's cumulative time, reset to 0
            
            formatted_proc = {
                "pid": proc.get("pid") or proc.get("Id"),
                "name": proc.get("name") or proc.get("ProcessName") or proc.get("comm", "Unknown"),
                "cpu": clamp_percent(cpu_pct),
                "memoryMB": 0.0
            }
            
            # Get memory - prefer mem_pct, fallback to working_set
            if "mem_pct" in proc and proc["mem_pct"]:
                # mem_pct is already a percentage, convert to MB estimate
                if psutil_lib:
                    try:
                        mem_stats = psutil_lib.virtual_memory()
                        total_mb = mem_stats.total / (1024 * 1024)
                        formatted_proc["memoryMB"] = round((proc["mem_pct"] / 100.0) * total_mb, 2)
                    except Exception:
                        formatted_proc["memoryMB"] = round(proc["mem_pct"], 2)
                else:
                    formatted_proc["memoryMB"] = round(proc["mem_pct"], 2)
            elif "working_set" in proc and isinstance(proc.get("working_set"), (int, float)):
                formatted_proc["memoryMB"] = round(proc["working_set"] / (1024 * 1024), 2)
            
            # Check if process is suspicious (simple heuristic - can be enhanced)
            proc_name = formatted_proc["name"].lower()
            suspicious_names = ["mimikatz", "netcat", "hydra", "powershell.exe", "cmd.exe", "nc", "nmap"]
            formatted_proc["suspicious"] = any(name in proc_name for name in suspicious_names)
            formatted_processes.append(formatted_proc)
        
        # Format network interfaces to match frontend expectations
        formatted_interfaces = []
        for iface in network_info.get("interfaces", []):
            addresses = []
            if iface.get("ipv4"):
                addresses.append(iface["ipv4"])
            if iface.get("ipv6"):
                addresses.append(iface["ipv6"])
            formatted_interfaces.append({
                "name": iface.get("name", "Unknown"),
                "addresses": addresses
            })
        
        # Calculate CPU usage (prefer overall system utilization)
        cpu_usage = 0.0
        try:
            if psutil_lib:
                cpu_usage = psutil_lib.cpu_percent(interval=0.2)
            else:
                import psutil
                cpu_usage = psutil.cpu_percent(interval=0.2)
        except Exception:
            # Fallback: sum top processes (not ideal but better than nothing)
            if top_cpu:
                total_cpu = sum(float(p.get("cpu_pct", 0) or 0) for p in top_cpu[:5])
                cpu_usage = min(total_cpu, 100.0)  # Cap at 100%
        cpu_usage = clamp_percent(cpu_usage)

        def resolve_primary_ip():
            """Resolve the primary LOCAL IP address (not public/external)."""
            ip_address = None
            
            # Method 1: Use psutil to get the IP of the interface used for default route
            if psutil_lib:
                try:
                    addrs = psutil_lib.net_if_addrs()
                    stats = psutil_lib.net_if_stats()
                    
                    # Find the interface with the most traffic (likely the primary one)
                    best_iface = None
                    max_bytes = 0
                    try:
                        net_io = psutil_lib.net_io_counters(pernic=True)
                        for iface_name, io_stats in net_io.items():
                            # Skip loopback, virtual, and tunnel interfaces
                            if any(skip in iface_name.lower() for skip in ["loopback", "lo", "virtual", "tunnel", "vpn", "tun", "tap"]):
                                continue
                            total_bytes = io_stats.bytes_sent + io_stats.bytes_recv
                            if total_bytes > max_bytes:
                                max_bytes = total_bytes
                                best_iface = iface_name
                    except Exception:
                        pass
                    
                    # Get IP from the best interface
                    if best_iface and best_iface in addrs:
                        for addr in addrs[best_iface]:
                            if addr.family == socket.AF_INET:
                                addr_ip = addr.address
                                if addr_ip != "127.0.0.1" and not addr_ip.startswith("169.254"):
                                    ip_address = addr_ip
                                    break
                    
                    # If no best interface found, iterate through all interfaces
                    if not ip_address:
                        for iface_name, iface_addrs in addrs.items():
                            # Skip loopback and virtual interfaces
                            if any(skip in iface_name.lower() for skip in ["loopback", "lo", "virtual", "tunnel", "vpn"]):
                                continue
                            # Check interface status
                            if iface_name in stats and not stats[iface_name].isup:
                                continue
                            for addr in iface_addrs:
                                if addr.family == socket.AF_INET:
                                    addr_ip = addr.address
                                    # Skip localhost and link-local addresses
                                    if addr_ip != "127.0.0.1" and not addr_ip.startswith("169.254"):
                                        ip_address = addr_ip
                                        break
                            if ip_address:
                                break
                except Exception as e:
                    logging.debug(f"[agent] Error getting IP from psutil: {e}")
            
            # Method 2: Socket connection method (fallback)
            if not ip_address:
                try:
                    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    s.connect(("8.8.8.8", 80))
                    ip_address = s.getsockname()[0]
                    s.close()
                except Exception:
                    pass
            
            # Method 3: Use interface list from network_info
            if not ip_address:
                for iface in network_info.get("interfaces", []):
                    if iface.get("ipv4") and iface["ipv4"] != "127.0.0.1" and not iface["ipv4"].startswith("169.254"):
                        ip_address = iface["ipv4"]
                        break
            
            # DO NOT use external_ip as fallback - that's the public IP
            return ip_address or "0.0.0.0"

        primary_ip = resolve_primary_ip()
        
        payload = {
            "agentId": AGENT_ID,
            "telemetry": {
                "cpu": {
                    "usage": cpu_usage,
                    "loadAverage": [],
                    "cores": system_info.get("cpu", {}).get("cores", 1),
                    "model": system_info.get("cpu", {}).get("model", "Unknown CPU")
                },
                "memory": {
                    "total": system_info.get("memory", {}).get("total_bytes"),
                    "used": None,  # Will be computed below
                    "free": None,  # Will be computed below
                    "utilization": 0  # Will be calculated below
                },
                "network": {
                    "interfaces": formatted_interfaces,
                    "hostname": socket.gethostname(),
                    "external_ip": network_info.get("external_ip"),
                    "primaryIp": primary_ip,
                    "dns_servers": network_info.get("dns_servers", []),
                    "network_traffic": network_info.get("network_traffic", {}),
                    "connection_history": network_info.get("connection_history", []),
                    "firewall_status": network_info.get("firewall_status", False)
                },
                "disk": {
                    "tempDirFree": disk_info[0] if disk_info else {"total": 0, "free": 0}
                },
                "processes": formatted_processes,
                "integrity": {
                    "alerts": sum(1 for p in formatted_processes if p.get("suspicious", False))
                },
                "status": "STABLE" if cpu_usage < 85 else "DEGRADED",
                "system": system_info,
                "os": os_info,
                "security_posture": security_posture,
                "apps": installed_apps,
                "security_tools": security_tools,
                "users": user_info,
                "endpoint_protection": endpoint_protection,
                "compliance": compliance,
                "system_uptime_seconds": os_info.get("uptime_seconds"),
                "file_changes_history": list(AGENT_STATE["file_changes_history"])[-10:],
                "windows_events": list(AGENT_STATE["windows_events"])[-20:] if SYSTEM == "windows" else [],
                # Use timezone-aware UTC timestamp with trailing Z
                "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat().replace("+00:00", "Z")
            }
        }
        # Compute memory utilization
        mem = payload["telemetry"]["memory"]
        try:
            import psutil
            mem_stats = psutil.virtual_memory()
            mem["total"] = int(mem_stats.total)
            mem["used"] = int(mem_stats.used)
            mem["free"] = int(mem_stats.available)
            mem["utilization"] = int(mem_stats.percent)
        except Exception:
            # Fallback: use system_info memory if available
            if mem["total"]:
                # Estimate used as 80% if we can't get actual usage
                mem["used"] = int(mem["total"] * 0.8) if mem["used"] is None else mem["used"]
                mem["free"] = int(mem["total"] - mem["used"]) if mem["used"] else None
                mem["utilization"] = int((mem["used"] / mem["total"]) * 100) if mem["total"] and mem["used"] else 0

        mem["utilization"] = int(clamp_percent(mem["utilization"]))

        if primary_ip:
            payload["ipAddress"] = primary_ip
        
        safe_emit("endpoint-agent:telemetry", payload)
    except Exception as exc:
        print("[agent] send_telemetry error:", exc)


def send_alerts():
    # Pick up and emit new file/usb alerts
    alerts = agent_alerts_extension()
    file_alerts = alerts.get("file_alerts", [])
    usb_alerts = alerts.get("usb_alerts", [])
    
    # Format alerts to match frontend expectations
    formatted_alerts = []
    for alert in file_alerts:
        formatted_alerts.append({
            "alertType": alert.get("alertType", "FILE_MODIFIED"),
            "severity": "MEDIUM",
            "type": alert.get("alertType", "FILE_MODIFIED"),
            "message": f"File {alert.get('alertType', '').replace('_', ' ').lower()}: {alert.get('file', 'Unknown')}",
            "details": {"file": alert.get("file")},
            "timestamp": alert.get("timestamp", datetime.datetime.now(datetime.timezone.utc).isoformat().replace("+00:00", "Z"))
        })
    
    for alert in usb_alerts:
        details = alert.get("details", {})
        if isinstance(details, dict):
            vendor = details.get("vendor", "")
            product = details.get("product", "")
            message = f"USB device {'connected' if alert.get('alertType') == 'USB_CONNECTED' else 'disconnected'}"
            if vendor or product:
                message += f": {vendor} {product}".strip()
        else:
            message = f"USB device {'connected' if alert.get('alertType') == 'USB_CONNECTED' else 'disconnected'}"
        
        formatted_alerts.append({
            "alertType": alert.get("alertType", "USB_CONNECTED"),
            "severity": "INFO",
            "type": alert.get("alertType", "USB_CONNECTED"),
            "message": message,
            "details": details if isinstance(details, dict) else {},
            "timestamp": alert.get("timestamp", datetime.datetime.now(datetime.timezone.utc).isoformat().replace("+00:00", "Z"))
        })
    
    if formatted_alerts:
        payload = {"agentId": AGENT_ID, "events": formatted_alerts}
        safe_emit("endpoint-agent:alert", payload)


# ---------------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------------

def run_cmd(cmd: List[str], timeout: int = 8) -> str:
    try:
        completed = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, check=False)
        if completed.returncode != 0:
            return ""
        return completed.stdout.strip()
    except Exception:
        return ""


def run_powershell(command: str, timeout: int = 10) -> str:
    if SYSTEM != "windows":
        return ""
    try:
        completed = subprocess.run(
            ["powershell", "-NoProfile", "-Command", command],
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
        if completed.returncode != 0:
            return ""
        return completed.stdout.strip()
    except Exception:
        return ""


def block_usb_devices() -> bool:
    try:
        if SYSTEM == "windows":
            run_powershell('Set-ItemProperty -Path "HKLM:\\SYSTEM\\CurrentControlSet\\Services\\USBSTOR" -Name "Start" -Value 4 -Type DWord')
            run_powershell('$usb = Get-PnpDevice | Where-Object {$_.InstanceId -like "*USBSTOR*"}; $usb | Disable-PnpDevice -Confirm:$false')
        elif SYSTEM == "linux":
            if psutil_lib:
                for part in psutil_lib.disk_partitions():
                    if 'removable' in getattr(part, "opts", "").lower():
                        run_cmd(["sudo", "umount", part.mountpoint])
            run_cmd(["sudo", "modprobe", "-r", "usb_storage"])
        elif SYSTEM == "darwin":
            run_cmd(["diskutil", "list"])
        try:
            current_devices = alert_collector._usb_platform_impl() if alert_collector else set()
            for device in current_devices:
                device_dict = dict(device) if isinstance(device, (set, frozenset)) else {"device": str(device)}
                alert_collector._block_usb_device(device_dict)
        except Exception:
            pass
        return True
    except Exception as e:
        logging.error(f"[agent] Failed to block USB devices: {e}")
        return False


def unblock_usb_devices() -> bool:
    try:
        if SYSTEM == "windows":
            run_powershell('Set-ItemProperty -Path "HKLM:\\SYSTEM\\CurrentControlSet\\Services\\USBSTOR" -Name "Start" -Value 3 -Type DWord')
            run_powershell('$usb = Get-PnpDevice | Where-Object {$_.InstanceId -like "*USBSTOR*"}; $usb | Enable-PnpDevice -Confirm:$false')
        elif SYSTEM == "linux":
            run_cmd(["sudo", "modprobe", "usb_storage"])
        elif SYSTEM == "darwin":
            run_cmd(["diskutil", "list"])
        return True
    except Exception as e:
        logging.error(f"[agent] Failed to unblock USB devices: {e}")
        return False


def fetch_external_ip() -> Optional[str]:
    for endpoint in ("https://ifconfig.me/ip", "https://api.ipify.org", "https://checkip.amazonaws.com"):
        try:
            return urlrequest.urlopen(endpoint, timeout=4).read().decode().strip()
        except Exception:
            continue
    if shutil.which("curl"):
        return run_cmd(["curl", "-s", "https://ifconfig.me"])
    return None


def parse_timestamp(value: Any) -> Optional[datetime.datetime]:
    if not value:
        return None
    if isinstance(value, (int, float)):
        # timezone-aware UTC
        try:
            return datetime.datetime.fromtimestamp(float(value), datetime.timezone.utc)
        except Exception:
            return None
    if isinstance(value, str):
        try:
            cleaned = value.rstrip("Z")
            dt = datetime.datetime.fromisoformat(cleaned)
            # If dt has no tzinfo, treat as UTC
            if dt.tzinfo is None:
                return dt.replace(tzinfo=datetime.timezone.utc)
            return dt
        except Exception:
            return None
    return None


# ---------------------------------------------------------------------------
# System & Hardware
# ---------------------------------------------------------------------------

def collect_identifiers() -> Dict[str, Any]:
    info: Dict[str, Any] = {
        "hostname": socket.gethostname(),
        "serial_number": None,
        "hardware_uuid": None,
        "model_identifier": None,
        "cpu": {"model": None, "cores": None},
        "memory": {"total_bytes": None},
        "storage_overview": None,
        "gpu": None,
        "motherboard": None,
        "bios": None,
    }
    if SYSTEM == "darwin":
        ioreg = run_cmd(["/usr/sbin/ioreg", "-rd1", "-c", "IOPlatformExpertDevice"])
        for line in ioreg.splitlines():
            if "IOPlatformSerialNumber" in line:
                info["serial_number"] = line.split("=")[-1].strip().strip('"')
            if "IOPlatformUUID" in line:
                info["hardware_uuid"] = line.split("=")[-1].strip().strip('"')
        info["model_identifier"] = run_cmd(["/usr/sbin/sysctl", "-n", "hw.model"]) or None
        cpu_model = run_cmd(["/usr/sbin/sysctl", "-n", "machdep.cpu.brand_string"]) or info["model_identifier"]
        cpu_cores = run_cmd(["/usr/sbin/sysctl", "-n", "hw.logicalcpu"])
        ram = run_cmd(["/usr/sbin/sysctl", "-n", "hw.memsize"])
        info["cpu"]["model"] = cpu_model
        info["cpu"]["cores"] = int(cpu_cores) if cpu_cores.isdigit() else None
        info["memory"]["total_bytes"] = int(ram) if ram.isdigit() else None
    elif SYSTEM == "linux":
        for path, key in [
            ("/sys/class/dmi/id/product_serial", "serial_number"),
            ("/sys/class/dmi/id/product_uuid", "hardware_uuid"),
            ("/sys/class/dmi/id/product_name", "model_identifier"),
        ]:
            path_obj = pathlib.Path(path)
            if path_obj.exists():
                info[key] = path_obj.read_text().strip()
        cpuinfo = run_cmd(["/bin/cat", "/proc/cpuinfo"])
        for line in cpuinfo.splitlines():
            if line.lower().startswith("model name"):
                info["cpu"]["model"] = line.split(":", 1)[1].strip()
                break
        cores = run_cmd(["/usr/bin/nproc"])
        info["cpu"]["cores"] = int(cores) if cores.isdigit() else None
        meminfo_path = pathlib.Path("/proc/meminfo")
        if meminfo_path.exists():
            for line in meminfo_path.read_text().splitlines():
                if line.startswith("MemTotal"):
                    kb = line.split()[1]
                    if kb.isdigit():
                        info["memory"]["total_bytes"] = int(kb) * 1024
                    break
    elif SYSTEM == "windows":
        info["serial_number"] = run_powershell("(Get-WmiObject Win32_BIOS).SerialNumber") or None
        info["hardware_uuid"] = run_powershell("(Get-WmiObject Win32_ComputerSystemProduct).UUID") or None
        info["model_identifier"] = run_powershell("(Get-WmiObject Win32_ComputerSystem).Model") or None
        info["cpu"]["model"] = run_powershell("(Get-WmiObject Win32_Processor).Name") or None
        cores = run_powershell("(Get-WmiObject Win32_ComputerSystem).NumberOfLogicalProcessors")
        info["cpu"]["cores"] = int(cores) if cores and cores.isdigit() else None
        ram = run_powershell("(Get-WmiObject Win32_ComputerSystem).TotalPhysicalMemory")
        info["memory"]["total_bytes"] = int(ram) if ram and ram.isdigit() else None
        
        # GPU information
        try:
            gpu_info = run_powershell("Get-WmiObject Win32_VideoController | Select-Object Name,AdapterRAM,CurrentHorizontalResolution,CurrentVerticalResolution | ConvertTo-Json")
            if gpu_info:
                gpu_data = json.loads(gpu_info)
                if isinstance(gpu_data, dict):
                    gpu_data = [gpu_data]
                if gpu_data:
                    gpu = gpu_data[0]
                    info["gpu"] = {
                        "model": gpu.get("Name"),
                        "memory_bytes": gpu.get("AdapterRAM"),
                        "resolution": f"{gpu.get('CurrentHorizontalResolution')}x{gpu.get('CurrentVerticalResolution')}" if gpu.get("CurrentHorizontalResolution") else None
                    }
        except Exception:
            pass
        
        # Motherboard information
        try:
            mb_info = run_powershell("Get-WmiObject Win32_BaseBoard | Select-Object Manufacturer,Product,Version | ConvertTo-Json")
            if mb_info:
                mb_data = json.loads(mb_info)
                if isinstance(mb_data, dict):
                    info["motherboard"] = {
                        "manufacturer": mb_data.get("Manufacturer"),
                        "product": mb_data.get("Product"),
                        "version": mb_data.get("Version")
                    }
        except Exception:
            pass
        
        # BIOS information
        try:
            bios_info = run_powershell("Get-WmiObject Win32_BIOS | Select-Object Manufacturer,Version,ReleaseDate | ConvertTo-Json")
            if bios_info:
                bios_data = json.loads(bios_info)
                if isinstance(bios_data, dict):
                    info["bios"] = {
                        "manufacturer": bios_data.get("Manufacturer"),
                        "version": bios_data.get("Version"),
                        "release_date": bios_data.get("ReleaseDate")
                    }
        except Exception:
            pass
    try:
        anchor = pathlib.Path.home().anchor or ("C:\\" if SYSTEM == "windows" else "/")
        usage = shutil.disk_usage(anchor)
        info["storage_overview"] = {
            "root_path": anchor,
            "total_bytes": usage.total,
            "used_bytes": usage.used,
            "free_bytes": usage.free,
        }
    except Exception:
        info["storage_overview"] = None
    return info


# ---------------------------------------------------------------------------
# OS & Patch info
# ---------------------------------------------------------------------------

def collect_installed_patches(limit: int = 5) -> List[str]:
    patches: List[str] = []
    if SYSTEM == "darwin":
        history = run_cmd(["/usr/sbin/softwareupdate", "--history"])
        if history:
            for line in history.splitlines():
                if "\t" in line:
                    patches.append(line.split("\t")[0].strip())
        patches = patches[-limit:]
    elif SYSTEM == "linux":
        apt_history = pathlib.Path("/var/log/apt/history.log")
        if apt_history.exists():
            for line in reversed(apt_history.read_text().splitlines()):
                if line.startswith("Start-Date"):
                    patches.append(line.strip())
                if len(patches) >= limit:
                    break
        elif pathlib.Path("/var/log/yum.log").exists():
            for line in reversed(pathlib.Path("/var/log/yum.log").read_text().splitlines()):
                if "Updated" in line:
                    patches.append(line.strip())
                if len(patches) >= limit:
                    break
    elif SYSTEM == "windows":
        hotfix = run_powershell(
            f"Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First {limit} HotFixID, InstalledOn | ConvertTo-Json"
        )
        if hotfix:
            try:
                data = json.loads(hotfix)
                if isinstance(data, dict):
                    data = [data]
                for entry in data:
                    patches.append(f"{entry.get('HotFixID')} ({entry.get('InstalledOn')})")
            except Exception:
                pass
    return patches


def collect_os_info() -> Dict[str, Any]:
    info: Dict[str, Any] = {
        "name": None,
        "version": None,
        "build": None,
        "kernel_version": platform.release(),
        "last_security_update": None,
        "installed_patches": [],
        "uptime_seconds": None,
    }
    if SYSTEM == "darwin":
        sw_vers = run_cmd(["/usr/bin/sw_vers"])
        for line in sw_vers.splitlines():
            if "ProductName" in line:
                info["name"] = line.split(":")[-1].strip()
            if "ProductVersion" in line:
                info["version"] = line.split(":")[-1].strip()
            if "BuildVersion" in line:
                info["build"] = line.split(":")[-1].strip()
        info["last_security_update"] = run_cmd([
            "/usr/bin/defaults",
            "read",
            "/Library/Preferences/com.apple.SoftwareUpdate",
            "LastFullSuccessfulDate",
        ]) or None
    elif SYSTEM == "linux":
        release_path = pathlib.Path("/etc/os-release")
        os_release = {}
        if release_path.exists():
            for line in release_path.read_text().splitlines():
                if "=" in line:
                    key, value = line.split("=", 1)
                    os_release[key] = value.strip().strip('"')
        info["name"] = os_release.get("PRETTY_NAME") or os_release.get("NAME")
        info["version"] = os_release.get("VERSION_ID")
        info["build"] = os_release.get("BUILD_ID")
        stamp = pathlib.Path("/var/lib/apt/periodic/update-success-stamp")
        if stamp.exists():
            info["last_security_update"] = datetime.datetime.fromtimestamp(stamp.stat().st_mtime, datetime.timezone.utc).isoformat().replace("+00:00", "Z")
    elif SYSTEM == "windows":
        info["name"] = run_powershell("(Get-WmiObject Win32_OperatingSystem).Caption")
        info["version"] = run_powershell("(Get-WmiObject Win32_OperatingSystem).Version")
        info["build"] = run_powershell("(Get-WmiObject Win32_OperatingSystem).BuildNumber")
        info["kernel_version"] = run_powershell("[Environment]::OSVersion.VersionString") or info["kernel_version"]
    
    # Get system uptime
    try:
        if psutil_lib:
            boot_time = psutil_lib.boot_time()
            uptime_seconds = int(time.time() - boot_time)
            info["uptime_seconds"] = uptime_seconds
        elif SYSTEM == "windows":
            uptime_str = run_powershell("(Get-CimInstance Win32_OperatingSystem).LastBootUpTime")
            if uptime_str:
                # Parse WMI datetime format
                try:
                    from datetime import datetime
                    boot_time = datetime.strptime(uptime_str.split(".")[0], "%Y%m%d%H%M%S")
                    uptime_seconds = int((datetime.now() - boot_time).total_seconds())
                    info["uptime_seconds"] = uptime_seconds
                except Exception:
                    pass
        elif SYSTEM == "linux":
            uptime_str = run_cmd(["/bin/cat", "/proc/uptime"])
            if uptime_str:
                try:
                    info["uptime_seconds"] = int(float(uptime_str.split()[0]))
                except Exception:
                    pass
        elif SYSTEM == "darwin":
            uptime_str = run_cmd(["/usr/sbin/sysctl", "-n", "kern.boottime"])
            if uptime_str:
                try:
                    # Parse boottime format
                    boot_timestamp = int(uptime_str.split()[3].strip(","))
                    uptime_seconds = int(time.time() - boot_timestamp)
                    info["uptime_seconds"] = uptime_seconds
                except Exception:
                    pass
    except Exception:
        pass
    
    info["installed_patches"] = collect_installed_patches()
    return info


# ---------------------------------------------------------------------------
# Network Collection
# ---------------------------------------------------------------------------

def collect_network() -> Dict[str, Any]:
    interfaces: List[Dict[str, Any]] = []
    dns_servers: Set[str] = set()
    if SYSTEM == "darwin":
        hw_ports = run_cmd(["/usr/sbin/networksetup", "-listallhardwareports"])
        current: Dict[str, Any] = {}
        for line in hw_ports.splitlines():
            if line.startswith("Hardware Port"):
                current = {"hardware_port": line.split(":")[1].strip()}
            elif line.startswith("Device") and current:
                iface = line.split(":")[1].strip()
                entry = {
                    "name": iface,
                    "hardware_port": current.get("hardware_port"),
                    "mac": None,
                    "ipv4": run_cmd(["/usr/sbin/ipconfig", "getifaddr", iface]) or None,
                    "ipv6": run_cmd(["/usr/sbin/ipconfig", "getv6ifaddr", iface]) or None,
                    "ssid": None,
                    "state": None,
                }
                ifconfig = run_cmd(["/sbin/ifconfig", iface])
                for ifline in ifconfig.splitlines():
                    if "ether" in ifline:
                        entry["mac"] = ifline.split()[1]
                    if "status:" in ifline:
                        entry["state"] = ifline.split(":")[1].strip()
                if entry["hardware_port"] and "wi-fi" in entry["hardware_port"].lower():
                    airport = run_cmd(["/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport", "-I"])
                    for ssid_line in airport.splitlines():
                        if " SSID:" in ssid_line:
                            entry["ssid"] = ssid_line.split(":")[1].strip()
                interfaces.append(entry)
        dns_info = run_cmd(["/usr/sbin/scutil", "--dns"])
        for dnsline in dns_info.splitlines():
            if "nameserver" in dnsline:
                dns_servers.add(dnsline.split(":")[1].strip())
    elif SYSTEM == "linux":
        ip_json = run_cmd(["/usr/sbin/ip", "-json", "addr"])
        if ip_json:
            try:
                data = json.loads(ip_json)
                for iface in data:
                    entry = {
                        "name": iface.get("ifname"),
                        "mac": iface.get("address"),
                        "state": iface.get("operstate"),
                        "ipv4": None,
                        "ipv6": None,
                        "ssid": None,
                    }
                    for addr in iface.get("addr_info", []):
                        if addr.get("family") == "inet":
                            entry["ipv4"] = addr.get("local")
                        elif addr.get("family") == "inet6":
                            entry["ipv6"] = addr.get("local")
                    interfaces.append(entry)
            except Exception:
                pass
        resolv = pathlib.Path("/etc/resolv.conf")
        if resolv.exists():
            for line in resolv.read_text().splitlines():
                if line.startswith("nameserver"):
                    dns_servers.add(line.split()[1])
    elif SYSTEM == "windows":
        net_info = run_powershell(
            "Get-NetIPConfiguration | Select-Object InterfaceAlias,IPv4Address,IPv6Address,DNSServer,NetAdapter | ConvertTo-Json"
        )
        if net_info:
            try:
                data = json.loads(net_info)
                if isinstance(data, dict):
                    data = [data]
                for iface in data:
                    entry = {
                        "name": iface.get("InterfaceAlias"),
                        "mac": iface.get("NetAdapter", {}).get("MacAddress"),
                        "state": iface.get("NetAdapter", {}).get("Status"),
                        "ipv4": iface.get("IPv4Address", [{}])[0].get("IPv4Address"),
                        "ipv6": iface.get("IPv6Address", [{}])[0].get("IPv6Address"),
                        "ssid": None,
                    }
                    interfaces.append(entry)
                    for dns in iface.get("DNSServer", []):
                        if isinstance(dns, dict):
                            dns_servers.update(dns.get("ServerAddresses", []))
            except Exception:
                pass
    # Collect network traffic statistics
    network_traffic = {}
    connection_history = list(AGENT_STATE["network_connections_history"])[-20:]  # Last 20 connections
    firewall_status = False
    
    if psutil_lib:
        try:
            net_io = psutil_lib.net_io_counters(pernic=True)
            for iface_name, stats in net_io.items():
                # Skip loopback interfaces
                if "lo" in iface_name.lower() or "loopback" in iface_name.lower():
                    continue
                network_traffic[iface_name] = {
                    "bytes_sent": stats.bytes_sent,
                    "bytes_recv": stats.bytes_recv,
                    "packets_sent": stats.packets_sent,
                    "packets_recv": stats.packets_recv,
                    "errin": stats.errin,
                    "errout": stats.errout,
                    "dropin": stats.dropin,
                    "dropout": stats.dropout
                }
        except Exception as e:
            logging.warning(f"[agent] Error collecting network traffic: {e}")
    
    # Get firewall status
    try:
        if SYSTEM == "windows":
            firewall = run_powershell("(Get-NetFirewallProfile | Where-Object {$_.Enabled -eq 1}).Name")
            firewall_status = bool(firewall.strip()) if firewall else False
        elif SYSTEM == "linux":
            firewall = run_cmd(["/usr/bin/systemctl", "is-active", "ufw"]) or run_cmd(["/usr/bin/systemctl", "is-active", "firewalld"])
            firewall_status = firewall == "active"
        elif SYSTEM == "darwin":
            firewall = run_cmd(["/usr/libexec/ApplicationFirewall/socketfilterfw", "--getglobalstate"])
            firewall_status = "enabled" in firewall.lower() if firewall else False
    except Exception:
        firewall_status = False
    
    return {
        "external_ip": fetch_external_ip(),
        "interfaces": interfaces,
        "dns_servers": [dns for dns in dns_servers if dns][:4],
        "network_traffic": network_traffic,
        "connection_history": connection_history,
        "firewall_status": firewall_status
    }


# ---------------------------------------------------------------------------
# Security Posture
# ---------------------------------------------------------------------------

def collect_screen_lock_settings() -> Dict[str, Any]:
    data = {"enabled": None, "timeout_seconds": None}
    if SYSTEM == "darwin":
        enabled = run_cmd(["/usr/bin/defaults", "read", "/Library/Preferences/com.apple.screensaver", "askForPassword"])
        delay = run_cmd(["/usr/bin/defaults", "read", "/Library/Preferences/com.apple.screensaver", "askForPasswordDelay"])
        data["enabled"] = enabled == "1"
        try:
            data["timeout_seconds"] = int(float(delay)) if delay else None
        except Exception:
            data["timeout_seconds"] = None
    elif SYSTEM == "linux" and shutil.which("gsettings"):
        enabled = run_cmd(["/usr/bin/gsettings", "get", "org.gnome.desktop.screensaver", "lock-enabled"])
        timeout = run_cmd(["/usr/bin/gsettings", "get", "org.gnome.desktop.session", "idle-delay"])
        data["enabled"] = enabled.strip().lower() == "true"
        try:
            data["timeout_seconds"] = int(timeout.replace("uint32", "").strip())
        except Exception:
            data["timeout_seconds"] = None
    elif SYSTEM == "windows":
        timeout = run_powershell("(Get-ItemProperty -Path 'HKCU:\\Control Panel\\Desktop').ScreenSaveTimeOut")
        if timeout and timeout.isdigit():
            data["timeout_seconds"] = int(timeout)
            data["enabled"] = data["timeout_seconds"] > 0
    return data


def detect_edr() -> List[Dict[str, Any]]:
    results: List[Dict[str, Any]] = []
    if SYSTEM == "darwin":
        vendors = {
            "CrowdStrike": ["/Applications/Falcon.app", "falcond"],
            "Carbon Black": ["/Applications/CBDefense.app", "cbagentd"],
            "SentinelOne": ["/Applications/SentinelOne.app", "SentinelAgent"],
            "Jamf Protect": ["/Applications/JamfProtect.app", "JamfProtect"],
        }
        for vendor, indicators in vendors.items():
            present = False
            version = None
            for indicator in indicators:
                if indicator.startswith("/Applications") and pathlib.Path(indicator).exists():
                    present = True
                    plist = pathlib.Path(indicator, "Contents", "Info.plist")
                    if plist.exists():
                        version = run_cmd(["/usr/bin/defaults", "read", str(plist), "CFBundleShortVersionString"]) or None
                elif run_cmd(["/usr/bin/pgrep", "-x", indicator]):
                    present = True
            if present:
                results.append({"vendor": vendor, "status": "running", "version": version})
    elif SYSTEM == "windows":
        defender = run_powershell("Get-MpComputerStatus | Select-Object AMServiceEnabled | ConvertTo-Json")
        if defender:
            results.append({"vendor": "Microsoft Defender", "status": "running"})
    elif SYSTEM == "linux":
        for path, vendor in [
            ("/opt/CrowdStrike/falconctl", "CrowdStrike"),
            ("/opt/SentinelOne/bin/sentinelctl", "SentinelOne"),
        ]:
            if pathlib.Path(path).exists():
                results.append({"vendor": vendor, "status": "running"})
    return results


def collect_security_posture() -> Dict[str, Any]:
    posture: Dict[str, Any] = {
        "firewall_enabled": None,
        "filevault_enabled": None,
        "sip_enabled": None,
        "gatekeeper_enabled": None,
        "secure_boot": None,
        "mdm_enrolled": None,
        "mdm_server": None,
        "screen_lock": collect_screen_lock_settings(),
        "edr": detect_edr(),
        "compliance_markers": {},
    }
    if SYSTEM == "darwin":
        posture["secure_boot"] = run_cmd(["/usr/bin/csrutil", "status"]) or None
    elif SYSTEM == "windows":
        posture["secure_boot"] = run_powershell("Confirm-SecureBootUEFI") or None
    if SYSTEM == "darwin":
        firewall = run_cmd(["/usr/libexec/ApplicationFirewall/socketfilterfw", "--getglobalstate"])
        filevault = run_cmd(["/usr/bin/fdesetup", "status"])
        sip = run_cmd(["/usr/bin/csrutil", "status"])
        gatekeeper = run_cmd(["/usr/sbin/spctl", "--status"])
        mdm_enrolled = run_cmd(["/usr/bin/profiles", "status", "-type", "enrollment"])
        mdm_server = run_cmd(["/usr/bin/profiles", "-C"])
        posture.update({
            "firewall_enabled": "enabled" in firewall.lower(),
            "filevault_enabled": "FileVault is On" in filevault,
            "sip_enabled": "enabled" in sip.lower(),
            "gatekeeper_enabled": "assessments enabled" in gatekeeper.lower(),
            "mdm_enrolled": "Enrolled" in mdm_enrolled,
            "mdm_server": mdm_server.splitlines()[0][:256] if mdm_server else None,
        })
        posture["compliance_markers"]["disk_encrypted"] = posture["filevault_enabled"]
    elif SYSTEM == "linux":
        firewall = run_cmd(["/usr/bin/systemctl", "is-active", "ufw"]) or run_cmd(["/usr/bin/systemctl", "is-active", "firewalld"])
        posture["firewall_enabled"] = firewall == "active"
        posture["compliance_markers"]["selinux"] = run_cmd(["/usr/sbin/getenforce"]) or None
    elif SYSTEM == "windows":
        firewall = run_powershell("(Get-NetFirewallProfile | Where-Object {$_.Enabled -eq 1}).Name")
        posture["firewall_enabled"] = bool(firewall.strip()) if firewall else False
        bitlocker = run_powershell("Get-BitLockerVolume | Select-Object MountPoint, VolumeStatus | ConvertTo-Json")
        posture["compliance_markers"]["disk_encrypted"] = "FullyEncrypted" in (bitlocker or "")
        posture["mdm_enrolled"] = bool(run_powershell("(Get-WmiObject -Namespace root\\cimv2\\mdm -Class MDM_DevDetail_Ext01)"))
    return posture


# ---------------------------------------------------------------------------
# Software & Processes
# ---------------------------------------------------------------------------

def json_from_cmd(cmd: List[str], timeout: int = 30) -> Optional[Dict[str, Any]]:
    """Run a command that outputs JSON and parse it."""
    try:
        output = run_cmd(cmd, timeout=timeout)
        if output:
            return json.loads(output)
    except Exception:
        pass
    return None


def collect_installed_apps(limit: int = 150) -> List[Dict[str, Any]]:
    apps: List[Dict[str, Any]] = []
    if SYSTEM == "darwin":
        data = json_from_cmd(["/usr/sbin/system_profiler", "SPApplicationsDataType", "-json"], timeout=45) or {}
        for app in data.get("SPApplicationsDataType", [])[:limit]:
            apps.append({"name": app.get("_name"), "version": app.get("version"), "path": app.get("path")})
    elif SYSTEM == "linux":
        dpkg = run_cmd(["/usr/bin/dpkg-query", "-W", "-f=${Package}|${Version}\n"])
        if dpkg:
            for line in dpkg.splitlines()[:limit]:
                if "|" in line:
                    name, version = line.split("|", 1)
                    apps.append({"name": name, "version": version})
        else:
            rpm = run_cmd(["/usr/bin/rpm", "-qa", "--qf", "%{NAME}|%{VERSION}\n"])
            for line in rpm.splitlines()[:limit]:
                if "|" in line:
                    name, version = line.split("|", 1)
                    apps.append({"name": name, "version": version})
    elif SYSTEM == "windows":
        installed = run_powershell("Get-ItemProperty 'HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*' | Select-Object DisplayName, DisplayVersion | ConvertTo-Json")
        if installed:
            try:
                data = json.loads(installed)
                if isinstance(data, dict):
                    data = [data]
                for entry in data[:limit]:
                    apps.append({"name": entry.get("DisplayName"), "version": entry.get("DisplayVersion")})
            except Exception:
                pass
    return apps


def collect_security_tools(apps: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    keywords = ["chrome", "firefox", "microsoft office", "defender", "crowdstrike", "sentinel", "carbon black", "jamf"]
    tools = []
    for app in apps:
        name = (app.get("name") or "").lower()
        if any(keyword in name for keyword in keywords):
            tools.append(app)
    return tools


def collect_process_summary() -> Dict[str, Any]:
    summary = {"total_processes": None, "top_cpu": [], "top_memory": []}
    
    # Use psutil for accurate CPU percentages across all platforms
    if psutil_lib:
        try:
            processes = []
            # First pass: collect all processes
            proc_list = []
            for proc in psutil_lib.process_iter(['pid', 'name']):
                try:
                    proc_list.append(proc)
                    # Baseline call: first call always returns 0.0; sets measurement window
                    proc.cpu_percent(interval=None)
                except (psutil_lib.NoSuchProcess, psutil_lib.AccessDenied, psutil_lib.ZombieProcess):
                    continue
            
            # Second pass: get CPU and memory with interval (more accurate)
            # Use a small sleep to get accurate CPU percentages
            time.sleep(0.2)
            for proc in proc_list:
                try:
                    pid = proc.info.get('pid')
                    name = (proc.info.get('name') or "Unknown")

                    # Exclude Windows idle process from top CPU list (not real consumption)
                    if SYSTEM == "windows" and (pid in {0} or name.lower() in {"system idle process", "idle"}):
                        continue

                    # Get CPU percent based on baseline window above
                    cpu_pct = float(proc.cpu_percent(interval=None) or 0.0)
                    
                    # Clamp CPU to reasonable values (per core, so can be > 100% on multi-core)
                    # But for display, we'll cap at 100% per process
                    cpu_pct = max(0.0, min(cpu_pct, 100.0))
                    
                    mem_info = proc.memory_info()
                    mem_pct = float(proc.memory_percent() or 0.0)
                    working_set = mem_info.rss if mem_info else 0
                    
                    processes.append({
                        "pid": pid,
                        "name": name,
                        "cpu_pct": cpu_pct,
                        "mem_pct": mem_pct,
                        "working_set": working_set
                    })
                except (psutil_lib.NoSuchProcess, psutil_lib.AccessDenied, psutil_lib.ZombieProcess):
                    continue
                except Exception as e:
                    logging.debug(f"[agent] Error getting process stats: {e}")
                    continue
            
            summary["total_processes"] = len(processes)
            summary["top_cpu"] = sorted(processes, key=lambda x: x["cpu_pct"], reverse=True)[:10]
            summary["top_memory"] = sorted(processes, key=lambda x: x["mem_pct"], reverse=True)[:10]
        except Exception as e:
            logging.warning(f"[agent] Error collecting processes with psutil: {e}")
            # Fallback to platform-specific methods
            if SYSTEM in {"darwin", "linux"}:
                ps_out = run_cmd(["/bin/ps", "-axo", "pid,comm,%cpu,%mem"])
                lines = ps_out.splitlines()
                summary["total_processes"] = max(len(lines) - 1, 0)
                processes = []
                for line in lines[1:]:
                    parts = line.split(None, 3)
                    if len(parts) == 4:
                        pid, name, cpu, mem = parts
                        try:
                            processes.append({
                                "pid": int(pid),
                                "name": pathlib.Path(name).name,
                                "cpu_pct": float(cpu),
                                "mem_pct": float(mem),
                            })
                        except Exception:
                            continue
                summary["top_cpu"] = sorted(processes, key=lambda x: x["cpu_pct"], reverse=True)[:5]
                summary["top_memory"] = sorted(processes, key=lambda x: x["mem_pct"], reverse=True)[:5]
            elif SYSTEM == "windows":
                count = run_powershell("(Get-Process).Count")
                summary["total_processes"] = int(count) if count and count.isdigit() else None
                mem_json = run_powershell("Get-Process | Sort-Object WorkingSet -Descending | Select-Object -First 5 Id,ProcessName,WorkingSet | ConvertTo-Json")
                if mem_json:
                    try:
                        data = json.loads(mem_json)
                        if isinstance(data, dict):
                            data = [data]
                        summary["top_memory"] = [{"pid": d.get("Id"), "name": d.get("ProcessName"), "working_set": d.get("WorkingSet")} for d in data]
                    except Exception:
                        pass
    else:
        # Fallback when psutil is not available
        if SYSTEM in {"darwin", "linux"}:
            ps_out = run_cmd(["/bin/ps", "-axo", "pid,comm,%cpu,%mem"])
            lines = ps_out.splitlines()
            summary["total_processes"] = max(len(lines) - 1, 0)
            processes = []
            for line in lines[1:]:
                parts = line.split(None, 3)
                if len(parts) == 4:
                    pid, name, cpu, mem = parts
                    try:
                        processes.append({
                            "pid": int(pid),
                            "name": pathlib.Path(name).name,
                            "cpu_pct": float(cpu),
                            "mem_pct": float(mem),
                        })
                    except Exception:
                        continue
            summary["top_cpu"] = sorted(processes, key=lambda x: x["cpu_pct"], reverse=True)[:5]
            summary["top_memory"] = sorted(processes, key=lambda x: x["mem_pct"], reverse=True)[:5]
        elif SYSTEM == "windows":
            count = run_powershell("(Get-Process).Count")
            summary["total_processes"] = int(count) if count and count.isdigit() else None
            mem_json = run_powershell("Get-Process | Sort-Object WorkingSet -Descending | Select-Object -First 5 Id,ProcessName,WorkingSet | ConvertTo-Json")
            if mem_json:
                try:
                    data = json.loads(mem_json)
                    if isinstance(data, dict):
                        data = [data]
                    summary["top_memory"] = [{"pid": d.get("Id"), "name": d.get("ProcessName"), "working_set": d.get("WorkingSet")} for d in data]
                except Exception:
                    pass
    
    return summary


# ---------------------------------------------------------------------------
# Users, Disk, Endpoint Protection
# ---------------------------------------------------------------------------

def collect_user_info() -> Dict[str, Any]:
    info = {"current_console_user": None, "logged_in_users": [], "admin_users": []}
    if SYSTEM == "darwin":
        info["current_console_user"] = run_cmd(["/usr/bin/stat", "-f", "%Su", "/dev/console"]) or None
        who = run_cmd(["/usr/bin/who"])
        info["logged_in_users"] = sorted({line.split()[0] for line in who.splitlines()}) if who else []
        admin_group = run_cmd(["/usr/sbin/dseditgroup", "-o", "read", "admin"])
        for line in admin_group.splitlines():
            if "users:" in line.lower():
                info["admin_users"] = [user.strip() for user in line.split(":")[1].split(",")]
                break
    elif SYSTEM == "linux":
        info["current_console_user"] = run_cmd(["/usr/bin/logname"]) or None
        who = run_cmd(["/usr/bin/who"])
        info["logged_in_users"] = sorted({line.split()[0] for line in who.splitlines()}) if who else []
        sudoers = run_cmd(["/usr/bin/getent", "group", "sudo"])
        if sudoers:
            info["admin_users"] = sudoers.split(":")[-1].strip().split(",")
    elif SYSTEM == "windows":
        info["current_console_user"] = run_powershell("$env:USERNAME")
        whoami = run_powershell("whoami /groups")
        if "Administrators" in (whoami or ""):
            info["admin_users"].append("Administrators")
    return info


def collect_disk_usage() -> List[Dict[str, Any]]:
    disks: List[Dict[str, Any]] = []
    if SYSTEM in {"darwin", "linux"}:
        df = run_cmd(["/bin/df", "-k"])
        for line in df.splitlines()[1:]:
            parts = line.split()
            if len(parts) >= 6:
                disks.append({
                    "filesystem": parts[0],
                    "mount": parts[-1],
                    "total_bytes": int(parts[1]) * 1024,
                    "used_bytes": int(parts[2]) * 1024,
                    "available_bytes": int(parts[3]) * 1024,
                    "usage": parts[4],
                })
    elif SYSTEM == "windows":
        drives = run_powershell("Get-PSDrive -PSProvider 'FileSystem' | Select-Object Name,Used,Free | ConvertTo-Json")
        if drives:
            try:
                data = json.loads(drives)
                if isinstance(data, dict):
                    data = [data]
                for drive in data:
                    used = drive.get("Used") or 0
                    free = drive.get("Free") or 0
                    disks.append({
                        "filesystem": drive.get("Name") + ":\\",
                        "mount": drive.get("Name") + ":\\",
                        "total_bytes": used + free,
                        "used_bytes": used,
                        "available_bytes": free,
                        "usage": None,
                    })
            except Exception:
                pass
    return disks


def collect_endpoint_protection_state() -> Dict[str, Any]:
    state: Dict[str, Any] = {}
    if SYSTEM == "darwin":
        firewall = run_cmd(["/usr/libexec/ApplicationFirewall/socketfilterfw", "--getblockall"])
        state["firewall_block_all"] = "enabled" in firewall.lower()
        state["gatekeeper"] = run_cmd(["/usr/sbin/spctl", "--status"]) or None
        vpn = run_cmd(["/usr/sbin/scutil", "--nc", "status"])
        state["vpn_state"] = vpn.splitlines()[0] if vpn else None
    elif SYSTEM == "linux":
        ufw = run_cmd(["/usr/sbin/ufw", "status"])
        state["firewall_block_all"] = "Status: active" in ufw
        vpn = run_cmd(["/usr/bin/nmcli", "connection", "show", "--active"])
        state["vpn_connections"] = vpn.splitlines()[1:6] if vpn else []
    elif SYSTEM == "windows":
        firewall_profiles = run_powershell("(Get-NetFirewallProfile | Where-Object {$_.Enabled -eq 1}).Name")
        state["firewall_profiles"] = firewall_profiles.splitlines() if firewall_profiles else []
        vpn = run_powershell("Get-VpnConnection | Where-Object {$_.ConnectionStatus -eq 'Connected'} | ConvertTo-Json")
        state["vpn_connections"] = vpn[:512] if vpn else None
    return state


# ---------------------------------------------------------------------------
# Compliance
# ---------------------------------------------------------------------------

def collect_compliance(os_info: Dict[str, Any], security_posture: Dict[str, Any]) -> Dict[str, Any]:
    checks: List[Dict[str, Any]] = []

    def add(name: str, status: Optional[bool], details: str):
        checks.append({"name": name, "status": status, "details": details})

    mdm = security_posture.get("mdm_enrolled")
    add("MDM Enrollment", mdm, "Device enrolled" if mdm else "Not enrolled")

    disk_encrypted = security_posture.get("compliance_markers", {}).get("disk_encrypted")
    add("Disk Encryption", disk_encrypted, "Encrypted" if disk_encrypted else "Not encrypted")

    firewall = security_posture.get("firewall_enabled")
    add("Firewall Enabled", firewall, "Firewall active" if firewall else "Firewall disabled")

    screen_lock = security_posture.get("screen_lock") or {}
    timeout = screen_lock.get("timeout_seconds")
    screen_ok = screen_lock.get("enabled") and timeout is not None and timeout <= 900
    add("Screen Lock <=15m", screen_ok, f"Timeout: {timeout}" if timeout else "Unknown timeout")

    last_update = parse_timestamp(os_info.get("last_security_update"))
    if last_update:
        # both timezone-aware
        try:
            update_recent = (datetime.datetime.now(datetime.timezone.utc) - last_update).days <= 30
        except Exception:
            update_recent = None
    else:
        update_recent = None
    add("Security Updates (<=30d)", update_recent, "Recent" if update_recent else "Older than 30 days")

    compliant = all(check["status"] is not False for check in checks)
    return {"compliant": compliant, "checks": checks}


# ---------------------------------------------------------------------------
# Extensions
# ---------------------------------------------------------------------------

def register_extension(func: Callable[[], Dict[str, Any]]) -> None:
    EXTENSIONS.append(func)


def sample_extension() -> Dict[str, Any]:
    return {"name": "sample_extension", "data": "placeholder"}


# Extension for real-time file & USB events
class AlertCollector:
    def __init__(self):
        self.file_alerts = []
        self.usb_alerts = []
        home_dir = pathlib.Path.home()
        preferred_dirs = ['Downloads', 'Documents', 'Pictures', 'Videos', 'Music']
        self.file_paths: List[str] = []
        self._watch_paths_resolved: List[pathlib.Path] = []
        for name in preferred_dirs:
            target = home_dir / name
            if target.exists():
                self.file_paths.append(str(target))
                self._watch_paths_resolved.append(target.resolve())
        if not self.file_paths:
            self.file_paths = [str(home_dir)]
            self._watch_paths_resolved = [home_dir.resolve()]
        self._file_observer = None
        self._usb_last_state = set()
        self._usb_thread = None
        self._run_usb_thread = False
        self._usb_lock = threading.Lock()
        self._last_usb_scan = set()
        self._usb_platform_impl = self._select_usb_impl()
        self._start_monitors()

    # Select platform-appropriate USB implementation
    def _select_usb_impl(self):
        if SYSTEM == 'linux' and pyudev:
            return self._usb_linux
        elif SYSTEM == 'windows' and psutil:
            return self._usb_windows
        elif SYSTEM == 'darwin':
            return self._usb_mac
        else:
            return lambda: set()

    def _start_monitors(self):
        # Start file system monitoring (if watchdog is available)
        if Observer:
            self._file_observer = Observer()
            handler = self.FileMonitorHandler(self)
            for watch_path in self.file_paths:
                try:
                    self._file_observer.schedule(handler, watch_path, recursive=True)
                except Exception:
                    pass
            # use the daemon attribute (set before start) to avoid DeprecationWarning
            try:
                self._file_observer.daemon = True
            except Exception:
                # older Observer implementations might not have daemon attribute; ignore
                pass
            self._file_observer.start()
        # Start USB background polling thread
        self._run_usb_thread = True
        t = threading.Thread(target=self._usb_polling_thread, name='USBMonitor', daemon=True)
        t.start()
        self._usb_thread = t

    def stop(self):
        self._run_usb_thread = False
        if self._file_observer:
            try:
                self._file_observer.stop()
            except Exception:
                pass

    # File event handler
    class FileMonitorHandler(FileSystemEventHandler):
        def __init__(self, parent):
            self.parent = parent
        def on_modified(self, event):
            if not event.is_directory and self.parent.is_allowed_file(event.src_path):
                alert_entry = {
                    'alertType': 'FILE_MODIFIED',
                    'file': event.src_path,
                    'timestamp': datetime.datetime.now(datetime.timezone.utc).isoformat().replace("+00:00", "Z")
                }
                self.parent.file_alerts.append(alert_entry)
                AGENT_STATE["file_changes_history"].append(alert_entry)
        def on_deleted(self, event):
            if not event.is_directory and self.parent.is_allowed_file(event.src_path):
                alert_entry = {
                    'alertType': 'FILE_DELETED',
                    'file': event.src_path,
                    'timestamp': datetime.datetime.now(datetime.timezone.utc).isoformat().replace("+00:00", "Z")
                }
                self.parent.file_alerts.append(alert_entry)
                AGENT_STATE["file_changes_history"].append(alert_entry)
    
    def is_allowed_file(self, path: str) -> bool:
        try:
            candidate = pathlib.Path(path).resolve()
            for root in self._watch_paths_resolved:
                if str(candidate).lower().startswith(str(root).lower()):
                    return True
        except Exception:
            return False
        return False

    def _block_usb_device(self, device_info):
        """Block a USB device based on platform."""
        try:
            if SYSTEM == "windows":
                # Get device instance ID and disable it
                device_id = device_info.get("device_id") or device_info.get("serial", "")
                if device_id:
                    # Disable USB storage via registry or device manager
                    run_powershell(f'''
                        $usb = Get-PnpDevice | Where-Object {{$_.InstanceId -like "*USBSTOR*"}}
                        $usb | Disable-PnpDevice -Confirm:$false
                    ''')
                    # Also block via registry
                    run_powershell('Set-ItemProperty -Path "HKLM:\\SYSTEM\\CurrentControlSet\\Services\\USBSTOR" -Name "Start" -Value 4 -Type DWord')
            elif SYSTEM == "linux":
                # Unmount USB devices
                for part in psutil_lib.disk_partitions():
                    if 'removable' in getattr(part, "opts", "").lower():
                        run_cmd(["sudo", "umount", part.mountpoint])
            elif SYSTEM == "darwin":
                # Eject USB devices
                run_cmd(["diskutil", "unmountDisk", "force", device_info.get("device", "")])
        except Exception as e:
            logging.error(f"[agent] Failed to block USB device: {e}")

    # Main USB polling thread
    def _usb_polling_thread(self):
        while self._run_usb_thread:
            try:
                curr_state = self._usb_platform_impl()
                with self._usb_lock:
                    added = curr_state - self._last_usb_scan
                    removed = self._last_usb_scan - curr_state
                    t = datetime.datetime.now(datetime.timezone.utc).isoformat().replace("+00:00", "Z")
                    
                    # Check if USB blocking is enabled
                    if AGENT_STATE["usb_blocked"]:
                        # Block any newly connected USB devices
                        for device in added:
                            device_dict = dict(device) if isinstance(device, (set, frozenset)) else {"device": str(device)}
                            self._block_usb_device(device_dict)
                            self.usb_alerts.append({
                                'alertType': 'USB_BLOCKED',
                                'severity': 'CRITICAL',
                                'message': f'USB device blocked: {device_dict.get("vendor", "")} {device_dict.get("product", "")}',
                                'details': device_dict,
                                'timestamp': t
                            })
                    
                    for device in added:
                        if not AGENT_STATE["usb_blocked"]:
                            device_dict = dict(device) if isinstance(device, (set, frozenset)) else {"device": str(device)}
                            self.usb_alerts.append({
                                'alertType': 'USB_CONNECTED',
                                'details': device_dict,
                                'timestamp': t
                            })
                    for device in removed:
                        device_dict = dict(device) if isinstance(device, (set, frozenset)) else {"device": str(device)}
                        self.usb_alerts.append({
                            'alertType': 'USB_DISCONNECTED',
                            'details': device_dict,
                            'timestamp': t
                        })
                    self._last_usb_scan = curr_state
            except Exception as e:
                logging.warning(f"[agent] USB polling error: {e}")
            time.sleep(5)

    def _usb_linux(self):
        # Linux: enumerate USB devices using pyudev
        context = pyudev.Context()
        usb_devices = set()
        for device in context.list_devices(subsystem='usb', DEVTYPE='usb_device'):
            descr = {
                'vendor': device.get('ID_VENDOR', ''),
                'product': device.get('ID_MODEL', ''),
                'serial': device.get('ID_SERIAL_SHORT', ''),
            }
            usb_devices.add(tuple(sorted(descr.items())))
        return {frozenset(d) for d in usb_devices}

    def _usb_windows(self):
        # Windows: enumerate removable drives
        drives = set()
        for part in psutil.disk_partitions():
            if 'removable' in getattr(part, "opts", "").lower():
                drives.add(frozenset({('device', part.device)}))
        # Can be enhanced to use WMI for more data
        return drives

    def _usb_mac(self):
        # macOS: parse diskutil info
        try:
            out = run_cmd(['diskutil', 'list'])
            usb = set()
            for line in out.splitlines():
                if 'external' in line.lower() or 'usb' in line.lower():
                    usb.add(frozenset({('desc', line.strip())}))
            return usb
        except Exception:
            return set()

    def collect_alerts(self):
        res = {'file_alerts': self.file_alerts[:], 'usb_alerts': self.usb_alerts[:]}
        self.file_alerts.clear()
        self.usb_alerts.clear()
        return res

alert_collector = AlertCollector()

def agent_alerts_extension():
    return alert_collector.collect_alerts()

register_extension(agent_alerts_extension)


# ---------------------------------------------------------------------------
# Windows Event Log Monitoring
# ---------------------------------------------------------------------------

def monitor_windows_events():
    """Monitor Windows Event Logs and stream critical events.

    - If pywin32 is installed, uses win32evtlog.
    - Otherwise falls back to PowerShell Get-WinEvent (no extra dependencies).
    """
    if SYSTEM != "windows":
        return

    # Allow explicitly disabling event collection
    if str(os.environ.get("ENDPOINT_ENABLE_WIN_EVENTS", "1")).lower() in {"0", "false", "no"}:
        return

    try:
        import win32evtlog  # type: ignore
        import win32evtlogutil  # type: ignore
        pywin32_available = True
    except Exception:
        pywin32_available = False

    def _append_event(event_entry: Dict[str, Any]) -> None:
        AGENT_STATE["windows_events"].append(event_entry)
        if len(AGENT_STATE["windows_events"]) > 50:
            AGENT_STATE["windows_events"] = AGENT_STATE["windows_events"][-50:]

        et = (event_entry.get("event_type") or "").upper()
        if et == "ERROR":
            send_alert(
                "WINDOWS_EVENT_ERROR",
                "CRITICAL",
                f"Windows {event_entry.get('log_type', 'System')} Event: {event_entry.get('source', 'Unknown')} - {str(event_entry.get('message', ''))[:200]}",
                event_entry,
            )
        elif et in {"WARNING", "CRITICAL"}:
            send_alert(
                "WINDOWS_EVENT_WARNING",
                "WARNING",
                f"Windows {event_entry.get('log_type', 'System')} Event: {event_entry.get('source', 'Unknown')} - {str(event_entry.get('message', ''))[:200]}",
                event_entry,
            )

    def windows_event_monitor_thread():
        log_types = ["Security", "System", "Application"]
        last_record: Dict[str, int] = {lt: 0 for lt in log_types}

        while True:
            try:
                if pywin32_available:
                    for log_type in log_types:
                        hand = None
                        try:
                            hand = win32evtlog.OpenEventLog(None, log_type)  # type: ignore[name-defined]
                            if not hand:
                                continue
                            flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ  # type: ignore[name-defined]
                            events = win32evtlog.ReadEventLog(hand, flags, 0)  # type: ignore[name-defined]
                            for event in events:
                                event_id = event.EventID & 0xFFFF
                                event_type = event.EventType
                                if event_type not in [win32evtlog.EVENTLOG_ERROR_TYPE, win32evtlog.EVENTLOG_WARNING_TYPE]:  # type: ignore[name-defined]
                                    continue
                                try:
                                    msg = win32evtlogutil.SafeFormatMessage(event, log_type)  # type: ignore[name-defined]
                                except Exception:
                                    msg = str(event.StringInserts) if event.StringInserts else ""
                                event_entry = {
                                    "log_type": log_type,
                                    "event_id": event_id,
                                    "event_type": "ERROR" if event_type == win32evtlog.EVENTLOG_ERROR_TYPE else "WARNING",  # type: ignore[name-defined]
                                    "source": event.SourceName,
                                    "message": (msg or "")[:500],
                                    "timestamp": datetime.datetime.fromtimestamp(event.TimeGenerated.timestamp(), datetime.timezone.utc)
                                        .isoformat()
                                        .replace("+00:00", "Z"),
                                }
                                _append_event(event_entry)
                        except Exception:
                            pass
                        finally:
                            if hand:
                                try:
                                    win32evtlog.CloseEventLog(hand)  # type: ignore[name-defined]
                                except Exception:
                                    pass
                else:
                    for log_type in log_types:
                        ps = (
                            f"Get-WinEvent -LogName '{log_type}' -MaxEvents 30 | "
                            "Select-Object RecordId,Id,LevelDisplayName,ProviderName,TimeCreated,Message | "
                            "ConvertTo-Json -Compress"
                        )
                        raw = run_powershell(ps, timeout=12)
                        if not raw:
                            continue
                        try:
                            data = json.loads(raw)
                            events = data if isinstance(data, list) else [data]
                        except Exception:
                            continue
                        events = list(reversed(events))
                        for ev in events:
                            try:
                                record_id = int(ev.get("RecordId") or 0)
                            except Exception:
                                record_id = 0
                            if record_id <= last_record.get(log_type, 0):
                                continue
                            level = (ev.get("LevelDisplayName") or "").strip()
                            if level not in {"Error", "Warning", "Critical"}:
                                continue
                            event_entry = {
                                "log_type": log_type,
                                "event_id": ev.get("Id"),
                                "event_type": "ERROR" if level == "Error" else ("CRITICAL" if level == "Critical" else "WARNING"),
                                "source": ev.get("ProviderName"),
                                "message": (ev.get("Message") or "")[:500],
                                "timestamp": (
                                    datetime.datetime.fromisoformat(str(ev.get("TimeCreated")).replace("Z", "+00:00"))
                                    .astimezone(datetime.timezone.utc)
                                    .isoformat()
                                    .replace("+00:00", "Z")
                                    if ev.get("TimeCreated")
                                    else datetime.datetime.now(datetime.timezone.utc).isoformat().replace("+00:00", "Z")
                                ),
                                "record_id": record_id,
                            }
                            last_record[log_type] = max(last_record.get(log_type, 0), record_id)
                            _append_event(event_entry)
            except Exception:
                pass
            time.sleep(10)

    try:
        event_thread = threading.Thread(target=windows_event_monitor_thread, name='WindowsEventMonitor', daemon=True)
        event_thread.start()
    except Exception:
        pass


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    system_info = collect_identifiers()
    os_info = collect_os_info()
    network_info = collect_network()
    security_posture = collect_security_posture()
    installed_apps = collect_installed_apps()
    security_tools = collect_security_tools(installed_apps)
    process_summary = collect_process_summary()
    user_info = collect_user_info()
    disk_info = collect_disk_usage()
    endpoint_protection = collect_endpoint_protection_state()
    compliance = collect_compliance(os_info, security_posture)

    payload: Dict[str, Any] = {
        "schema_version": "2.0.0",
        # timezone-aware timestamp for collected_at
        "collected_at": datetime.datetime.now(datetime.timezone.utc).isoformat().replace("+00:00", "Z"),
        "agent": {"id": socket.gethostname(), "version": "4.0.0", "extensions": []},
        "system": system_info,
        "os": os_info,
        "network": network_info,
        "security_posture": security_posture,
        "software": {
            "installed_apps": installed_apps,
            "security_tools": security_tools,
        },
        "processes": process_summary,
        "users": user_info,
        "disk": disk_info,
        "endpoint_protection": endpoint_protection,
        "compliance": compliance,
    }

    for ext in EXTENSIONS:
        try:
            payload.setdefault("extensions_data", []).append(ext())
            payload["agent"]["extensions"].append(ext.__name__)
        except Exception as err:
            payload.setdefault("extensions_data", []).append({"name": ext.__name__, "error": str(err)})

    payload_json = json.dumps(payload, indent=2)
    payload["integrity"] = {"checksum_sha256": hashlib.sha256(payload_json.encode()).hexdigest()}
    print(json.dumps(payload, indent=2))


# ---------------------
# Socket connect helper with retries (non-fatal)
# ---------------------
def try_connect_with_backoff(url: str, max_attempts: int = 6, transports: Optional[List[str]] = None) -> bool:
    """
    Attempt to connect to the socket.io backend with backoff.
    IMPORTANT: If the environment is missing the 'requests' package (used by engineio for polling),
    prefer to force websocket-only transport. By default this function will use websocket-only to
    avoid engineio attempting HTTP polling which requires 'requests'.
    """
    attempt = 0
    # Default to websocket-only transport to avoid 'requests' dependency errors during polling.
    if transports is None:
        transports = ["websocket"]
    
    # Update global connection attempts
    global AGENT_STATE
    AGENT_STATE["connection_attempts"] += 1
    
    # Ensure we start with a clean state
    try:
        sio.disconnect()
    except:
        pass
    
    while attempt < max_attempts:
        try:
            sio.connect(url, transports=transports)
            # Wait a moment to ensure connection is fully established
            time.sleep(0.2)
            if getattr(sio, "connected", False):
                AGENT_STATE["connection_attempts"] = 0  # Reset on success
                return True
            else:
                # Connection didn't fully establish, disconnect and retry
                try:
                    sio.disconnect()
                except:
                    pass
                raise Exception("Connection established but not fully ready")
        except Exception as e:
            attempt += 1
            wait = min(5 * attempt, 30)
            logging.warning(f"[agent] socket connect failed (attempt {attempt}): {e}. retrying in {wait}s")
            time.sleep(wait)
    
    # If we've had too many failed attempts, wait longer before next retry
    if AGENT_STATE["connection_attempts"] > 3:
        logging.warning(f"[agent] Multiple connection failures detected. Waiting before next retry...")
        time.sleep(30)
    
    return False


if __name__ == "__main__":
    register_extension(sample_extension)
    
    # Start Windows Event Log monitoring
    if SYSTEM == "windows":
        monitor_windows_events()

    # Attempt to connect with backoff; do not let failure crash the agent.
    # This call forces websocket transport by default (avoids engineio trying HTTP polling
    # which emits "requests package is not installed" if requests isn't installed).
    connected = try_connect_with_backoff(SOCKETIO_URL, max_attempts=6, transports=["websocket"])
    if not connected:
        logging.warning("[agent] unable to connect to backend after retries; starting in offline mode. Telemetry will be attempted periodically and safe_emit will drop events until a connection is made.")

    # Start periodic telemetry / alert sending (will use safe_emit)
    t = threading.Thread(target=periodic_telemetry_thread, daemon=True)
    t.start()
    hb = threading.Thread(target=heartbeat_thread, daemon=True)
    hb.start()

    # Main should NOT exit
    while True:
        import time; time.sleep(60)

"""
Jamf Deployment Instructions:
1. Upload this script to Jamf Pro (Settings -> Computer Management -> Scripts) ensuring /usr/bin/python3 is available.
2. Create a policy (e.g., recurring check-in) to run the script. Optional: redirect output to a file:
       /usr/bin/python3 /path/to/enterprise_endpoint_agent.py > /Library/Application\\ Support/Org/agent.json
3. Use an Extension Attribute or log forwarder to ingest the JSON payload, or append a curl command to POST the payload to your backend.
4. For Windows/Linux deployments, schedule via Task Scheduler, cron, or systemd timers.
5. Extend capabilities by registering additional collectors via register_extension().
"""
