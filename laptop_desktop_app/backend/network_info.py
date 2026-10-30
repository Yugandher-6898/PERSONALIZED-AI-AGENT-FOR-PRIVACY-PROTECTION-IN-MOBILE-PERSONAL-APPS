"""
Network Information Utility
Detects the host machine's active local Wi-Fi / LAN IP address so real mobile devices
can seamlessly connect to the Laptop SOC backend on the local network.
"""

import socket
import subprocess
import re

def get_local_ip() -> str:
    """
    Attempts multiple techniques to resolve the machine's primary Wi-Fi / LAN IPv4 address.
    Filters out virtual adapters (VMware, VirtualBox, WSL) and loopback.
    """
    # 1. Primary technique: connect dummy UDP socket to public IP (no packets actually sent)
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(0.5)
        # 8.8.8.8 is used as dummy destination to discover the routing interface
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        if ip and not ip.startswith("127.") and not ip.startswith("169.254."):
            # Check if this isn't a VMware network (192.168.159.x or 192.168.132.x)
            if not (ip.startswith("192.168.159.") or ip.startswith("192.168.132.")):
                return ip
    except Exception:
        pass

    # 2. Windows PowerShell / ipconfig parsing fallback
    try:
        cmd = 'Get-NetIPAddress -AddressFamily IPv4 | Where-Object { $_.InterfaceAlias -like "*Wi-Fi*" -or $_.InterfaceAlias -like "*Wireless*" -or $_.InterfaceAlias -like "*Ethernet*" } | Select-Object -ExpandProperty IPAddress'
        out = subprocess.check_output(["powershell", "-NoProfile", "-Command", cmd], text=True, timeout=3).strip()
        ips = [line.strip() for line in out.splitlines() if line.strip() and not line.strip().startswith("169.254.")]
        if ips:
            return ips[0]
    except Exception:
        pass

    # 3. Standard hostname fallback
    try:
        host_name = socket.gethostname()
        host_ip = socket.gethostbyname(host_name)
        if host_ip and not host_ip.startswith("127."):
            return host_ip
    except Exception:
        pass

    return "127.0.0.1"

if __name__ == "__main__":
    print(f"Detected Local IP: {get_local_ip()}")
