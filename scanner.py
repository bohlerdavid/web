import subprocess
import socket
import re
import platform
import ipaddress
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

# ---------------------------------------------------------------------------
# OUI vendor lookup table (top vendors, inline — no external API)
# Key = first 8 chars of MAC uppercase, e.g. 'AA:BB:CC'
# ---------------------------------------------------------------------------

OUI_VENDORS = {
    # Apple
    '00:03:93': 'Apple',
    '00:0A:27': 'Apple',
    '00:1B:63': 'Apple',
    '00:1C:B3': 'Apple',
    '00:1D:4F': 'Apple',
    '00:1E:52': 'Apple',
    '00:1F:5B': 'Apple',
    '00:21:E9': 'Apple',
    '00:22:41': 'Apple',
    '00:23:12': 'Apple',
    '00:23:32': 'Apple',
    '00:24:36': 'Apple',
    '00:25:00': 'Apple',
    '00:25:4B': 'Apple',
    '00:25:BC': 'Apple',
    '00:26:08': 'Apple',
    '00:26:B0': 'Apple',
    '00:26:BB': 'Apple',
    'AC:BC:32': 'Apple',
    'B8:E8:56': 'Apple',
    'F0:18:98': 'Apple',
    # Dell
    '00:14:22': 'Dell',
    '00:1A:A0': 'Dell',
    '18:03:73': 'Dell',
    '18:A9:9B': 'Dell',
    '24:B6:FD': 'Dell',
    '34:17:EB': 'Dell',
    '44:37:E6': 'Dell',
    '54:BF:64': 'Dell',
    '74:86:7A': 'Dell',
    '84:8F:69': 'Dell',
    'A4:1F:72': 'Dell',
    'B0:83:FE': 'Dell',
    'D8:9E:F3': 'Dell',
    'F0:1F:AF': 'Dell',
    # HP
    '00:17:A4': 'HP',
    '00:1C:C4': 'HP',
    '00:21:5A': 'HP',
    '00:22:64': 'HP',
    '00:23:7D': 'HP',
    '00:24:81': 'HP',
    '00:25:B3': 'HP',
    '00:26:55': 'HP',
    '3C:D9:2B': 'HP',
    '58:20:B1': 'HP',
    '94:57:A5': 'HP',
    'A0:1D:48': 'HP',
    'B4:B5:2F': 'HP',
    'D8:D3:85': 'HP',
    'FC:15:B4': 'HP',
    # Cisco
    '00:00:0C': 'Cisco',
    '00:01:42': 'Cisco',
    '00:01:63': 'Cisco',
    '00:01:96': 'Cisco',
    '00:02:16': 'Cisco',
    '00:02:3D': 'Cisco',
    '00:02:4A': 'Cisco',
    '00:02:4B': 'Cisco',
    '00:03:6B': 'Cisco',
    '00:04:9A': 'Cisco',
    '00:0B:46': 'Cisco',
    '00:0D:28': 'Cisco',
    '00:0D:29': 'Cisco',
    '00:0E:38': 'Cisco',
    '00:0F:23': 'Cisco',
    # Microsoft
    '00:03:FF': 'Microsoft',
    '00:0D:3A': 'Microsoft',
    '00:12:5A': 'Microsoft',
    '00:15:5D': 'Microsoft',
    '00:17:FA': 'Microsoft',
    '00:1D:D8': 'Microsoft',
    '00:22:48': 'Microsoft',
    '00:50:F2': 'Microsoft',
    '28:18:78': 'Microsoft',
    '48:50:73': 'Microsoft',
    '7C:1E:52': 'Microsoft',
    '98:5F:D3': 'Microsoft',
    'A4:C3:61': 'Microsoft',
    'C4:9D:ED': 'Microsoft',
    # Lenovo
    '00:23:AE': 'Lenovo',
    '28:D2:44': 'Lenovo',
    '54:EE:75': 'Lenovo',
    '60:6C:66': 'Lenovo',
    '84:2B:2B': 'Lenovo',
    '88:70:8C': 'Lenovo',
    '98:FA:9B': 'Lenovo',
    'B8:88:E3': 'Lenovo',
    'DC:FE:18': 'Lenovo',
    'E8:6A:64': 'Lenovo',
    # Samsung
    '00:07:AB': 'Samsung',
    '00:12:FB': 'Samsung',
    '00:15:99': 'Samsung',
    '00:16:32': 'Samsung',
    '00:17:C9': 'Samsung',
    '00:18:AF': 'Samsung',
    '00:1A:8A': 'Samsung',
    '00:1B:98': 'Samsung',
    '00:1C:43': 'Samsung',
    '00:1D:25': 'Samsung',
    '00:21:19': 'Samsung',
    '00:23:39': 'Samsung',
    '00:24:54': 'Samsung',
    '00:26:37': 'Samsung',
    '2C:AE:2B': 'Samsung',
    # Raspberry Pi
    'B8:27:EB': 'Raspberry Pi',
    'DC:A6:32': 'Raspberry Pi',
    'E4:5F:01': 'Raspberry Pi',
    # ASUS
    '00:0C:6E': 'ASUS',
    '00:1A:92': 'ASUS',
    '00:1D:60': 'ASUS',
    '00:E0:18': 'ASUS',
    'AC:22:0B': 'ASUS',
    'F8:32:E4': 'ASUS',
    # Intel
    '00:02:B3': 'Intel',
    '00:07:E9': 'Intel',
    '00:12:F0': 'Intel',
    '00:13:02': 'Intel',
    '00:13:20': 'Intel',
    '00:15:17': 'Intel',
    '00:16:76': 'Intel',
    'A4:C3:F0': 'Intel',
    # VMware
    '00:0C:29': 'VMware',
    '00:50:56': 'VMware',
    '00:05:69': 'VMware',
    # TP-Link
    '00:27:19': 'TP-Link',
    '14:CC:20': 'TP-Link',
    '50:C7:BF': 'TP-Link',
    '54:AF:97': 'TP-Link',
    '64:70:02': 'TP-Link',
    'AC:84:C6': 'TP-Link',
    # NETGEAR
    '00:09:5B': 'NETGEAR',
    '00:14:6C': 'NETGEAR',
    '00:18:4D': 'NETGEAR',
    '00:1B:2F': 'NETGEAR',
    '00:1E:2A': 'NETGEAR',
    '20:4E:7F': 'NETGEAR',
    # D-Link
    '00:05:5D': 'D-Link',
    '00:0D:88': 'D-Link',
    '00:1B:11': 'D-Link',
    '00:1C:F0': 'D-Link',
    '00:21:91': 'D-Link',
    '14:D6:4D': 'D-Link',
    # Ubiquiti
    '00:15:6D': 'Ubiquiti',
    '00:27:22': 'Ubiquiti',
    '04:18:D6': 'Ubiquiti',
    '24:A4:3C': 'Ubiquiti',
    '44:D9:E7': 'Ubiquiti',
    '68:72:51': 'Ubiquiti',
    'B4:FB:E4': 'Ubiquiti',
}


# ---------------------------------------------------------------------------
# Global scan state (thread-safe)
# ---------------------------------------------------------------------------

scan_state = {
    'running': False,
    'progress': 0,
    'status_text': '',
    'results': [],
    'started_at': None,
    'finished_at': None,
    'error': None,
}
scan_lock = threading.Lock()


# ---------------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------------

def get_local_network():
    """
    Returns (local_ip, network_cidr), e.g. ('192.168.1.5', '192.168.1.0/24').
    Falls back to loopback on failure.
    """
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(2)
        s.connect(('8.8.8.8', 80))
        local_ip = s.getsockname()[0]
        s.close()
        network = ipaddress.ip_network(f'{local_ip}/24', strict=False)
        return local_ip, str(network)
    except Exception:
        return '127.0.0.1', '127.0.0.0/24'


def ping_host(ip_str):
    """
    Ping a single host. Returns True if alive.
    Windows: ping -n 1 -w 500
    Linux/Mac: ping -c 1 -W 1
    """
    system = platform.system().lower()
    try:
        if system == 'windows':
            cmd = ['ping', '-n', '1', '-w', '500', ip_str]
        else:
            cmd = ['ping', '-c', '1', '-W', '1', ip_str]

        result = subprocess.run(
            cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=3,
        )
        return result.returncode == 0
    except (subprocess.TimeoutExpired, OSError, FileNotFoundError):
        return False


def get_arp_table():
    """
    Returns dict {ip: mac}. Reads system ARP table.
    Windows: arp -a
    Linux/Mac: arp -n
    Normalizes MAC to XX:XX:XX:XX:XX:XX uppercase.
    """
    arp = {}
    system = platform.system().lower()
    try:
        if system == 'windows':
            cmd = ['arp', '-a']
        else:
            cmd = ['arp', '-n']

        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=10,
        )
        output = result.stdout

        if system == 'windows':
            # Windows format: "  192.168.1.1          aa-bb-cc-dd-ee-ff     dynamic"
            pattern = re.compile(
                r'(\d{1,3}(?:\.\d{1,3}){3})\s+([\da-fA-F]{2}[-:][\da-fA-F]{2}[-:][\da-fA-F]{2}[-:][\da-fA-F]{2}[-:][\da-fA-F]{2}[-:][\da-fA-F]{2})'
            )
        else:
            # Linux format: "192.168.1.1 ether aa:bb:cc:dd:ee:ff  C  eth0"
            # Also handles incomplete entries
            pattern = re.compile(
                r'(\d{1,3}(?:\.\d{1,3}){3})\s+\S+\s+([\da-fA-F]{2}[:\-][\da-fA-F]{2}[:\-][\da-fA-F]{2}[:\-][\da-fA-F]{2}[:\-][\da-fA-F]{2}[:\-][\da-fA-F]{2})'
            )

        for match in pattern.finditer(output):
            ip = match.group(1)
            raw_mac = match.group(2)
            # Normalize: replace dashes with colons, uppercase, zero-pad each octet
            parts = re.split(r'[:\-]', raw_mac)
            normalized = ':'.join(p.zfill(2).upper() for p in parts)
            arp[ip] = normalized

    except Exception:
        pass

    return arp


def resolve_hostname(ip_str):
    """
    Resolve IP to hostname via reverse DNS. Returns hostname string or '' on failure.
    """
    try:
        hostname, _, _ = socket.gethostbyaddr(ip_str)
        return hostname
    except (socket.herror, socket.gaierror, OSError):
        return ''


def get_nmap_os(ip_str):
    """
    Use python-nmap to detect OS. Returns dict with keys: os, accuracy.
    Returns empty dict if nmap unavailable or fails.
    Requires root/admin privileges for OS detection.
    """
    try:
        import nmap
        nm = nmap.PortScanner()
        nm.scan(
            hosts=ip_str,
            arguments='-O --osscan-guess -T4 --max-retries 1 --host-timeout 10s',
        )
        if ip_str in nm.all_hosts():
            host = nm[ip_str]
            if 'osmatch' in host and host['osmatch']:
                best = host['osmatch'][0]
                return {
                    'os': best.get('name', ''),
                    'accuracy': best.get('accuracy', ''),
                }
    except ImportError:
        pass
    except Exception:
        pass
    return {}


def get_mac_vendor(mac):
    """
    Return vendor name from MAC OUI prefix using inline OUI table.
    Normalizes MAC to uppercase, compares first 8 chars (XX:XX:XX).
    Returns empty string if unknown.
    """
    if not mac:
        return ''
    # Normalize: replace dashes, uppercase
    normalized = mac.upper().replace('-', ':')
    # Ensure proper XX:XX:XX:... format — handle compact formats
    parts = re.split(r'[:\-]', mac.upper())
    if len(parts) >= 3:
        oui = ':'.join(p.zfill(2) for p in parts[:3])
        return OUI_VENDORS.get(oui, '')
    return ''


# ---------------------------------------------------------------------------
# Background scan
# ---------------------------------------------------------------------------

def _do_scan(network_cidr, use_nmap):
    """Internal: performs the full scan, updates scan_state throughout."""
    try:
        with scan_lock:
            scan_state['status_text'] = f'Starte Ping-Sweep für {network_cidr} …'
            scan_state['progress'] = 0

        network = ipaddress.ip_network(network_cidr, strict=False)
        hosts = list(network.hosts())
        total = len(hosts)

        # ------------------------------------------------------------------
        # Step 1: Ping sweep (progress 0–60%)
        # ------------------------------------------------------------------
        alive_ips = []
        completed = 0

        with scan_lock:
            scan_state['status_text'] = f'Ping-Sweep: 0 / {total} Hosts …'

        def ping_and_track(ip):
            return str(ip), ping_host(str(ip))

        with ThreadPoolExecutor(max_workers=50) as executor:
            futures = {executor.submit(ping_and_track, ip): ip for ip in hosts}
            for future in as_completed(futures):
                ip_str, is_alive = future.result()
                if is_alive:
                    alive_ips.append(ip_str)
                completed += 1
                pct = int((completed / total) * 60)
                with scan_lock:
                    scan_state['progress'] = pct
                    scan_state['status_text'] = (
                        f'Ping-Sweep: {completed} / {total} — '
                        f'{len(alive_ips)} aktive Hosts gefunden'
                    )

        # ------------------------------------------------------------------
        # Step 2: ARP table
        # ------------------------------------------------------------------
        with scan_lock:
            scan_state['status_text'] = 'Lese ARP-Tabelle …'
            scan_state['progress'] = 61

        arp_table = get_arp_table()

        # ------------------------------------------------------------------
        # Step 3: Hostname & vendor for each alive host (progress 62–65%)
        # ------------------------------------------------------------------
        with scan_lock:
            scan_state['status_text'] = 'Löse Hostnamen auf …'
            scan_state['progress'] = 62

        results = []
        now_str = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

        for ip_str in sorted(alive_ips, key=lambda x: ipaddress.ip_address(x)):
            mac = arp_table.get(ip_str, '')
            hostname = resolve_hostname(ip_str)
            vendor = get_mac_vendor(mac) if mac else ''
            results.append({
                'ip': ip_str,
                'mac': mac,
                'hostname': hostname,
                'vendor': vendor,
                'os': '',
                'os_accuracy': '',
                'first_seen': now_str,
            })

        with scan_lock:
            scan_state['progress'] = 65
            scan_state['status_text'] = f'{len(results)} Hosts aufgelöst.'
            scan_state['results'] = list(results)

        # ------------------------------------------------------------------
        # Step 4: nmap OS detection (progress 65–95%)
        # ------------------------------------------------------------------
        if use_nmap and results:
            with scan_lock:
                scan_state['status_text'] = 'Starte nmap OS-Erkennung …'

            for idx, entry in enumerate(results):
                pct = 65 + int(((idx + 1) / len(results)) * 30)
                with scan_lock:
                    scan_state['progress'] = pct
                    scan_state['status_text'] = (
                        f'nmap OS-Erkennung: {idx + 1} / {len(results)} — {entry["ip"]}'
                    )

                os_info = get_nmap_os(entry['ip'])
                entry['os'] = os_info.get('os', '')
                entry['os_accuracy'] = os_info.get('accuracy', '')

            with scan_lock:
                scan_state['results'] = list(results)

        # ------------------------------------------------------------------
        # Step 5: Done
        # ------------------------------------------------------------------
        with scan_lock:
            scan_state['progress'] = 100
            scan_state['running'] = False
            scan_state['finished_at'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            scan_state['status_text'] = (
                f'Fertig! {len(results)} Geräte gefunden.'
            )
            scan_state['results'] = list(results)

    except Exception as exc:
        with scan_lock:
            scan_state['running'] = False
            scan_state['error'] = str(exc)
            scan_state['status_text'] = f'Fehler: {exc}'
            scan_state['progress'] = 0
            scan_state['finished_at'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')


def start_scan(network=None, use_nmap=True):
    """
    Start a background network scan.
    If network is None, auto-detect via get_local_network().
    Returns immediately; scan runs in a daemon thread.
    """
    if not network:
        _, network = get_local_network()

    with scan_lock:
        scan_state['running'] = True
        scan_state['progress'] = 0
        scan_state['status_text'] = 'Initialisiere Scan …'
        scan_state['results'] = []
        scan_state['started_at'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        scan_state['finished_at'] = None
        scan_state['error'] = None

    thread = threading.Thread(target=_do_scan, args=(network, use_nmap), daemon=True)
    thread.start()


def get_scan_state():
    """Return a thread-safe copy of scan_state."""
    with scan_lock:
        return dict(scan_state)


# ---------------------------------------------------------------------------
# Hardware query functions
# ---------------------------------------------------------------------------

def query_hardware_wmi(ip, username=None, password=None, domain=''):
    """
    Query hardware info from a Windows machine via WMI.
    If username is None, tries current Windows session (NTLM passthrough).
    Returns dict with keys: cpu, cpu_cores, ram_gb, disks, manufacturer, model,
                            serial, os_caption, os_build, last_boot, method, error
    """
    try:
        import wmi
        import pythoncom
        pythoncom.CoInitialize()

        connect_kwargs = {'computer': ip}
        if username:
            connect_kwargs['user'] = f'{domain}\\{username}' if domain else username
            connect_kwargs['password'] = password

        c = wmi.WMI(**connect_kwargs)
        result = {'method': 'wmi', 'error': None}

        # CPU
        try:
            cpus = c.Win32_Processor()
            if cpus:
                result['cpu'] = cpus[0].Name.strip()
                result['cpu_cores'] = cpus[0].NumberOfCores
                result['cpu_threads'] = cpus[0].NumberOfLogicalProcessors
        except: pass

        # RAM
        try:
            cs = c.Win32_ComputerSystem()
            if cs:
                result['ram_gb'] = round(int(cs[0].TotalPhysicalMemory) / (1024**3), 1)
                result['manufacturer'] = cs[0].Manufacturer.strip()
                result['model'] = cs[0].Model.strip()
        except: pass

        # Disks
        try:
            disks = []
            for disk in c.Win32_DiskDrive():
                size_gb = round(int(disk.Size) / (1024**3), 1) if disk.Size else 0
                disks.append(f'{disk.Model.strip()} ({size_gb} GB)')
            result['disks'] = ' | '.join(disks)
        except: pass

        # BIOS / Serial
        try:
            bios = c.Win32_BIOS()
            if bios:
                result['serial'] = bios[0].SerialNumber.strip()
        except: pass

        # OS
        try:
            os_list = c.Win32_OperatingSystem()
            if os_list:
                result['os_caption'] = os_list[0].Caption.strip()
                result['os_build'] = os_list[0].BuildNumber
                lb = os_list[0].LastBootUpTime
                if lb:
                    result['last_boot'] = lb[:4]+'-'+lb[4:6]+'-'+lb[6:8]+' '+lb[8:10]+':'+lb[10:12]
        except: pass

        pythoncom.CoUninitialize()
        return result

    except ImportError:
        return {'error': 'wmi_not_installed', 'method': 'wmi'}
    except Exception as e:
        try:
            pythoncom.CoUninitialize()
        except Exception:
            pass
        err = str(e)
        if 'Access denied' in err or '0x80070005' in err:
            return {'error': 'access_denied', 'method': 'wmi'}
        elif 'RPC' in err or 'connect' in err.lower() or '0x800706ba' in err:
            return {'error': 'unreachable', 'method': 'wmi'}
        return {'error': err[:200], 'method': 'wmi'}


def query_hardware_ssh(ip, username, password, port=22):
    """Query hardware info from a Linux/Mac machine via SSH."""
    try:
        import paramiko
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(ip, port=port, username=username, password=password, timeout=10)

        result = {'method': 'ssh', 'error': None}

        def run(cmd):
            _, stdout, _ = ssh.exec_command(cmd, timeout=10)
            return stdout.read().decode('utf-8', errors='ignore').strip()

        # CPU
        cpu = run("lscpu | grep 'Model name' | sed 's/.*: *//'")
        if not cpu:
            cpu = run("sysctl -n machdep.cpu.brand_string 2>/dev/null")  # macOS
        if cpu: result['cpu'] = cpu

        cores = run("nproc 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null")
        if cores:
            try:
                result['cpu_cores'] = int(cores)
            except ValueError:
                pass

        # RAM
        ram = run("free -b | awk '/Mem:/ {print $2}'")
        if not ram:
            ram = run("sysctl -n hw.memsize 2>/dev/null")  # macOS
        if ram:
            try:
                result['ram_gb'] = round(int(ram) / (1024**3), 1)
            except ValueError:
                pass

        # Disks
        disks = run("lsblk -d -o NAME,SIZE,MODEL --noheadings 2>/dev/null | head -5")
        if disks: result['disks'] = disks.replace('\n', ' | ')

        # OS
        os_info = run("cat /etc/os-release 2>/dev/null | grep PRETTY_NAME | cut -d= -f2 | tr -d '\"'")
        if not os_info:
            os_info = run("sw_vers -productVersion 2>/dev/null")  # macOS
        if os_info: result['os_caption'] = os_info

        # Serial / Model
        serial = run("sudo dmidecode -s system-serial-number 2>/dev/null || cat /sys/class/dmi/id/product_serial 2>/dev/null")
        if serial and 'Permission' not in serial: result['serial'] = serial

        model = run("sudo dmidecode -s system-product-name 2>/dev/null || cat /sys/class/dmi/id/product_name 2>/dev/null")
        if model: result['model'] = model

        # Last boot
        last_boot = run("uptime -s 2>/dev/null")
        if last_boot: result['last_boot'] = last_boot

        ssh.close()
        return result

    except ImportError:
        return {'error': 'paramiko_not_installed', 'method': 'ssh'}
    except Exception as e:
        err = str(e)
        if 'Authentication' in err:
            return {'error': 'access_denied', 'method': 'ssh'}
        return {'error': err[:200], 'method': 'ssh'}


def get_smb_info(ip):
    """Use nmap NSE scripts to get hostname, OS, domain via SMB (no credentials)."""
    try:
        import nmap
        nm = nmap.PortScanner()
        nm.scan(ip, arguments='--script smb-os-discovery,nbstat -p 137,139,445 -T4 --host-timeout 15s')

        result = {}
        if ip not in nm.all_hosts():
            return result

        host = nm[ip]

        # From smb-os-discovery script
        script_output = ''
        if 'tcp' in host:
            for port in [445, 139]:
                if port in host.get('tcp', {}):
                    scripts = host['tcp'][port].get('script', {})
                    if 'smb-os-discovery' in scripts:
                        script_output = scripts['smb-os-discovery']
                        break

        if script_output:
            for line in script_output.split('\n'):
                line = line.strip()
                if 'OS:' in line:
                    result['os'] = line.split('OS:')[-1].strip()
                elif 'Computer name:' in line:
                    result['hostname'] = line.split('Computer name:')[-1].strip()
                elif 'Domain name:' in line or 'Workgroup:' in line:
                    result['domain'] = line.split(':')[-1].strip()

        # From nbstat
        for port in [137]:
            if 'udp' in host and port in host.get('udp', {}):
                scripts = host['udp'][port].get('script', {})
                if 'nbstat' in scripts and 'hostname' not in result:
                    nb = scripts['nbstat']
                    for line in nb.split('\n'):
                        if '<00>' in line and 'UNIQUE' in line:
                            result['hostname'] = line.split()[0].strip()
                            break

        return result
    except:
        return {}
