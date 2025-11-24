import socket
import threading
from queue import Queue

open_ports = []
print_lock = threading.Lock()


def scan_port(target, port, timeout=1):
    """Scan a single port."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)

        result = sock.connect_ex((target, port))
        if result == 0:
            with print_lock:
                print(f"[OPEN] Port {port} is open")
            open_ports.append(port)

        sock.close()

    except Exception:
        pass


def threaded_scan(target, ports):
    """Thread worker to scan ports."""
    while not ports.empty():
        port = ports.get()
        scan_port(target, port)
        ports.task_done()


def port_scan(target, mode="top100"):
    """
    Scans ports on a target.
    Modes:
      - top100 : scans top 100 common ports
      - full   : scans entire 1-65535 range
    """

    print(f"[INFO] Starting port scan on {target} (mode={mode})")
    
    # Top ports list (Nmap's official top 100)
    top_100_ports = [
        21,22,23,25,53,80,110,111,135,139,143,443,445,993,995,
        1723,3306,3389,5900,8080,8443
    ]

    if mode == "top100":
        ports_to_scan = top_100_ports
    else:
        ports_to_scan = range(1, 65536)

    # Queue for threaded scanning
    port_queue = Queue()
    for port in ports_to_scan:
        port_queue.put(port)

    threads = []
    thread_count = 100  # adjust for speed

    for _ in range(thread_count):
        t = threading.Thread(target=threaded_scan, args=(target, port_queue))
        t.daemon = True
        t.start()
        threads.append(t)

    port_queue.join()

    print("\n[INFO] Scan complete.")
    print(f"[INFO] Open Ports: {open_ports}\n")

    return sorted(open_ports)
