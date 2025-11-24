# ShadowRecon.py
import argparse
from modules.subdomain_enum import enumerate_subdomains
from modules.port_scanner import port_scan
from modules.dns_resolver import resolve_subdomains
from modules.dir_bruteforce import brute_force
from modules.vuln_scanner import scan_targets_for_vulns
from modules.output_manager import ensure_output_dir, save_summary
import socket

def banner():
    print(r"""
   ____  _               _                  ____                      
  / ___|| |__   __ _  __| | ___  _ __      |  _ \ ___  ___ ___  _ __  
  \___ \| '_ \ / _` |/ _` |/ _ \| '_ \_____| |_) / _ \/ __/ _ \| '_ \ 
   ___) | | | | (_| | (_| | (_) | | |_____|  _ <  __/ (_| (_) | | | |
  |____/|_| |_|\__,_|\__,_|\___/|_|       |_| \_\___|\___\___/|_| |_|

                       ShadowRecon by Mohid
                  Recon • Enumeration • Analysis
""")

def get_root_url(domain):
    if not domain.startswith("http"):
        return "http://" + domain
    return domain

def main():
    banner()
    parser = argparse.ArgumentParser(description="ShadowRecon - Recon Framework (FULL pipeline)")
    parser.add_argument("-t", "--target", help="Target domain (example.com)", required=True)
    parser.add_argument("--out", help="Output base folder", default="output")
    parser.add_argument("--no-save", help="Do not save output files", action="store_true")
    args = parser.parse_args()

    target = args.target.strip()
    print(f"\n[+] Target set to: {target}\n")

    # Step 1: Subdomain enumeration
    print("[+] Running Subdomain Enumeration (crt.sh)...")
    subdomains = enumerate_subdomains(target)
    if subdomains:
        print(f"[+] Found {len(subdomains)} subdomains")
    else:
        print("[!] No subdomains found")

    # Step 2: DNS resolution - filter alive subdomains
    print("[+] Resolving subdomains (DNS)...")
    resolved = resolve_subdomains(subdomains)
    if resolved:
        print(f"[+] Resolved {len(resolved)} hosts")
        for h, ips in resolved.items():
            print(f" - {h} -> {', '.join(ips)}")
    else:
        print("[!] No subdomains resolved")

    # Step 3: Port scan on target root (resolve target first)
    print("\n[+] Running Port Scan on target root (top100)...")
    # try to resolve main target to IP (fall back to domain if not)
    target_ip = None
    try:
        target_ip = socket.gethostbyname(target)
    except Exception:
        # try with www
        try:
            target_ip = socket.gethostbyname("www." + target)
        except Exception:
            target_ip = None

    scan_target_for_ports = target if target_ip is None else target_ip
    ports = port_scan(scan_target_for_ports, mode="top100")

    # Step 4: Directory brute force on root URL
    print("\n[+] Running directory brute force on root (light wordlist)...")
    root_url = get_root_url(target)
    dirs = brute_force(root_url)

    if dirs:
        print("[+] Found directories/paths:")
        for url, status, clen in dirs:
            print(f" - {url} ({status})")
    else:
        print("[!] No interesting directories found with the small wordlist.")

    # Step 5: Vulnerability scanning (headers + simple XSS/SQLi)
    print("\n[+] Running lightweight vulnerability checks (non-invasive)...")
    # Build targets to check: root + found dirs
    target_urls = [root_url]
    for url, _, _ in dirs:
        target_urls.append(url)
    vuln_report = scan_targets_for_vulns(target_urls)

    # Print quick vuln summary
    missing_headers_count = sum(1 for h in vuln_report["headers"] if "missing" in h and h["missing"])
    print(f"[+] Header checks performed: {len(vuln_report['headers'])} — missing headers found on {missing_headers_count} targets")
    print(f"[+] XSS findings: {len(vuln_report['xss'])}")
    print(f"[+] SQLi findings: {len(vuln_report['sqli'])}")

    # Step 6: Save outputs
    if not args.no_save:
        outdir = ensure_output_dir(args.out, target)
        # ports list as strings
        ports_str = [str(p) for p in ports]
        save_summary(outdir, subdomains, resolved, ports_str, dirs, vuln_report)
        print(f"\n[+] Results saved to: {outdir}")
    else:
        print("\n[!] Skipping saving outputs (--no-save provided)")

    print("\n[+] Recon completed.\n")

if __name__ == "__main__":
    main()
