# modules/output_manager.py
import os
import json

def ensure_output_dir(base, domain):
    outdir = os.path.join(base, domain)
    os.makedirs(outdir, exist_ok=True)
    return outdir

def save_list(filepath, items):
    with open(filepath, "w", encoding="utf-8") as f:
        for it in items:
            f.write(f"{it}\n")

def save_vuln_report(outdir, report):
    with open(os.path.join(outdir, "vuln_report.json"), "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)

def save_summary(outdir, subdomains, resolved, ports, dirs, vuln):
    save_list(os.path.join(outdir, "subdomains.txt"), subdomains)
    # resolved is dict host -> [ips]
    with open(os.path.join(outdir, "resolved.txt"), "w", encoding="utf-8") as f:
        for h, ips in resolved.items():
            f.write(f"{h} -> {', '.join(ips)}\n")
    save_list(os.path.join(outdir, "ports.txt"), ports if isinstance(ports, list) else [str(ports)])
    with open(os.path.join(outdir, "dirs.txt"), "w", encoding="utf-8") as f:
        for url, status, clen in dirs:
            f.write(f"{url}\t{status}\t{clen}\n")
    save_vuln_report(outdir, vuln)
