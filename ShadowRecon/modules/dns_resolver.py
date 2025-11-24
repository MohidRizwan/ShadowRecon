# modules/dns_resolver.py
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed

def resolve_host(host):
    try:
        info = socket.gethostbyname_ex(host)
        ips = list(set(info[2]))
        return host, ips
    except Exception:
        return host, []

def resolve_subdomains(subdomains, threads=20):
    """
    Resolve list of subdomains. Returns dict: {subdomain: [ips]}
    Filters out subdomains with no A record.
    """
    results = {}
    with ThreadPoolExecutor(max_workers=threads) as ex:
        futures = {ex.submit(resolve_host, s): s for s in subdomains}
        for fut in as_completed(futures):
            host, ips = fut.result()
            results[host] = ips
    # alive = those with at least one IP
    alive = {h: ips for h, ips in results.items() if ips}
    return alive
