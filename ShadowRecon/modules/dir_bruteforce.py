# modules/dir_bruteforce.py
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urljoin

DEFAULT_WORDLIST = [
    "admin", "login", "dashboard", "wp-admin", "api", "config", "uploads",
    "backup", "server-status", "phpinfo.php", "robots.txt", "sitemap.xml"
]

VALID_STATUS = {200, 301, 302, 401, 403}

def check_path(base_url, path, timeout=6):
    url = urljoin(base_url.rstrip("/") + "/", path.lstrip("/"))
    try:
        r = requests.get(url, timeout=timeout, allow_redirects=True)
        if r.status_code in VALID_STATUS:
            return url, r.status_code, len(r.content)
    except Exception:
        return None
    return None

def brute_force(base_url, wordlist=None, threads=20):
    """
    Returns list of tuples: (url, status_code, content_length)
    """
    if wordlist is None:
        wordlist = DEFAULT_WORDLIST

    found = []
    with ThreadPoolExecutor(max_workers=threads) as ex:
        futures = {ex.submit(check_path, base_url, p): p for p in wordlist}
        for fut in as_completed(futures):
            res = fut.result()
            if res:
                found.append(res)
    return sorted(found, key=lambda x: x[0])
