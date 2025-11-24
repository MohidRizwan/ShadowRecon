# modules/vuln_scanner.py
import requests
from urllib.parse import urljoin, urlparse, urlencode

SECURITY_HEADERS = [
    "strict-transport-security",
    "x-frame-options",
    "x-content-type-options",
    "content-security-policy",
    "referrer-policy"
]

XSS_PAYLOAD = "<script>alert(1)</script>"
SQLI_PAYLOAD = "' OR '1'='1"

SQL_ERRORS = [
    "you have an error in your sql syntax",
    "warning: mysql",
    "unclosed quotation mark after the character string",
    "quoted string not properly terminated",
    "mysql_fetch_assoc()"
]

def check_security_headers(url, timeout=6):
    try:
        r = requests.head(url, timeout=timeout, allow_redirects=True)
        headers = {k.lower(): v for k, v in r.headers.items()}
        missing = [h for h in SECURITY_HEADERS if h not in headers]
        present = {h: headers.get(h) for h in SECURITY_HEADERS if h in headers}
        return {"url": url, "missing": missing, "present": present}
    except Exception as e:
        return {"url": url, "error": str(e)}

def simple_xss_test(url, timeout=6):
    """
    Inject a single GET parameter 'q' with XSS payload.
    Non-invasive: single request, checks reflection.
    """
    try:
        parsed = urlparse(url)
        base = f"{parsed.scheme}://{parsed.netloc}{parsed.path or '/'}"
        params = {"q": XSS_PAYLOAD}
        full = base + "?" + urlencode(params)
        r = requests.get(full, timeout=timeout, allow_redirects=True)
        if XSS_PAYLOAD in r.text:
            return {"url": full, "vuln": "XSS", "evidence": "payload reflected in response"}
    except Exception:
        pass
    return None

def simple_sqli_test(url, timeout=6):
    """
    Test SQLi by injecting a simple payload into 'id' and/or 'q' param.
    Look for common SQL error messages or obvious content changes.
    """
    try:
        parsed = urlparse(url)
        base = f"{parsed.scheme}://{parsed.netloc}{parsed.path or '/'}"
        candidates = [{"id": SQLI_PAYLOAD}, {"q": SQLI_PAYLOAD}]
        for params in candidates:
            full = base + "?" + urlencode(params)
            r = requests.get(full, timeout=timeout, allow_redirects=True)
            text = r.text.lower()
            for err in SQL_ERRORS:
                if err in text:
                    return {"url": full, "vuln": "SQLi", "evidence": err}
            # crude content-length heuristic: large change could indicate injection but avoid false positives
            if len(r.text) > 10000:
                return {"url": full, "vuln": "SQLi-suspect", "evidence": "large response length"}
    except Exception:
        pass
    return None

def scan_targets_for_vulns(target_urls):
    """
    target_urls: list of URL strings (root + discovered dirs)
    Returns dict with header_issues, xss, sqli
    """
    results = {"headers": [], "xss": [], "sqli": []}
    checked = set()
    for url in target_urls:
        if url in checked:
            continue
        checked.add(url)
        # headers
        hdr = check_security_headers(url)
        results["headers"].append(hdr)
        # xss
        x = simple_xss_test(url)
        if x:
            results["xss"].append(x)
        # sqli
        s = simple_sqli_test(url)
        if s:
            results["sqli"].append(s)
    return results
