import requests

def enumerate_subdomains(domain):
    print(f"[INFO] Enumerating subdomains for {domain} using crt.sh...")

    url = f"https://crt.sh/?q=%25.{domain}&output=json"

    try:
        response = requests.get(url, timeout=10)
        if response.status_code != 200:
            print("[ERROR] Failed to fetch data from crt.sh")
            return []

        data = response.json()
        subdomains = set()

        for entry in data:
            name = entry["name_value"]
            if "*" not in name:
                subdomains.add(name)

        return sorted(subdomains)

    except Exception as e:
        print(f"[ERROR] {e}")
        return []
