# 🌑 ShadowRecon

### 🔥 Automated Recon & Web Vulnerability Scanner

**Created by Mohid**

ShadowRecon is a Python-based reconnaissance and vulnerability scanning toolkit designed for pentesters, bug bounty hunters, and cybersecurity learners.
It combines **subdomain enumeration, DNS resolution, port scanning, directory discovery, and vulnerability detection** into one streamlined tool.

---

# 🚀 Features

### 🔎 **Subdomain Enumeration**

* Uses Certificate Transparency logs (`crt.sh`)
* Fast & lightweight
* Removes duplicates and wildcard entries

### 🌐 **DNS Resolution**

* Resolves subdomains → IP addresses
* Filters out dead subdomains

### 🚪 **Port Scanning**

* Scans top/common ports
* Detects open/closed/filtered states
* Fast sockets-based scanning

### 📂 **Directory Bruteforce**

* Multithreaded directory discovery
* Uses lightweight built-in wordlist
* Detects valid accessible URLs

### 🛡 **Vulnerability Scanning**

Includes checks for:

* Reflected XSS
* SQL Injection error-based detection
* HTTP Security Headers (Missing CSP, HSTS, X-Frame, etc.)

### 📁 **Automatic Output Saving**

All results saved to:

```
output/<target>/
    ├── subdomains.txt
    ├── dns_resolved.txt
    ├── open_ports.txt
    ├── directories.txt
    └── vulnerabilities.txt
```

---

# 📁 **Project Structure**

```
ShadowRecon/
│
├── ShadowRecon.py
├── README.md
├── requirements.txt
├── LICENSE
│
└── modules/
    ├── __init__.py
    ├── subdomain_enum.py
    ├── dns_resolver.py
    ├── port_scanner.py
    ├── dir_bruteforce.py
    ├── vuln_scanner.py
    └── output_handler.py
```

---

# 🛠 Installation

### **Clone the repository**

```bash
git clone https://github.com/MohidRizwan/ShadowRecon
cd ShadowRecon
```

### **Install dependencies**

```bash
pip install -r requirements.txt
```

---

# 🏃 Usage

### **Basic scan**

```bash
python ShadowRecon.py -t example.com
```

### **Only subdomains**

```bash
python ShadowRecon.py -t example.com --subs
```

### **Only port scan**

```bash
python ShadowRecon.py -t example.com --ports
```

### **Only directory scan**

```bash
python ShadowRecon.py -t example.com --dirs
```

### **Only vulnerability scan**

```bash
python ShadowRecon.py -t example.com --vulns
```

### **Scan using specific wordlist**

```bash
python ShadowRecon.py -t example.com --wordlist wordlists/common.txt
```

### **Save output to custom folder**

```bash
python ShadowRecon.py -t example.com -o results/
```

---

# 📌 Examples

### **Full Recon**

```
python ShadowRecon.py -t tesla.com
```

### **Directory scan with threads**

```
python ShadowRecon.py -t site.com --dirs --threads 20
```


# 🧪 Vulnerability Checks Explanation

### 🔸 **XSS Test**

* Sends payload: `<script>alert(1)</script>`
* Checks if reflected in response

### 🔸 **SQLi Errors**

Searches for:

* `You have an error in your SQL syntax`
* `SQLSTATE`
* `Warning: mysql`
* `syntax error`

### 🔸 **Security Header Scanner**

Checks if headers are missing:

* `Content-Security-Policy`
* `X-Frame-Options`
* `Strict-Transport-Security`
* `X-XSS-Protection`

---

# 📝 requirements.txt

```
requests
dnspython
```

(Add wordlists optionally later)

---

# ⚠️ Legal Disclaimer

ShadowRecon is built **for educational and ethical security testing only**.
Use it **only on systems you own or have explicit permission to test**.
The author takes no responsibility for misuse.

---

# ⭐ Contributions

Pull requests are welcome!
Open an issue first to describe features or bugs.

---

# ❤️ Author

**Mohid**
Python Developer | Cybersecurity Student | Bug Bounty Learner

---
