````markdown
# 🐺 ShadowHound v1

> **Advanced Black-Box Reconnaissance Toolkit for Ethical Hackers & Red Teamers**

ShadowHound is a modular, stealth-focused reconnaissance and vulnerability discovery suite built with Python. It’s tailored for black-box penetration testing, red teaming operations, and bug bounty recon — with support for web scanning, endpoint fuzzing, XSS analysis, git leak detection, and more.

🚨 **For authorized use only. This tool is intended strictly for legal security research and educational purposes.**

---

## 🧰 Features

| Module       | Description                                                                 |
|--------------|-----------------------------------------------------------------------------|
| `webscan`    | Subdomain enumeration + tech stack & header analysis                        |
| `netrecon`   | Network scanning, host discovery, and service enumeration using Nmap        |
| `jsdig`      | JavaScript endpoint extraction + API link harvesting                        |
| `aslookup`   | Shodan-based ASN, IP, and port intel discovery for organizations            |
| `gitleaks`   | Git repository scanner for API keys, tokens, secrets, and credentials       |
| `xssfinder`  | Reflected and DOM-based XSS testing with custom fuzzing payloads            |
| `dirbuster`  | Stealthy brute-forcing of hidden or restricted directories and endpoints    |

---

## 📦 Installation

### ✅ 1. Clone the Repo

```bash
git clone https://github.com/yourusername/shadowhound.git
cd shadowhound
````

### ✅ 2. Install Dependencies

```bash
pip install -r requirements.txt
```

> Python 3.7+ required.

---

## 🚀 Usage

```bash
python3 shadowhound.py <module> [options]
```

### 🔍 Examples

```bash
# Web scanning and subdomain enumeration
python3 shadowhound.py webscan example.com

# Network scanning
python3 shadowhound.py netrecon 192.168.1.0/24

# JavaScript endpoint discovery
python3 shadowhound.py jsdig https://example.com

# Shodan ASN/IP lookup
python3 shadowhound.py aslookup "Google LLC"

# Git secrets detection
python3 shadowhound.py gitleaks https://github.com/user/repo.git

# XSS scanning with custom fuzzing
python3 shadowhound.py xssfinder "https://example.com/search?q=test" --deep

# Directory brute-forcing with custom wordlist
python3 shadowhound.py dirbuster example.com --wordlist payloads/common.txt
```

---

## 🗝️ Shodan Configuration

If using the `aslookup` module:

```bash
# Set your Shodan API Key
export SHODAN_API_KEY="your_api_key"
```

Or update it directly in `shadowhound.py`.

---

## 📁 Project Structure

```
shadowhound/
├── shadowhound.py      # Main CLI + modules
├── requirements.txt     # Python dependencies
└── README.md            # This file
```

---

## 📜 License

MIT License

---

## 🙋‍♂️ Author

Built by **Faheem Musthafa C.P** — for the cyber warriors, the red teamers, the relentless.

> Feel free to fork, contribute, and improve. Pull requests welcome!


