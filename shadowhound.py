#!/usr/bin/env python3

import argparse
import sys
import requests
import dns.resolver
import socket
import subprocess
import json
import re
from urllib.parse import urlparse
import os
import nmap
import shodan
import shutil
import warnings
from bs4 import BeautifulSoup
import signal
import random
import time
from concurrent.futures import ThreadPoolExecutor
import base64

# Suppress warnings for cleaner output
warnings.filterwarnings("ignore")

def signal_handler(sig, frame):
    print("\n[!] Operation cancelled by user")
    sys.exit(0)

signal.signal(signal.SIGINT, signal_handler)

def show_banner():
    print(r"""
   ███████╗██╗  ██╗ █████╗ ██████╗  ██████╗ ██╗    ██╗
   ██╔════╝██║  ██║██╔══██╗██╔══██╗██╔═══██╗██║    ██║
   ███████╗███████║███████║██║  ██║██║   ██║██║ █╗ ██║
   ╚════██║██╔══██║██╔══██║██║  ██║██║   ██║██║███╗██║
   ███████║██║  ██║██║  ██║██████╔╝╚██████╔╝╚███╔███╔╝
   ╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝  ╚═════╝  ╚══╝╚══╝ 
                                                    
      ShadowHound - ReconOps Framework
    ⚔️  GitHub: https://github.com/Faheem-Musthafa
""")


def random_delay(max_seconds=3):
    """Add random delay to avoid pattern detection"""
    time.sleep(random.uniform(0.5, max_seconds))

def random_user_agent():
    """Return a random user agent from a list of common browsers"""
    agents = [
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0.3 Safari/605.1.15',
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0',
        'Mozilla/5.0 (iPhone; CPU iPhone OS 14_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0 Mobile/15E148 Safari/604.1'
    ]
    return random.choice(agents)

def check_internet():
    try:
        requests.get('https://google.com', timeout=3)
        return True
    except:
        print("[-] No internet connection detected")
        return False

def stealthy_request(url, method='GET', **kwargs):
    """Make a request with random delays and user agents"""
    headers = kwargs.get('headers', {})
    headers['User-Agent'] = random_user_agent()
    kwargs['headers'] = headers
    
    # Add random delay between requests
    random_delay()
    
    try:
        if method.upper() == 'GET':
            return requests.get(url, **kwargs)
        elif method.upper() == 'POST':
            return requests.post(url, **kwargs)
    except Exception as e:
        print(f"[-] Request failed: {str(e)}")
        return None

def webscan(target):
    """Comprehensive web reconnaissance including subdomains, technologies, and common vulnerabilities"""
    print(f"[+] Starting Web Recon on {target}")
    
    if not check_internet():
        return
    
    # Subdomain enumeration
    print("\n[+] Running subdomain enumeration...")
    try:
        subdomains = set()
        crt_url = f"https://crt.sh/?q=%25.{target}&output=json"
        response = stealthy_request(crt_url)
        if response and response.status_code == 200:
            data = json.loads(response.text)
            for item in data:
                subdomains.add(item['name_value'].lower())
        
        print(f"[+] Found {len(subdomains)} subdomains:")
        for i, sub in enumerate(sorted(subdomains), 1):
            print(f"  {i}. {sub}")
    except Exception as e:
        print(f"[-] Subdomain enumeration failed: {str(e)}")
    
    # Web technology detection
    print("\n[+] Detecting web technologies...")
    try:
        url = f"http://{target}" if not target.startswith(('http://', 'https://')) else target
        resp = stealthy_request(url, verify=False, timeout=5)
        
        if resp:
            server = resp.headers.get('Server', 'Not detected')
            x_powered_by = resp.headers.get('X-Powered-By', 'Not detected')
            
            print(f"  Server: {server}")
            print(f"  X-Powered-By: {x_powered_by}")
            
            # Check for common vulnerabilities
            if 'X-XSS-Protection' not in resp.headers:
                print("  [!] Missing X-XSS-Protection header")
            if 'Content-Security-Policy' not in resp.headers:
                print("  [!] Missing Content-Security-Policy header")
    except Exception as e:
        print(f"[-] Web tech detection failed: {str(e)}")

def netrecon(target):
    """Network reconnaissance including host discovery and service enumeration"""
    print(f"[+] Starting Network Recon on {target}")
    
    try:
        nm = nmap.PortScanner()
        
        print("\n[+] Running quick host discovery...")
        nm.scan(hosts=target, arguments='-sn')
        for host in nm.all_hosts():
            print(f"  Host: {host} ({nm[host].hostname()})")
            print(f"  State: {nm[host].state()}")
            
            mac = nm[host]['addresses'].get('mac')
            if mac:
                print(f"  MAC: {mac}")
                vendor = nm[host]['vendor'].get(mac, 'Unknown')
                print(f"  Vendor: {vendor}")
        
        print("\n[+] Running service detection scan...")
        nm.scan(hosts=target, arguments='-sV -T4')
        for host in nm.all_hosts():
            print(f"\nScan results for {host}:")
            for proto in nm[host].all_protocols():
                print(f"\nProtocol: {proto}")
                ports = nm[host][proto].keys()
                for port in sorted(ports):
                    service = nm[host][proto][port]
                    print(f"  Port: {port}\tState: {service['state']}\tService: {service['name']}\tVersion: {service.get('product', '')} {service.get('version', '')}")
    except Exception as e:
        print(f"[-] Network recon failed: {str(e)}")

def jsdig(target):
    """JavaScript endpoint extraction and analysis"""
    print(f"[+] JS Endpoint extraction from {target}")
    
    if not check_internet():
        return
    
    try:
        url = f"http://{target}" if not target.startswith(('http://', 'https://')) else target
        resp = stealthy_request(url, verify=False, timeout=5)
        
        if not resp:
            return
            
        # Find all script tags
        soup = BeautifulSoup(resp.text, 'html.parser')
        scripts = soup.find_all('script')
        
        endpoints = set()
        patterns = [
            r'[\'"](\/.*?)[\'"]',
            r'[\'"](https?:\/\/.*?)[\'"]',
            r'[\'"](\/[a-zA-Z0-9_\-\.\/]+\.(js|json|php|asp|aspx|jsp|action|do))[\'"]'
        ]
        
        for script in scripts:
            if script.get('src'):
                js_url = script['src']
                if not js_url.startswith(('http://', 'https://')):
                    js_url = url + ('' if js_url.startswith('/') else '/') + js_url
                print(f"\n[+] Found external JS: {js_url}")
                
                try:
                    js_resp = stealthy_request(js_url, verify=False, timeout=5)
                    if js_resp:
                        for pattern in patterns:
                            matches = re.findall(pattern, js_resp.text)
                            for match in matches:
                                if isinstance(match, tuple):
                                    endpoint = match[0]
                                else:
                                    endpoint = match
                                if not endpoint.startswith(('http://', 'https://')):
                                    endpoint = url + ('' if endpoint.startswith('/') else '/') + endpoint
                                endpoints.add(endpoint)
                except:
                    continue
        
        print("\n[+] Found endpoints in JavaScript files:")
        for i, endpoint in enumerate(sorted(endpoints), 1):
            print(f"  {i}. {endpoint}")
            
    except Exception as e:
        print(f"[-] JS endpoint extraction failed: {str(e)}")

def aslookup(org):
    """ASN and IP lookup for an organization using Shodan"""
    print(f"[+] ASN Lookup for org: {org}")
    
    if not check_internet():
        return
    
    try:
        SHODAN_API_KEY = "Get your own API key from Shodan"  # Should be configured in environment variables
        if not SHODAN_API_KEY:
            print("[-] Shodan API key not configured")
            return
            
        api = shodan.Shodan(SHODAN_API_KEY)
        results = api.search(f'org:"{org}"')
        
        print(f"\n[+] Found {results['total']} results for {org}")
        
        asns = set()
        ips = set()
        ports = set()
        
        for result in results['matches']:
            if 'asn' in result:
                asns.add(result['asn'])
            if 'ip_str' in result:
                ips.add(result['ip_str'])
            if 'port' in result:
                ports.add(result['port'])
        
        print("\n[+] ASNs found:")
        for asn in sorted(asns):
            print(f"  {asn}")
            
        print("\n[+] Sample IP addresses:")
        for i, ip in enumerate(sorted(ips)[:10], 1):
            print(f"  {i}. {ip}")
            
        print("\n[+] Common ports found:")
        for port in sorted(ports):
            print(f"  {port}")
            
    except Exception as e:
        print(f"[-] ASN lookup failed: {str(e)}")

def gitleaks(repo_url):
    """Git repository secret scanning"""
    print(f"[+] Scanning repo {repo_url} for leaked secrets")
    
    if not check_internet():
        return
    
    try:
        # Clone repo to temp directory
        repo_name = repo_url.split('/')[-1].replace('.git', '')
        temp_dir = f"/tmp/{repo_name}"
        
        if os.path.exists(temp_dir):
            shutil.rmtree(temp_dir)
            
        print(f"\n[+] Cloning repository to {temp_dir}")
        subprocess.run(['git', 'clone', '--depth', '1', repo_url, temp_dir], check=True)
        
        # Common secret patterns
        patterns = {
            'AWS Keys': r'(A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}',
            'Google API': r'AIza[0-9A-Za-z\\-_]{35}',
            'SSH Private Key': r'-----BEGIN (RSA|DSA|EC|OPENSSH) PRIVATE KEY-----',
            'Database URLs': r'(postgres|mysql|mongodb)://[a-zA-Z0-9_]+:[a-zA-Z0-9_]+@[a-zA-Z0-9_.-]+/[a-zA-Z0-9_]+',
            'API Keys': r'(?i)(api|access|secret|token|key)[_ -]?key["\']?\\s*[:=]\\s*["\'][a-z0-9]{20,}["\']',
            'Passwords': r'(?i)password["\']?\\s*[:=]\\s*["\'][^"\']{6,}["\']'
        }
        
        print("\n[+] Scanning for secrets...")
        found = False
        
        for root, dirs, files in os.walk(temp_dir):
            for file in files:
                if file.endswith(('.git', '.gitignore', '.DS_Store')):
                    continue
                    
                file_path = os.path.join(root, file)
                try:
                    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read()
                        for name, pattern in patterns.items():
                            matches = re.findall(pattern, content)
                            if matches:
                                found = True
                                print(f"\n[!] Found potential {name} in {file_path}:")
                                for match in matches[:3]:  # Show first 3 matches
                                    print(f"  {match}")
                except:
                    continue
        
        if not found:
            print("[-] No obvious secrets found")
            
        # Clean up
        shutil.rmtree(temp_dir)
        
    except Exception as e:
        print(f"[-] Git leaks scan failed: {str(e)}")
        if 'temp_dir' in locals() and os.path.exists(temp_dir):
            shutil.rmtree(temp_dir)

def xssfinder(url, deep=False, payload_file=None):
    """Enhanced XSS vulnerability scanner with stealth techniques"""
    print(f"[+] Finding XSS vectors in {url}")
    
    if not check_internet():
        return
    
    try:
        if not url.startswith(('http://', 'https://')):
            url = f"http://{url}"
            
        # Load payloads
        payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "\"><script>alert('XSS')</script>",
            "javascript:alert('XSS')",
            "onmouseover=alert('XSS')"
        ]
        
        # Add payload variations
        encoded_payloads = []
        for payload in payloads:
            encoded_payloads.append(base64.b64encode(payload.encode()).decode())
            encoded_payloads.append("".join([f"&#{ord(c)};" for c in payload]))
        
        payloads.extend(encoded_payloads)
        
        # Load custom payloads if specified
        if payload_file and os.path.isfile(payload_file):
            with open(payload_file, 'r') as f:
                custom_payloads = [line.strip() for line in f if line.strip()]
                payloads.extend(custom_payloads)
        
        # Test for reflected parameters
        parsed = urlparse(url)
        params = {}
        if parsed.query:
            params = dict(pair.split('=') for pair in parsed.query.split('&'))
        
        if not params:
            print("[-] No query parameters found to test")
            return
            
        print("\n[+] Testing for reflected XSS:")
        vulnerable = False
        
        for param in params:
            for payload in payloads:
                test_url = url.replace(f"{param}={params[param]}", f"{param}={payload}")
                
                try:
                    resp = stealthy_request(test_url, verify=False, timeout=5)
                    if resp and payload in resp.text:
                        vulnerable = True
                        print(f"[!] Parameter '{param}' appears vulnerable to reflected XSS")
                        print(f"    Payload: {payload}")
                        print(f"    Test URL: {test_url}")
                        break  # Stop after first successful payload for this param
                except:
                    continue
        
        if not vulnerable:
            print("[-] No reflected XSS vulnerabilities found")
            
        # Deep scan checks
        if deep:
            print("\n[+] Running deep scan checks...")
            
            # Check for DOM-based XSS sinks
            print("\n[+] Checking for DOM XSS sinks...")
            try:
                resp = stealthy_request(url, verify=False, timeout=5)
                if resp:
                    dom_sinks = [
                        'document.write',
                        'document.writeln',
                        'innerHTML',
                        'outerHTML',
                        'eval(',
                        'setTimeout(',
                        'setInterval(',
                        'Function('
                    ]
                    
                    found_sinks = []
                    for sink in dom_sinks:
                        if sink in resp.text:
                            found_sinks.append(sink)
                    
                    if found_sinks:
                        print("[!] Potential DOM XSS sinks found:")
                        for sink in found_sinks:
                            print(f"  {sink}")
                    else:
                        print("[-] No common DOM XSS sinks found")
                    
                    # Check for AngularJS injection points
                    if 'ng-app' in resp.text:
                        print("[!] AngularJS application detected - potential injection point")
                
            except Exception as e:
                print(f"[-] DOM XSS check failed: {str(e)}")
            
    except Exception as e:
        print(f"[-] XSS scan failed: {str(e)}")

def dirbuster(target, wordlist=None):
    """Stealthy directory brute-forcing with random delays"""
    print(f"[+] Starting directory brute-force on {target}")
    
    if not check_internet():
        return
    
    try:
        url = f"http://{target}" if not target.startswith(('http://', 'https://')) else target
        if not url.endswith('/'):
            url += '/'
        
        # Default wordlist if none provided
        if not wordlist:
            wordlist = [
                'admin', 'login', 'wp-admin', 'wp-login', 'config', 'backup',
                'test', 'secret', 'api', 'docs', 'phpmyadmin', 'dbadmin',
                'assets', 'images', 'uploads', 'downloads', 'cgi-bin'
            ]
        
        print(f"[+] Testing {len(wordlist)} common directories...")
        
        def test_directory(path):
            test_url = url + path
            resp = stealthy_request(test_url, allow_redirects=False)
            if resp:
                if resp.status_code == 200:
                    print(f"[+] Found: {test_url} (200 OK)")
                elif resp.status_code in (301, 302, 307, 308):
                    print(f"[+] Found: {test_url} ({resp.status_code} -> {resp.headers.get('Location')})")
                elif resp.status_code == 403:
                    print(f"[!] Found (restricted): {test_url} (403 Forbidden)")
        
        # Use threading but with rate limiting
        with ThreadPoolExecutor(max_workers=3) as executor:
            executor.map(test_directory, wordlist)
            
    except Exception as e:
        print(f"[-] Directory brute-force failed: {str(e)}")

def main():
    show_banner()
    
    parser = argparse.ArgumentParser(
        description='Shadow - Advanced Black Box Web Attack Toolkit',
        epilog='WARNING: For authorized security testing only. Unauthorized use is prohibited.',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    subparsers = parser.add_subparsers(dest='command', required=True, title='commands',
                                     description='Available attack modules:')

    # webscan
    parser_web = subparsers.add_parser('webscan', 
                                      help='Comprehensive web reconnaissance (subdomains, technologies, vulnerabilities)')
    parser_web.add_argument('target', help='Target domain (e.g., example.com)')
    parser_web.add_argument('--stealth', action='store_true', 
                          help='Enable stealth mode with random delays')

    # netrecon
    parser_net = subparsers.add_parser('netrecon', 
                                      help='Network reconnaissance (host discovery, service enumeration)')
    parser_net.add_argument('target', help='Target IP/CIDR (e.g., 192.168.1.0/24)')

    # jsdig
    parser_js = subparsers.add_parser('jsdig', 
                                     help='JavaScript endpoint extraction and analysis')
    parser_js.add_argument('target', help='URL or domain (e.g., https://example.com)')

    # aslookup
    parser_as = subparsers.add_parser('aslookup', 
                                     help='ASN and IP lookup for an organization using Shodan')
    parser_as.add_argument('org', help='Organization name (e.g., "Google LLC")')

    # gitleaks
    parser_git = subparsers.add_parser('gitleaks', 
                                      help='Git repository secret scanning')
    parser_git.add_argument('repo', help='Repository URL (e.g., https://github.com/user/repo.git)')

    # xssfinder
    parser_xss = subparsers.add_parser('xssfinder', 
                                      help='XSS vulnerability scanner with stealth techniques')
    parser_xss.add_argument('url', help='Target URL with parameters (e.g., https://example.com/search?q=test)')
    parser_xss.add_argument('--deep', action='store_true', 
                          help='Enable deep scanning with more payloads')
    parser_xss.add_argument('--payloads', help='Custom XSS payload file path')

    # dirbuster
    parser_dir = subparsers.add_parser('dirbuster', 
                                      help='Stealthy directory brute-forcing')
    parser_dir.add_argument('target', help='Target URL or domain (e.g., example.com)')
    parser_dir.add_argument('--wordlist', help='Custom wordlist file path')

    args = parser.parse_args()
    
    if args.command == 'webscan':
        webscan(args.target)
    elif args.command == 'netrecon':
        netrecon(args.target)
    elif args.command == 'jsdig':
        jsdig(args.target)
    elif args.command == 'aslookup':
        aslookup(args.org)
    elif args.command == 'gitleaks':
        gitleaks(args.repo)
    elif args.command == 'xssfinder':
        xssfinder(args.url, args.deep, args.payloads)
    elif args.command == 'dirbuster':
        wordlist = None
        if args.wordlist and os.path.isfile(args.wordlist):
            with open(args.wordlist, 'r') as f:
                wordlist = [line.strip() for line in f if line.strip()]
        dirbuster(args.target, wordlist)

if __name__ == '__main__':
    main()