import requests
from bs4 import BeautifulSoup # type: ignore

def detect_sql_injection(url):
    sqli_payloads = ["' OR 1=1 --", "' OR 'a'='a'", "' AND 1=2 --", "' OR '1'='1'"]
    vulnerable = False

    for payload in sqli_payloads:
        target_url = f"{url}?id={payload}"
        try:
            response = requests.get(target_url)
            if any(err in response.text for err in ["SQL syntax", "mysql_fetch", "SQL error"]):
                print(f"[!] SQL Injection vulnerability detected with payload: {payload}")
                vulnerable = True
                break
        except requests.RequestException as e:
            print(f"Error accessing {url}: {e}")
    
    if not vulnerable: 
        print("[*] No SQL Injection vulnerabilities detected.")
    
    return vulnerable


def detect_xss(url):
    xss_payloads = [
        "<script>alert('XSS')</script>",
        "<img src=x onerror=alert(1)>",
        "<svg/onload=alert(1)>"
    ]
    vulnerable = False

    for payload in xss_payloads:
        target_url = f"{url}?q={payload}"
        try:
            response = requests.get(target_url)
            if payload in response.text:
                print(f"[!] XSS vulnerability detected with payload: {payload}")
                vulnerable = True
                break
        except requests.RequestException as e:
            print(f"Error accessing {url}: {e}")

    if not vulnerable:
        print("[*] No XSS vulnerabilities detected.")
    return vulnerable


def detect_lfi(url):
    lfi_payloads = ["../../../../etc/passwd", "../../../../../../windows/win.ini"]
    vulnerable = False

    for payload in lfi_payloads:
        target_url = f"{url}?file={payload}"
        try:
            response = requests.get(target_url)
            if "root" in response.text or "[fonts]" in response.text:
                print(f"[!] LFI vulnerability detected with payload: {payload}")
                vulnerable = True
                break
        except requests.RequestException as e:
            print(f"Error accessing {url}: {e}")
    
    if not vulnerable:
        print("[*] No Local File Inclusion vulnerabilities detect.")
    return vulnerable


def detect_csrf(url):
    response = requests.get(url)
    soup = BeautifulSoup(response.text, 'html.parser')
    forms = soup.find_all('form')
    vulnerable = False

    for form in forms:
        inputs = form.find_all('input')
        token_found = False
        for input_tag in inputs:
            if 'csrf' in input_tag.get('name', '').lower():
                token_found = True
                break
        
        if not token_found:
            print(f"[!] CSRF vulnerability detected in form at {url}")
            return vulnerable
        
    if not vulnerable:
        print("[*] No CSRF vulnerabilities detected.")
    return vulnerable


def detect_open_redirect(url):
    payloads = ["//evil.com", "https://evil.com"]
    vulnerable = False

    for payload in payloads:
        target_url = url + payloads
        response = requests.get(target_url, allow_redirects=True)

        if response.history and "evil.com" in response.url:
            print(f"[!] Open redirect vulnerability detected with payload: {payload}")
            vulnerable = True
            break

    if not vulnerable:
        print("[*] No open redirect vulnerabilities detected.")
    
    return vulnerable