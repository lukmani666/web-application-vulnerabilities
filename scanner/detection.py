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
        "<script>alert('XSS)</script>",
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

