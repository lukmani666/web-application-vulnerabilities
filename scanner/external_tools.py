import subprocess
import requests
import json


def run_nmap_scan(target):
    print(f"[*] Running Nmap scan on {target}...")
    result = subprocess.run(["nmap", "-sV", target], capture_output=True, text=True)
    print(result.stdout)


def run_burp_scan(target):
    print(f"[*] Initiating Burp scan on {target}...")
    headers = {'Content-Type': 'application/json'}
    data = {"url": target, "scanConfiguration": {"type": "Passive"}}
    response = requests.post("http://localhost:8080/burp/v1/scans", headers=headers, data=json.dumps(data))

    if response.status_code == 200:
        print(f"[+] Burp scan started for {target}")
    else:
        print(f"[!] Failed to start Burp scan for {target}")