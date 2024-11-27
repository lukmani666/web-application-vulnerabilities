import tkinter as tk
from scanner.detection import detect_sql_injection, detect_xss, detect_lfi, detect_csrf, detect_open_redirect
from scanner.external_tools import run_burp_scan, run_nmap_scan
from scanner.mitigation import provide_mitigation


def run_scan():
    url = url_entry.get()
    scan_type = scan_var.get()

    if scan_type == "SQL Injection":
        vuln_detected = detect_sql_injection(url)
        provide_mitigation("SQL Injection") if vuln_detected else None
    elif scan_type == "XSS":
        vuln_detected = detect_xss(url)
        provide_mitigation("XSS") if vuln_detected else None
    elif scan_type == "LFI":
        vuln_detected = detect_lfi(url)
        provide_mitigation("LFI") if vuln_detected else None
    elif scan_type == "CSRF":
        vuln_detected = detect_csrf(url)
        provide_mitigation("CSRF") if vuln_detected else None
    elif scan_type == "Open-Redirect":
        vuln_detected = detect_open_redirect(url)
        provide_mitigation("Open Redirect") if vuln_detected else None
    else:
        print("Invalid scan type specified!")


def run_nmap():
    url = url_entry.get()
    run_nmap_scan(url)


def run_burp():
    url = url_entry.get()
    run_burp_scan()


root = tk.Tk()
root.title("Web Vulnerability Scanner")

tk.Label(root, text="Target URL:").pack()
url_entry = tk.Entry(root).pack()

scan_var = tk.StringVar(root)
scan_var.set("SQL Injection")

tk.OptionMenu(root, scan_var, "SQL Injection", "XSS", "LFI", "CSRF", "Open Redirect").pack()

tk.Button(root, text="Run Scan", command=run_scan).pack()

tk.Button(root, text="Run Nmap Scan", command=run_nmap).pack()
tk.Button(root, text="Run Burp Suite Scan", command=run_burp).pack()

root.mainloop()
