import argparse
from scanner.detection import detect_sql_injection, detect_xss, detect_lfi, detect_csrf, detect_open_redirect
from scanner.external_tools import run_burp_scan, run_nmap_scan
from scanner.mitigation import provide_mitigation


def main():
    parser = argparse.ArgumentParser(description="Web Vulnerablity Scanner")
    parser.add_argument("--url", help="Target URL", required=True)
    parser.add_argument("--scan", help="Type of scan: sql, xss, lfi, csrf, open-redirect", required=True)
    parser.add_argument("--nmap", help="Run Nmap scan on the target", action="store_true")
    parser.add_argument("--burp", help="Run Burp Suite scan on the target", action="store_true")

    args = parser.parse_args()

    if args.scan == "sql":
        vuln_detected = detect_sql_injection(args.url)
        provide_mitigation("SQL Injection") if vuln_detected else None
    elif args.scan == "xss":
        vuln_detected = detect_xss(args.url)
        provide_mitigation("XSS") if vuln_detected else None
    elif args.scan == "lfi":
        vuln_detected = detect_lfi(args.url)
        provide_mitigation("LFI") if vuln_detected else None
    elif args.scan == "csrf":
        vuln_detected = detect_csrf(args.url)
        provide_mitigation("CSRF") if vuln_detected else None
    elif args.scan == "open-redirect":
        vuln_detected = detect_open_redirect(args.url)
        provide_mitigation("Open Redirect") if vuln_detected else None
    else:
        print("Invalid scan type specified!")
    
    if args.nmap:
        run_nmap_scan(args.url)
    
    if args.burp:
        run_burp_scan(args.url)
    

if __name__ == "__main__":
    main()