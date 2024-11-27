mitigation_guidance = {
    "SQL Injection": "Use parameterized queries and avoid dynamic SQL.",
    "XSS": "Escape user input before rendering on the page. Use Content Security Policy (CSP).",
    "CSRF": "Include anti-csrf tokens in form and verify their presence.",
    "Open Redirect": "Validate URLs and disallow redirects to external domains."
}

def provide_mitigation(vuln_type):
    print(f"Mitigation for {vuln_type}: {mitigation_guidance.get(vuln_type, 'No guidance available.')}")