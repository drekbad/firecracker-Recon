import os, subprocess, requests, re, json, csv, socket
from bs4 import BeautifulSoup
from datetime import datetime

# CONFIG - Change these if needed
TARGET_PORTS = "21,22,23,25,53,69,80,135,137,139,143,161,443,500,587,1433,3000,3306,3389,5000,8000,8080,8443,9000,10000"
USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Pentest-Firecracker/3.0"

class FirecrackerV3:
    def __init__(self, domain):
        self.domain = domain
        self.subdomains = {domain}
        self.results = []
        self.email_security = {}

    def log(self, msg):
        print(f"[*] {msg}")

    def get_subdomains(self):
        self.log(f"Hunting for subdomains of {self.domain}...")
        
        # 1. crt.sh (Aggressive search)
        try:
            r = requests.get(f"https://crt.sh/?q=%.{self.domain}&output=json", timeout=15)
            for entry in r.json():
                name = entry['name_value'].lower()
                for sub in name.split('\n'):
                    if self.domain in sub:
                        self.subdomains.add(sub.replace('*.', ''))
        except: pass

        # 2. DNSRecon (Kali native)
        try:
            subprocess.run(["dnsrecon", "-d", self.domain, "-t", "std", "--json", "tmp.json"], 
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            if os.path.exists("tmp.json"):
                with open("tmp.json") as f:
                    for item in json.load(f):
                        if 'name' in item: self.subdomains.add(item['name'].lower())
                os.remove("tmp.json")
        except: pass
        self.log(f"Found {len(self.subdomains)} potential targets.")

    def audit_email_security(self):
        """Detailed SPF/DMARC/DKIM lookup"""
        self.log("Evaluating Email Security...")
        # Using dig for raw output
        spf = subprocess.getoutput(f"dig TXT {self.domain} +short")
        dmarc = subprocess.getoutput(f"dig TXT _dmarc.{self.domain} +short")
        
        is_spoofable = "NO"
        reason = "Secure"
        
        if "v=spf1" not in spf:
            is_spoofable, reason = "YES", "Missing SPF"
        elif "~all" in spf:
            is_spoofable, reason = "YES", "SoftFail (~all)"
        elif "p=none" in dmarc:
            is_spoofable, reason = "YES", "DMARC p=none"
        
        self.email_security = {"SPF": spf, "DMARC": dmarc, "Spoofable": is_spoofable, "Reason": reason}

    def deep_web_audit(self, url):
        findings = []
        try:
            res = requests.get(url, timeout=5, verify=False, headers={'User-Agent': USER_AGENT})
            soup = BeautifulSoup(res.text, 'html.parser')
            
            # 1. Check for Login Forms
            if soup.find('input', {'type': 'password'}) or re.search(r'login|signin', res.text, re.I):
                findings.append("LOGIN_PAGE_DETECTED")

            # 2. Check for WordPress/CMS
            if "wp-content" in res.text:
                findings.append("WORDPRESS_DETECTED")

            # 3. Robots.txt Analysis
            rob = requests.get(f"{url}/robots.txt", timeout=3, verify=False)
            if rob.status_code == 200:
                interesting = [l for l in rob.text.split('\n') if "Disallow" in l and not l.endswith('/')]
                if interesting: findings.append(f"ROBOTS_DATA({len(interesting)} paths)")

            # 4. User Enum Check (Ambiguous Forgot Password)
            for path in ['/forgot-password', '/reset', '/wp-login.php?action=lostpassword']:
                f_res = requests.post(f"{url}{path}", data={'user': 'fakeuser123@gmail.com'}, timeout=2)
                if f_res.status_code == 200 and "not found" not in f_res.text.lower():
                    findings.append("POTENTIAL_USER_ENUM")
                    break
        except: pass
        return " | ".join(findings) if findings else "None Detected"

    def scan_host(self, host):
        self.log(f"Scanning {host}...")
        try:
            ip = socket.gethostbyname(host)
        except: return None

        # Nmap with Banner Grabbing
        nm_cmd = f"nmap -sV --version-intensity 5 -T4 -p{TARGET_PORTS} {ip}"
        nm_out = subprocess.getoutput(nm_cmd)
        open_ports = re.findall(r"(\d+/tcp\s+open\s+\S+)", nm_out)

        # Shodan Scraper (No API needed for basic ports)
        shodan_ports = "Unknown"
        try:
            s_res = requests.get(f"https://www.shodan.io/host/{ip}", timeout=5)
            shodan_ports = ", ".join(re.findall(r"<li>(\d+)</li>", s_res.text))
        except: pass

        return {
            "FQDN": host,
            "IP": ip,
            "Open Ports": ", ".join(open_ports),
            "Web Intel": self.deep_web_audit(f"http://{host}"),
            "Shodan History": shodan_ports if shodan_ports else "None"
        }

    def run(self):
        self.get_subdomains()
        self.audit_email_security()
        
        for sub in list(self.subdomains):
            data = self.scan_host(sub)
            if data: self.results.append(data)
        
        self.export_html()

    def export_html(self):
        report_name = f"Pentest_{self.domain}.html"
        with open(report_name, "w") as f:
            f.write(f"""
            <html><head><style>
                body {{ font-family: Arial; background: #f4f4f4; padding: 20px; }}
                table {{ border-collapse: collapse; width: 100%; background: white; }}
                th, td {{ border: 1px solid #ddd; padding: 12px; text-align: left; }}
                th {{ background-color: #2c3e50; color: white; }}
                .high {{ color: red; font-weight: bold; }}
            </style></head><body>
            <h2>Executive Summary: {self.domain}</h2>
            <table>
                <tr><th>Email Security</th><td>{self.email_security['Spoofable']} ({self.email_security['Reason']})</td></tr>
                <tr><th>SPF Record</th><td><code>{self.email_security['SPF']}</code></td></tr>
                <tr><th>DMARC Record</th><td><code>{self.email_security['DMARC']}</code></td></tr>
            </table>
            <br>
            <h2>Infrastructure Inventory</h2>
            <table>
                <tr><th>FQDN</th><th>IP</th><th>Nmap (Active)</th><th>Web Intel</th><th>Shodan (Passive)</th></tr>
            """)
            for r in self.results:
                f.write(f"<tr><td>{r['FQDN']}</td><td>{r['IP']}</td><td>{r['Open Ports']}</td><td>{r['Web Intel']}</td><td>{r['Shodan History']}</td></tr>")
            f.write("</table></body></html>")
        self.log(f"REPORT GENERATED: {report_name}")

if __name__ == "__main__":
    target = input("Enter target domain: ")
    FirecrackerV3(target).run()
