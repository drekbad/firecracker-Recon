import os, subprocess, requests, re, json, socket, argparse
from bs4 import BeautifulSoup
import urllib3

# Absolute silence for the terminal
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# --- CONFIGURATION ---
SHODAN_API_KEY = "YOUR_SHODAN_API_KEY" 
TARGET_PORTS = "21,22,23,25,53,69,80,135,137,139,143,161,443,500,587,1433,3000,3306,3389,5000,8000,8080,8443,9000,10000"

class FirecrackerV9:
    def __init__(self, domain, input_file=None):
        self.domain = domain
        self.subdomains = {domain}
        self.input_file = input_file
        self.results = []
        self.email_security = {}

    def log(self, msg):
        print(f"[*] {msg}")

    def get_subdomains(self):
        self.log(f"Aggressive hunting for {self.domain}...")
        
        # 1. CRT.SH - Pulling EVERYTHING related
        try:
            r = requests.get(f"https://crt.sh/?q=%.{self.domain}&output=json", timeout=20)
            if r.status_code == 200:
                for entry in r.json():
                    names = entry['name_value'].lower().split('\n')
                    for n in names:
                        self.subdomains.add(n.replace('*.', '').strip())
        except: pass

        # 2. DNSRecon (Kali native)
        try:
            subprocess.run(["dnsrecon", "-d", self.domain, "-t", "std", "--json", "tmp.json"], 
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            if os.path.exists("tmp.json"):
                with open("tmp.json") as f:
                    data = json.load(f)
                    for item in data:
                        if 'name' in item: self.subdomains.add(item['name'].lower())
                os.remove("tmp.json")
        except: pass

        # 3. Import External List (Manual overrides)
        if self.input_file and os.path.exists(self.input_file):
            with open(self.input_file, 'r') as f:
                for line in f:
                    if line.strip(): self.subdomains.add(line.strip().lower())

        self.log(f"Total Targets identified: {len(self.subdomains)}")

    def audit_email_security(self):
        self.log("Evaluating Email Security...")
        spf = subprocess.getoutput(f"dig TXT {self.domain} +short").replace('"', '').strip()
        dmarc = subprocess.getoutput(f"dig TXT _dmarc.{self.domain} +short").replace('"', '').strip()
        
        spoof, reason, ctx = "NO", "Strong Policy", "Records are present and restrictive."
        if not spf: spoof, reason = "YES", "Missing SPF"
        elif "~all" in spf: spoof, reason = "YES", "SoftFail (~all)"
        elif "p=none" in dmarc: spoof, reason = "YES", "DMARC p=none"

        self.email_security = {"Status": f"Spoofable: {spoof} ({reason})", "SPF": spf, "DMARC": dmarc, "Context": ctx}

    def deep_web_audit(self, url):
        findings = []
        try:
            # We must use a User-Agent to avoid being blocked by simple WAFs
            headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Pentest-Firecracker/9.0'}
            res = requests.get(url, timeout=5, verify=False, headers=headers)
            html = res.text
            low_html = html.lower()
            soup = BeautifulSoup(html, 'html.parser')

            # 1. Login Detection (Aggressive Regex)
            if soup.find('input', {'type': 'password'}) or re.search(r'login|signin|sign-in|authenticate', low_html):
                findings.append("<b style='color:red;'>LOGIN_DETECTED</b>")

            # 2. WordPress Detection
            if "wp-content" in low_html or "wp-includes" in low_html:
                findings.append("<b style='color:#21759b;'>WORDPRESS_DETECTED</b>")

            # 3. Robots.txt Analysis
            rob = requests.get(f"{url}/robots.txt", timeout=3, verify=False, headers=headers)
            if rob.status_code == 200:
                paths = [l for l in rob.text.split('\n') if "disallow" in l.lower()]
                findings.append(f"Robots.txt ({len(paths)} paths)")

            # 4. Forgot Password / User Enum Logic
            if re.search(r'forgot|reset|recovery', low_html):
                findings.append("FORGOT_PWD_DETECTED")
                # Quick probe for common enum endpoints
                for path in ['/forgot-password', '/wp-login.php?action=lostpassword']:
                    enum_test = requests.get(f"{url}{path}", timeout=2, verify=False)
                    if enum_test.status_code == 200:
                        findings.append(f"ENUM_POINT: {path}")
                        break

        except: pass
        return " | ".join(findings) if findings else "Low Profile / No Web"

    def get_shodan(self, ip):
        if not SHODAN_API_KEY or "YOUR" in SHODAN_API_KEY: return "No API Key"
        try:
            r = requests.get(f"https://api.shodan.io/shodan/host/{ip}?key={SHODAN_API_KEY}", timeout=5)
            if r.status_code == 200:
                d = r.json()
                return f"Ports: {d.get('ports')}<br>Vulns: {d.get('vulns', 'None')}"
        except: pass
        return "No Data"

    def scan_host(self, host):
        self.log(f"Scanning {host}...")
        try:
            ip = socket.gethostbyname(host)
        except: return None

        # Active Nmap scan
        nm_out = subprocess.getoutput(f"nmap -sV -T4 -p{TARGET_PORTS} {ip}")
        
        # Parse open ports
        open_tcp = []
        closed, filtered = 0, 0
        for line in nm_out.split('\n'):
            if "open" in line and "tcpwrapped" not in line and "/tcp" in line:
                p = re.split(r'\s+', line)
                open_tcp.append(f"<b>{p[0]}</b> - {p[2]} {' '.join(p[3:])}")
            elif "closed" in line: closed += 1
            elif "filtered" in line: filtered += 1

        # Trigger Web Audit if appropriate
        web_info = "N/A"
        if "80/tcp" in nm_out or "443/tcp" in nm_out:
            proto = "https" if "443/tcp" in nm_out else "http"
            web_info = self.deep_web_audit(f"{proto}://{host}")

        return {
            "FQDN": host, "IP": ip, "TCP": "<br>".join(open_tcp),
            "Stats": f"C: {closed} | F: {filtered}", "Web": web_info,
            "Shodan": self.get_shodan(ip)
        }

    def run(self):
        self.get_subdomains()
        self.audit_email_security()
        for sub in list(self.subdomains):
            data = self.scan_host(sub)
            if data: self.results.append(data)
        self.export_html()

    def export_html(self):
        fn = f"Final_Audit_{self.domain}.html"
        with open(fn, "w") as f:
            f.write(f"""
            <html><head><style>
                body {{ font-family: 'Segoe UI', Tahoma, sans-serif; padding: 30px; background: #fafafa; }}
                .card {{ background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 8px rgba(0,0,0,0.1); margin-bottom: 20px; }}
                table {{ border-collapse: collapse; width: 100%; }}
                th, td {{ border: 1px solid #ddd; padding: 12px; text-align: left; vertical-align: top; }}
                th {{ background: #2c3e50; color: white; }}
                .high {{ color: #e74c3c; font-weight: bold; }}
                code {{ background: #eee; padding: 2px 4px; border-radius: 4px; display: block; white-space: pre-wrap; }}
            </style></head><body>
            <h1>Assessment: {self.domain}</h1>
            <div class="card">
                <h3>1. Domain & Email Security</h3>
                <table>
                    <tr><th>Metric</th><th>Finding</th><th>Analyst Context</th></tr>
                    <tr><td class="high">{self.email_security['Status']}</td><td>Check records</td><td>{self.email_security['Context']}</td></tr>
                    <tr><td>SPF</td><td><code>{self.email_security['SPF']}</code></td><td>Records authorized IPs. ~all = Vulnerable.</td></tr>
                    <tr><td>DMARC</td><td><code>{self.email_security['DMARC']}</code></td><td>p=none is monitoring only. Needs p=reject.</td></tr>
                </table>
            </div>
            <div class="card">
                <h3>2. Infrastructure Inventory</h3>
                <table>
                    <tr><th>Target</th><th>Services & Banners</th><th>Web Intelligence</th><th>Shodan (Passive)</th><th>Stats</th></tr>""")
            for r in self.results:
                f.write(f"<tr><td><b>{r['FQDN']}</b><br>{r['IP']}</td><td>{r['TCP'] if r['TCP'] else 'None'}</td><td>{r['Web']}</td><td>{r['Shodan']}</td><td>{r['Stats']}</td></tr>")
            f.write("</table></div></body></html>")
        self.log(f"REPORT SAVED: {fn}")

if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("-l", "--list", help="Import FQDN list")
    args = p.parse_args()
    dom = input("Primary Domain: ")
    FirecrackerV9(dom, input_file=args.list).run()
