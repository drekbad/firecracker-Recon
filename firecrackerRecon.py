import os, subprocess, requests, re, json, socket, argparse
from bs4 import BeautifulSoup
import urllib3

# Absolute silence for the terminal
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# --- CONFIGURATION ---
SHODAN_API_KEY = "YOUR_SHODAN_API_KEY" 
TARGET_PORTS = "21,22,23,25,53,69,80,135,137,139,143,161,443,500,587,1433,3000,3306,3389,5000,8000,8080,8443,9000,10000"

class FirecrackerV10:
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
        
        # 1. CRT.SH - Pulling EVERYTHING
        try:
            r = requests.get(f"https://crt.sh/?q=%.{self.domain}&output=json", timeout=25)
            if r.status_code == 200:
                for entry in r.json():
                    names = entry['name_value'].lower().split('\n')
                    for n in names:
                        # Strip wildcards and whitespace
                        clean_n = n.replace('*.', '').strip()
                        if clean_n: self.subdomains.add(clean_n)
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

        # 3. Import External List
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
            headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Pentest-Firecracker/10.0'}
            res = requests.get(url, timeout=5, verify=False, headers=headers)
            low_html = res.text.lower()
            soup = BeautifulSoup(res.text, 'html.parser')

            if soup.find('input', {'type': 'password'}) or re.search(r'login|signin|sign-in|authenticate', low_html):
                findings.append("<b style='color:#e74c3c;'>Login detected</b>")

            if "wp-content" in low_html or "wp-includes" in low_html:
                findings.append("<b style='color:#21759b;'>WordPress detected</b>")

            rob = requests.get(f"{url}/robots.txt", timeout=3, verify=False, headers=headers)
            if rob.status_code == 200:
                paths = [l for l in rob.text.split('\n') if "disallow" in l.lower()]
                findings.append(f"Robots.txt ({len(paths)} paths)")

            if re.search(r'forgot|reset|recovery', low_html):
                findings.append("Forgot pwd detected")

        except: pass
        return " | ".join(findings) if findings else "Low Profile"

    def get_shodan(self, ip):
        if not SHODAN_API_KEY or "YOUR" in SHODAN_API_KEY: return "No API Key"
        try:
            r = requests.get(f"https://api.shodan.io/shodan/host/{ip}?key={SHODAN_API_KEY}", timeout=5)
            if r.status_code == 200:
                d = r.json()
                ports = sorted(d.get('ports', []))
                link = f"<a href='https://www.shodan.io/host/{ip}' target='_blank' style='text-decoration:none;'> 🔗</a>"
                return f"Ports: {ports}{link}<br>Vulns: {d.get('vulns', 'None')}"
        except: pass
        return "No Data"

    def scan_host(self, host):
        self.log(f"Scanning {host}...")
        try:
            ip = socket.gethostbyname(host)
        except: return None

        nm_out = subprocess.getoutput(f"nmap -sV -T4 -p{TARGET_PORTS} {ip}")
        
        open_tcp = []
        closed, filtered = 0, 0
        for line in nm_out.split('\n'):
            if "open" in line and "tcpwrapped" not in line and "/tcp" in line:
                p = re.split(r'\s+', line)
                port_num = p[0].split('/')[0]
                # Hyperlink the port number
                link = f"http://{host}:{port_num}" if port_num != "443" else f"https://{host}"
                open_tcp.append(f"<b><a href='{link}' target='_blank' style='color:black;text-decoration:underline;'>{p[0]}</a></b> - {p[2]} {' '.join(p[3:])}")
            elif "closed" in line: closed += 1
            elif "filtered" in line: filtered += 1

        web_info = "N/A"
        if "80/tcp" in nm_out or "443/tcp" in nm_out:
            proto = "https" if "443/tcp" in nm_out else "http"
            web_info = self.deep_web_audit(f"{proto}://{host}")

        return {
            "FQDN": host, "IP": ip, "TCP": "<br>".join(open_tcp),
            "Stats": f"C:{closed}<br>F:{filtered}", "Web": web_info,
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
                body {{ font-family: 'Segoe UI', sans-serif; padding: 20px; background: #fafafa; }}
                .card {{ background: white; padding: 15px; border-radius: 8px; box-shadow: 0 2px 8px rgba(0,0,0,0.1); margin-bottom: 20px; }}
                table {{ border-collapse: collapse; width: 100%; table-layout: fixed; word-wrap: break-word; }}
                th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; vertical-align: top; font-size: 0.9em; }}
                th {{ background: #2c3e50; color: white; }}
                /* Specific Column Widths for Portrait Monitors */
                th:nth-child(1) {{ width: 18%; }} /* Target */
                th:nth-child(2) {{ width: 27%; }} /* Services */
                th:nth-child(3) {{ width: 25%; }} /* Web Intel */
                th:nth-child(4) {{ width: 20%; }} /* Shodan */
                th:nth-child(5) {{ width: 10%; }} /* Stats */
                .high {{ color: #e74c3c; font-weight: bold; }}
                code {{ background: #eee; padding: 2px 4px; border-radius: 4px; display: block; white-space: pre-wrap; font-size: 0.85em; }}
            </style></head><body>
            <h1>Assessment: {self.domain}</h1>
            <div class="card">
                <h3>1. Domain & Email Security</h3>
                <table>
                    <tr><th style="width:20%;">Metric</th><th style="width:40%;">Finding</th><th style="width:40%;">Analyst Context</th></tr>
                    <tr><td class="high">{self.email_security['Status']}</td><td>Check records</td><td>{self.email_security['Context']}</td></tr>
                    <tr><td>SPF</td><td><code>{self.email_security['SPF']}</code></td><td>~all = SoftFail / Vulnerable.</td></tr>
                    <tr><td>DMARC</td><td><code>{self.email_security['DMARC']}</code></td><td>p=none is monitoring only.</td></tr>
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
    FirecrackerV10(dom, input_file=args.list).run()
