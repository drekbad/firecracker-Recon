import os, subprocess, requests, re, json, socket, argparse
from bs4 import BeautifulSoup
import urllib3

# Silence the 'Unverified HTTPS' warnings in the terminal
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# --- CONFIGURATION ---
SHODAN_API_KEY = "YOUR_SHODAN_API_KEY" 
TARGET_PORTS = "21,22,23,25,53,69,80,135,137,139,143,161,443,500,587,1433,3000,3306,3389,5000,8000,8080,8443,9000,10000"

class FirecrackerV8:
    def __init__(self, domain, input_file=None):
        self.domain = domain
        self.subdomains = {domain}
        self.input_file = input_file
        self.results = []
        self.email_security = {}

    def log(self, msg):
        print(f"[*] {msg}")

    def get_subdomains(self):
        self.log(f"Hunting for subdomains of {self.domain}...")
        try:
            r = requests.get(f"https://crt.sh/?q=%.{self.domain}&output=json", timeout=15)
            if r.status_code == 200:
                for entry in r.json():
                    for n in entry['name_value'].lower().split('\n'):
                        clean_n = n.replace('*.', '').strip()
                        if self.domain in clean_n: self.subdomains.add(clean_n)
        except: pass

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

        if self.input_file and os.path.exists(self.input_file):
            with open(self.input_file, 'r') as f:
                for line in f:
                    target = line.strip().lower()
                    if target and self.domain in target: self.subdomains.add(target)

        self.log(f"Total Targets identified: {len(self.subdomains)}")

    def audit_email_security(self):
        self.log("Evaluating Email Security...")
        spf_raw = subprocess.getoutput(f"dig TXT {self.domain} +short").replace('"', '').strip()
        dmarc_raw = subprocess.getoutput(f"dig TXT _dmarc.{self.domain} +short").replace('"', '').strip()
        
        spoofable, reason, context = "NO", "Strong Policy", "Records are present and restrictive."

        if not spf_raw:
            spoofable, reason = "YES", "Missing SPF Record"
            context = "No SPF record found. Any mail server can impersonate this domain."
        elif "~all" in spf_raw:
            spoofable, reason = "YES", "SoftFail (~all)"
            context = "SoftFail allows mail through but marks it as suspicious. Not a hard block."
        elif "p=none" in dmarc_raw:
            spoofable, reason = "YES", "DMARC p=none"
            context = "DMARC is in 'Monitoring Mode'. No spoofing protection is active."

        self.email_security = {
            "Status": f"Spoofable: {spoofable} ({reason})",
            "SPF": spf_raw if spf_raw else "None Detected",
            "DMARC": dmarc_raw if dmarc_raw else "None Detected",
            "Context": context
        }

    def get_shodan_data(self, ip):
        if not SHODAN_API_KEY or "YOUR" in SHODAN_API_KEY: return "No API Key"
        try:
            r = requests.get(f"https://api.shodan.io/shodan/host/{ip}?key={SHODAN_API_KEY}", timeout=5)
            if r.status_code == 200:
                d = r.json()
                ports = d.get('ports', [])
                vulns = d.get('vulns', 'None')
                return f"Ports: {ports}<br>Vulns: {vulns}"
        except: pass
        return "No Data"

    def parse_nmap(self, output):
        lines = output.split('\n')
        parsed = {"tcp": [], "closed": 0, "filtered": 0}
        for line in lines:
            if "open" in line and "tcpwrapped" not in line and "/tcp" in line:
                parts = re.split(r'\s+', line)
                parsed["tcp"].append(f"<b>{parts[0]}</b> - {parts[2]} {' '.join(parts[3:])}")
            elif "closed" in line: parsed["closed"] += 1
            elif "filtered" in line: parsed["filtered"] += 1
        return parsed

    def deep_web_audit(self, url):
        findings = []
        try:
            # verify=False handles the SSL issues; timeout prevents hanging
            res = requests.get(url, timeout=5, verify=False)
            content = res.text.lower()
            soup = BeautifulSoup(res.text, 'html.parser')

            # 1. Login/Portal Detection
            if soup.find('input', {'type': 'password'}) or any(x in content for x in ['login', 'signin', 'forgot password', 'reset password']):
                findings.append("<span style='color:red; font-weight:bold;'>LOGIN_DETECTED</span>")

            # 2. WordPress Detection
            if "wp-content" in content or "wp-includes" in content:
                findings.append("CMS: WordPress")

            # 3. Robots.txt check
            rob = requests.get(f"{url}/robots.txt", timeout=3, verify=False)
            if rob.status_code == 200:
                paths = len(re.findall(r"Disallow:", rob.text))
                findings.append(f"Robots.txt ({paths} paths)")

        except: pass
        return "<br>".join(findings) if findings else "Low Profile"

    def scan_host(self, host):
        self.log(f"Scanning {host}...")
        try:
            ip = socket.gethostbyname(host)
        except: return None

        nm_out = subprocess.getoutput(f"nmap -sV -T4 -p{TARGET_PORTS} {ip}")
        nmap_data = self.parse_nmap(nm_out)
        
        # Only check Web Intel if 80 or 443 are open
        web_info = "Port 80/443 Closed"
        if "80/tcp" in nm_out or "443/tcp" in nm_out:
            proto = "https" if "443/tcp" in nm_out else "http"
            web_info = self.deep_web_audit(f"{proto}://{host}")

        return {
            "FQDN": host, "IP": ip,
            "TCP": "<br>".join(nmap_data["tcp"]),
            "Stats": f"Closed: {nmap_data['closed']} | Filtered: {nmap_data['filtered']}",
            "Web": web_info,
            "Shodan": self.get_shodan_data(ip)
        }

    def run(self):
        self.get_subdomains()
        self.audit_email_security()
        for sub in list(self.subdomains):
            data = self.scan_host(sub)
            if data: self.results.append(data)
        self.export_html()

    def export_html(self):
        filename = f"Audit_{self.domain}.html"
        with open(filename, "w") as f:
            f.write(f"""
            <html><head><style>
                body {{ font-family: 'Segoe UI', Tahoma, sans-serif; margin: 40px; background: #fafafa; }}
                .card {{ background: white; border-radius: 8px; padding: 20px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); margin-bottom: 20px; }}
                table {{ border-collapse: collapse; width: 100%; margin-top: 10px; }}
                th, td {{ border: 1px solid #eee; padding: 10px; text-align: left; vertical-align: top; }}
                th {{ background: #2c3e50; color: white; }}
                .high {{ color: #e74c3c; font-weight: bold; }}
                .context {{ font-size: 0.85em; color: #7f8c8d; font-style: italic; }}
                code {{ background: #f4f4f4; padding: 2px 4px; border-radius: 4px; display: block; white-space: pre-wrap; }}
            </style></head><body>
            <h1>External Recon Report: {self.domain}</h1>
            <div class="card">
                <h3>1. Domain & Email Security</h3>
                <table>
                    <tr><th>Metric</th><th>Finding</th><th>Analyst Context</th></tr>
                    <tr><td class="high">{self.email_security['Status']}</td><td>Check records below</td><td>{self.email_security['Context']}</td></tr>
                    <tr><td>SPF Record</td><td><code>{self.email_security['SPF']}</code></td><td class="context">SoftFail (~all) or Neutral (?all) are the primary indicators for spoofing.</td></tr>
                    <tr><td>DMARC Record</td><td><code>{self.email_security['DMARC']}</code></td><td class="context">Ensure 'p=reject' is present for hardened security.</td></tr>
                </table>
            </div>
            <div class="card">
                <h3>2. Infrastructure Inventory</h3>
                <table>
                    <tr><th>FQDN / IP</th><th>Open TCP & Banners</th><th>Web Intelligence</th><th>Shodan (Passive)</th><th>Stats</th></tr>
            """)
            for r in self.results:
                f.write(f"""
                <tr>
                    <td><b>{r['FQDN']}</b><br>{r['IP']}</td>
                    <td>{r['TCP'] if r['TCP'] else 'None Detected'}</td>
                    <td>{r['Web']}</td>
                    <td>{r['Shodan']}</td>
                    <td class="context">{r['Stats']}</td>
                </tr>""")
            f.write("</table></div></body></html>")
        self.log(f"Done! Created: {filename}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("-l", "--list", help="Path to text file containing FQDNs")
    args = parser.parse_args()
    
    target_dom = input("Primary Domain: ")
    FirecrackerV8(target_dom, input_file=args.list).run()
