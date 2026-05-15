import os, subprocess, requests, re, json, socket
from bs4 import BeautifulSoup
from datetime import datetime

# --- CONFIGURATION ---
SHODAN_API_KEY = "YOUR_SHODAN_API_KEY" # <--- Insert your key here
TARGET_PORTS = "21,22,23,25,53,69,80,135,137,139,143,161,443,500,587,1433,3000,3306,3389,5000,8000,8080,8443,9000,10000"

class FirecrackerV4:
    def __init__(self, domain):
        self.domain = domain
        self.subdomains = {domain}
        self.results = []
        self.email_security = {}

    def log(self, msg):
        print(f"[*] {msg}")

    def get_subdomains(self):
        self.log(f"Hunting for subdomains of {self.domain}...")
        # Passive: CRT.SH
        try:
            r = requests.get(f"https://crt.sh/?q=%.{self.domain}&output=json", timeout=15)
            for entry in r.json():
                names = entry['name_value'].lower().split('\n')
                for n in names:
                    if self.domain in n: self.subdomains.add(n.replace('*.', ''))
        except: pass
        # Active: DNSRecon
        try:
            subprocess.run(["dnsrecon", "-d", self.domain, "-t", "std", "--json", "tmp.json"], capture_output=True)
            if os.path.exists("tmp.json"):
                with open("tmp.json") as f:
                    for item in json.load(f):
                        if 'name' in item: self.subdomains.add(item['name'].lower())
                os.remove("tmp.json")
        except: pass

    def audit_email_security(self):
        self.log("Evaluating Email Security...")
        spf_raw = subprocess.getoutput(f"dig TXT {self.domain} +short")
        dmarc_raw = subprocess.getoutput(f"dig TXT _dmarc.{self.domain} +short")
        
        # Logic for "Spoofable" status
        spoofable = "NO"
        reason = "Strong Policy"
        context = "Records are present and restrictive."

        if "v=spf1" not in spf_raw:
            spoofable, reason = "YES", "Missing SPF Record"
            context = "No SPF record means any server can claim to send email as this domain."
        elif "~all" in spf_raw:
            spoofable, reason = "YES", "SoftFail (~all)"
            context = "SoftFail tells receiving servers to accept the mail but mark it as suspicious; it doesn't block it."
        elif "p=none" in dmarc_raw:
            spoofable, reason = "YES", "DMARC p=none"
            context = "p=none is 'Monitoring Mode'. It tells servers to take no action even if SPF/DKIM fails."

        self.email_security = {
            "Status": f"Spoofable: {spoofable} ({reason})",
            "SPF": spf_raw.replace('"', '').strip(),
            "DMARC": dmarc_raw.replace('"', '').strip(),
            "Context": context
        }

    def get_shodan_data(self, ip):
        if not SHODAN_API_KEY or SHODAN_API_KEY == "YOUR_SHODAN_API_KEY":
            return "API Key Missing"
        try:
            r = requests.get(f"https://api.shodan.io/shodan/host/{ip}?key={SHODAN_API_KEY}", timeout=5)
            if r.status_code == 200:
                data = r.json()
                ports = data.get('ports', [])
                vulns = data.get('vulns', [])
                return f"Ports: {ports}<br>Vulns: {vulns if vulns else 'None Found'}"
        except: pass
        return "No Data"

    def parse_nmap(self, output):
        lines = output.split('\n')
        parsed = {"tcp": [], "udp": [], "closed": 0, "filtered": 0}
        for line in lines:
            if "/tcp" in line or "/udp" in line:
                if "open" in line and "tcpwrapped" not in line:
                    # Clean up the port/service line
                    parts = re.split(r'\s+', line)
                    entry = f"<b>{parts[0]}</b> - {parts[2]} {' '.join(parts[3:])}"
                    if "/tcp" in line: parsed["tcp"].append(entry)
                    else: parsed["udp"].append(entry)
                elif "closed" in line: parsed["closed"] += 1
                elif "filtered" in line: parsed["filtered"] += 1
        return parsed

    def deep_web_audit(self, url):
        findings = []
        try:
            res = requests.get(url, timeout=4, verify=False)
            soup = BeautifulSoup(res.text, 'html.parser')
            # 1. Login Logic
            if soup.find('input', {'type': 'password'}) or any(x in res.text.lower() for x in ['login', 'sign-in', 'password']):
                findings.append("<span style='color:red;'>LOGIN_DETECTED</span>")
            # 2. WordPress
            if "wp-content" in res.text or "wp-includes" in res.text:
                findings.append("CMS: WordPress")
            # 3. Robots
            rob = requests.get(f"{url}/robots.txt", timeout=2, verify=False)
            if rob.status_code == 200:
                disallowed = len(re.findall(r"Disallow:", rob.text))
                findings.append(f"Robots.txt ({disallowed} hidden paths)")
        except: pass
        return "<br>".join(findings) if findings else "Low Profile"

    def scan_host(self, host):
        self.log(f"Processing {host}...")
        try:
            ip = socket.gethostbyname(host)
        except: return None

        # Execute Nmap -sV for banners
        nm_out = subprocess.getoutput(f"nmap -sV -T4 -p{TARGET_PORTS} {ip}")
        nmap_data = self.parse_nmap(nm_out)
        
        return {
            "FQDN": host, "IP": ip,
            "TCP": "<br>".join(nmap_data["tcp"]),
            "Stats": f"Closed: {nmap_data['closed']} | Filtered: {nmap_data['filtered']}",
            "Web": self.deep_web_audit(f"http://{host}"),
            "Shodan": self.get_shodan_data(ip)
        }

    def run(self):
        self.get_subdomains()
        self.audit_email_security()
        for sub in list(self.subdomains):
            if self.domain in sub:
                data = self.scan_host(sub)
                if data: self.results.append(data)
        self.export_html()

    def export_html(self):
        filename = f"Audit_{self.domain}.html"
        with open(filename, "w") as f:
            f.write(f"""
            <html><head><style>
                body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; margin: 40px; background: #fafafa; }}
                .card {{ background: white; border-radius: 8px; padding: 20px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); margin-bottom: 20px; }}
                table {{ border-collapse: collapse; width: 100%; margin-top: 10px; }}
                th, td {{ border: 1px solid #eee; padding: 10px; text-align: left; vertical-align: top; }}
                th {{ background: #2c3e50; color: white; }}
                .high {{ color: #e74c3c; font-weight: bold; }}
                .context {{ font-size: 0.85em; color: #7f8c8d; font-style: italic; }}
                code {{ background: #f4f4f4; padding: 2px 4px; border-radius: 4px; }}
            </style></head><body>
            <h1>External Pentest Recon: {self.domain}</h1>
            <div class="card">
                <h3>1. Domain & Email Security</h3>
                <table>
                    <tr><th>Metric</th><th>Finding</th><th>Analyst Context</th></tr>
                    <tr><td class="high">{self.email_security['Status']}</td><td>See Raw Records Below</td><td>{self.email_security['Context']}</td></tr>
                    <tr><td>SPF Record</td><td><code>{self.email_security['SPF']}</code></td><td class="context">v=spf1 indicates the version. 'include' adds authorized IPs. ~all/ -all is the policy.</td></tr>
                    <tr><td>DMARC Record</td><td><code>{self.email_security['DMARC']}</code></td><td class="context">p=none is just for monitoring. p=reject is what you want.</td></tr>
                </table>
            </div>
            <div class="card">
                <h3>2. Infrastructure Inventory</h3>
                <table>
                    <tr><th>FQDN / IP</th><th>Open TCP Ports & Banners</th><th>Web Intelligence</th><th>Shodan (Passive)</th><th>Firewall Stats</th></tr>
            """)
            for r in self.results:
                f.write(f"""
                    <tr>
                        <td><b>{r['FQDN']}</b><br>{r['IP']}</td>
                        <td>{r['TCP'] if r['TCP'] else 'No Open Ports Detected'}</td>
                        <td>{r['Web']}</td>
                        <td>{r['Shodan']}</td>
                        <td class="context">{r['Stats']}</td>
                    </tr>""")
            f.write("</table></div></body></html>")
        self.log(f"Audit Complete. Report generated: {filename}")

if __name__ == "__main__":
    target = input("Target Domain: ")
    FirecrackerV4(target).run()
