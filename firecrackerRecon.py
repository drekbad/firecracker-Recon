import os, subprocess, requests, re, json, socket, argparse
from bs4 import BeautifulSoup
import urllib3

# Complete terminal silence
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# --- CONFIGURATION ---
SHODAN_API_KEY = "YOUR_SHODAN_API_KEY" 
TARGET_PORTS = "21,22,23,25,53,69,80,135,137,139,143,161,443,500,587,1433,3000,3306,3389,5000,8000,8080,8443,9000,10000"

class FirecrackerV12:
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
        
        # 1. Aggressive CRT.SH Loop (Restored to the 16-record version)
        try:
            r = requests.get(f"https://crt.sh/?q=%.{self.domain}&output=json", timeout=20)
            if r.status_code == 200:
                for entry in r.json():
                    name_val = entry['name_value'].lower()
                    for sub in name_val.split('\n'):
                        clean_sub = sub.replace('*.', '').strip()
                        if self.domain in clean_sub:
                            self.subdomains.add(clean_sub)
        except: pass

        # 2. DNSRecon
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
                    if line.strip(): self.subdomains.add(line.strip().lower())

        self.log(f"Total Targets identified: {len(self.subdomains)}")

    def audit_email_security(self):
        self.log("Evaluating Email Security...")
        spf = subprocess.getoutput(f"dig TXT {self.domain} +short").replace('"', '').strip()
        dmarc = subprocess.getoutput(f"dig TXT _dmarc.{self.domain} +short").replace('"', '').strip()
        
        spoof, reason, ctx = "NO", "Strong Policy", "Records are present and restrictive."
        if not spf: 
            spoof, reason = "YES", "Missing SPF Record"
            ctx = "The absence of an SPF record allows unauthorized mail servers to send on behalf of the domain."
        elif "~all" in spf: 
            spoof, reason = "YES", "SoftFail (~all)"
            ctx = "SoftFail mechanisms advise receiving servers to accept mail but flag it as suspicious; it is not a definitive block."
        elif "p=none" in dmarc: 
            spoof, reason = "YES", "DMARC p=none"
            ctx = "The DMARC policy is currently in monitoring mode (p=none), providing no enforcement against spoofed messages."

        self.email_security = {
            "Status": f"Spoofable: {spoof} ({reason})",
            "SPF": spf if spf else "None Detected",
            "DMARC": dmarc if dmarc else "None Detected",
            "Context": ctx
        }

    def deep_web_audit(self, url, host):
        findings = []
        try:
            headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Pentest-Firecracker/12.0'}
            res = requests.get(url, timeout=5, verify=False, headers=headers)
            low_html = res.text.lower()
            soup = BeautifulSoup(res.text, 'html.parser')

            # Linked findings
            if soup.find('input', {'type': 'password'}) or re.search(r'login|signin|sign-in|authenticate', low_html):
                findings.append(f"<a href='{url}' style='color:#e74c3c; font-weight:bold; text-decoration:none;'>Login detected</a>")

            if "wp-content" in low_html or "wp-includes" in low_html:
                findings.append(f"<a href='{url}' style='color:#21759b; font-weight:bold; text-decoration:none;'>WordPress detected</a>")

            if re.search(r'forgot|reset|recovery', low_html):
                findings.append(f"<a href='{url}' style='color:black; text-decoration:none;'>Forgot pwd detected</a>")

            rob = requests.get(f"{url}/robots.txt", timeout=3, verify=False, headers=headers)
            if rob.status_code == 200:
                paths = [l for l in rob.text.split('\n') if "disallow" in l.lower()]
                findings.append(f"Robots.txt ({len(paths)} paths)")

        except: pass
        return " | ".join(findings) if findings else "Low Profile"

    def get_shodan(self, ip):
        if not SHODAN_API_KEY or "YOUR" in SHODAN_API_KEY: return "No API Key"
        try:
            r = requests.get(f"https://api.shodan.io/shodan/host/{ip}?key={SHODAN_API_KEY}", timeout=5)
            if r.status_code == 200:
                d = r.json()
                ports = sorted(d.get('ports', []))
                # Link icon moved to beginning
                link = f"<a href='https://www.shodan.io/host/{ip}' target='_blank' style='text-decoration:none;'>&#10697; </a>"
                return f"{link}Ports: {ports}<br>Vulns: {d.get('vulns', 'None Found')}"
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
        total_targeted = len(TARGET_PORTS.split(','))

        for line in nm_out.split('\n'):
            if "open" in line and "tcpwrapped" not in line and "/tcp" in line:
                p = re.split(r'\s+', line)
                port_num = p[0].split('/')[0]
                link = f"http://{host}:{port_num}" if port_num != "443" else f"https://{host}"
                open_tcp.append(f"<b><a href='{link}' target='_blank' style='color:black;text-decoration:underline;'>{p[0]}</a></b> - {p[2]} {' '.join(p[3:])}")
            elif "closed" in line: closed += 1
            elif "filtered" in line: filtered += 1
        
        # Reconciliation of missing ports
        unaccounted = total_targeted - (len(open_tcp) + closed + filtered)
        filtered += unaccounted

        web_info = "N/A"
        if "80/tcp" in nm_out or "443/tcp" in nm_out:
            proto = "https" if "443/tcp" in nm_out else "http"
            web_info = self.deep_web_audit(f"{proto}://{host}", host)

        return {
            "FQDN": host, "IP": ip, "TCP": "<br>".join(open_tcp), "Count": len(open_tcp),
            "Stats": f"Closed: {closed}<br>Filtered: {filtered}", "Web": web_info,
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
                body {{ font-family: 'Segoe UI', Tahoma, sans-serif; padding: 20px; background: #fafafa; }}
                .card {{ background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); margin-bottom: 20px; }}
                table {{ border-collapse: collapse; width: 100%; table-layout: fixed; }}
                th, td {{ border: 1px solid #eee; padding: 12px; text-align: left; vertical-align: top; font-size: 0.95em; }}
                th {{ background: #2c3e50; color: white; }}
                th:nth-child(1) {{ width: 18%; }} th:nth-child(2) {{ width: 27%; }} 
                th:nth-child(3) {{ width: 25%; }} th:nth-child(4) {{ width: 20%; }} th:nth-child(5) {{ width: 10%; }} 
                .high {{ color: #e74c3c; font-weight: bold; }}
                .context {{ font-size: 0.85em; color: #7f8c8d; font-style: italic; }}
                .count {{ font-weight: bold; color: #2c3e50; font-size: 0.8em; margin-bottom: 5px; display: block; }}
                code {{ background: #f4f4f4; padding: 4px; border-radius: 4px; display: block; white-space: pre-wrap; font-family: monospace; }}
            </style></head><body>
            <h1>External Pentest Recon: {self.domain}</h1>
            <div class="card">
                <h3>1. Domain & Email Security</h3>
                <table>
                    <tr><th style="width:20%;">Metric</th><th style="width:40%;">Finding</th><th style="width:40%;">Analyst Context</th></tr>
                    <tr><td class="high">{self.email_security['Status']}</td><td>See Raw Records Below</td><td>{self.email_security['Context']}</td></tr>
                    <tr><td>SPF Record</td><td><code>{self.email_security['SPF']}</code></td><td class="context">The SPF record defines authorized sending hosts. SoftFail (~all) or Neutral (?all) indicates weak enforcement.</td></tr>
                    <tr><td>DMARC Record</td><td><code>{self.email_security['DMARC']}</code></td><td class="context">DMARC provides instruction to receivers on how to handle failed authentication. Enforcement requires p=reject or p=quarantine.</td></tr>
                </table>
            </div>
            <div class="card">
                <h3>2. Infrastructure Inventory ({len(self.results)} Systems Identified)</h3>
                <table>
                    <tr><th>Target</th><th>Services & Banners</th><th>Web Intelligence</th><th>Shodan (Passive)</th><th>Stats</th></tr>""")
            for r in self.results:
                f.write(f"""<tr>
                    <td><b>{r['FQDN']}</b><br>{r['IP']}</td>
                    <td><span class='count'>Open Ports: {r['Count']}</span>{r['TCP'] if r['TCP'] else 'None Detected'}</td>
                    <td>{r['Web']}</td>
                    <td>{r['Shodan']}</td>
                    <td class="context">{r['Stats']}</td>
                </tr>""")
            f.write("</table></div></body></html>")
        self.log(f"Report generated: {fn}")

if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("-l", "--list", help="Import FQDN list")
    args = p.parse_args()
    dom = input("Primary Domain: ")
    FirecrackerV12(dom, input_file=args.list).run()
