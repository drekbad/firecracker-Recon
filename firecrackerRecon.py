import os
import subprocess
import requests
import json
import csv
import dns.resolver
from datetime import datetime

# --- CONFIGURATION ---
# Use your Shodan API key if you have one
SHODAN_API_KEY = "YOUR_SHODAN_API_KEY"

class FirecrackerV2:
    def __init__(self, domain):
        self.domain = domain
        self.subdomains = set()
        self.results = []
        # Your specific port list
        self.target_ports = "21,22,23,25,53,69,80,135,137,139,143,161,443,500,587,1433,3000,3306,3389,5000,8000,8008,8080,8088,8090,8443,8444,8800,8808,8880,8888,9000,9090,9443,10000,10001,10002,20000"

    def log(self, msg):
        print(f"[{datetime.now().strftime('%H:%M:%S')}] {msg}")

    def get_subdomains(self):
        """CRT.SH + DNSRecon (Kali native)"""
        self.log(f"Starting discovery for {self.domain}...")
        
        # 1. crt.sh
        try:
            r = requests.get(f"https://crt.sh/?q=%.{self.domain}&output=json", timeout=15)
            if r.status_code == 200:
                for entry in r.json():
                    self.subdomains.add(entry['name_value'].lower().replace("*.", ""))
        except: self.log("crt.sh query failed.")

        # 2. dnsrecon (Leveraging Kali binary)
        self.log("Running dnsrecon...")
        try:
            cmd = f"dnsrecon -d {self.domain} -t std --json recon.json"
            subprocess.run(cmd.split(), capture_output=True)
            if os.path.exists("recon.json"):
                with open("recon.json", "r") as f:
                    data = json.load(f)
                    for item in data:
                        if 'name' in item: self.subdomains.add(item['name'].lower())
                os.remove("recon.json")
        except: self.log("dnsrecon failed.")

    def check_spoofing(self):
        """Logic used by Smartfense/Spoofcheck"""
        self.log("Checking SPF/DMARC Spoofability...")
        report = {"spoofable": "No", "reason": ""}
        try:
            # SPF Check
            txt_records = dns.resolver.resolve(self.domain, 'TXT')
            spf = [str(r) for r in txt_records if "v=spf1" in str(r)]
            if not spf:
                report.update({"spoofable": "YES", "reason": "Missing SPF"})
            elif "~all" not in spf[0] and "-all" not in spf[0]:
                report.update({"spoofable": "YES", "reason": "Soft SPF Policy"})
            
            # DMARC Check
            dmarc = dns.resolver.resolve(f"_dmarc.{self.domain}", 'TXT')
            if "p=none" in str(dmarc[0]):
                report.update({"spoofable": "YES", "reason": "DMARC p=none"})
        except:
            report.update({"spoofable": "YES", "reason": "No Email Security Records"})
        return report

    def audit_web(self, url):
        """User Enum & Sensitive Files"""
        web_findings = []
        try:
            # 1. Check robots.txt
            r = requests.get(f"{url}/robots.txt", timeout=3, verify=False)
            if r.status_code == 200 and "Disallow" in r.text:
                web_findings.append("Robots.txt-Interesting")

            # 2. WordPress Check
            wp = requests.get(f"{url}/wp-admin/", timeout=3, verify=False)
            if wp.status_code == 200:
                web_findings.append("WordPress-Instance")

            # 3. Ambiguous Forgot Password (Logic check)
            # Simulating the check you requested
            payload = {"user": "fakeuser135@example.com"}
            # This is a generic target; you'd adjust path per site
            forgot_path = f"{url}/forgot-password" 
            res = requests.post(forgot_path, data=payload, timeout=3, verify=False)
            if "not found" not in res.text.lower() and res.status_code == 200:
                web_findings.append("Potential-User-Enum")
        except: pass
        return ", ".join(web_findings)

    def scan_host(self, host):
        """Nmap + Shodan check"""
        self.log(f"Probing {host}...")
        try:
            ip = socket.gethostbyname(host)
        except: return None

        # Nmap Banner Grab
        nm = subprocess.run(f"nmap -sV -T4 -p{self.target_ports} {ip}".split(), capture_output=True, text=True)
        
        # Shodan (Passive Check)
        shodan_info = "Not Checked"
        if SHODAN_API_KEY != "YOUR_SHODAN_API_KEY":
            s_res = requests.get(f"https://api.shodan.io/shodan/host/{ip}?key={SHODAN_API_KEY}").json()
            shodan_info = f"Ports: {s_res.get('ports', 'None')}"

        return {
            "FQDN": host,
            "IP": ip,
            "Nmap_Output": "Active" if "open" in nm.stdout else "No Open Ports",
            "Web_Audit": self.audit_web(f"http://{host}"),
            "Shodan_Passive": shodan_info
        }

    def run(self):
        self.get_subdomains()
        spoof_results = self.check_spoofing()
        self.log(f"Spoofable: {spoof_results['spoofable']} ({spoof_results['reason']})")
        
        # Process unique in-scope subdomains
        for sub in list(self.subdomains):
            if self.domain in sub:
                data = self.scan_host(sub)
                if data: self.results.append(data)
        
        # Export to HTML for OneNote Copy-Paste
        self.export_html()

    def export_html(self):
        html = "<html><body><table border='1'><tr><th>FQDN</th><th>IP</th><th>Nmap</th><th>Web Audit</th><th>Shodan</th></tr>"
        for r in self.results:
            html += f"<tr><td>{r['FQDN']}</td><td>{r['IP']}</td><td>{r['Nmap_Output']}</td><td>{r['Web_Audit']}</td><td>{r['Shodan_Passive']}</td></tr>"
        html += "</table></body></html>"
        with open("report.html", "w") as f:
            f.write(html)
        self.log("Done! Report saved to report.html")

import socket
if __name__ == "__main__":
    domain = input("Target Domain: ")
    fire = FirecrackerV2(domain)
    fire.run()