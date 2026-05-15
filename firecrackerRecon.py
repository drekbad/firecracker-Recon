import os, subprocess, requests, re, json, socket, time
from bs4 import BeautifulSoup
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from webdriver_manager.chrome import ChromeDriverManager

# --- CONFIG ---
SHODAN_API_KEY = "YOUR_SHODAN_API_KEY"
TCP_PORTS = "21,22,23,25,80,135,139,443,445,1433,3306,3389,8080,8443,10000"
UDP_PORTS = "53,69,161,500" # High-value UDP targets
USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Pentest-Firecracker/5.0"

class FirecrackerV5:
    def __init__(self, domain):
        self.domain = domain
        self.subdomains = {domain}
        self.results = []
        self.email_security = {}
        if not os.path.exists("screenshots"): os.makedirs("screenshots")

    def log(self, msg): print(f"[*] {msg}")

    def get_subdomains(self):
        self.log(f"Aggressive hunting for {self.domain}...")
        # 1. CRT.SH
        try:
            r = requests.get(f"https://crt.sh/?q=%.{self.domain}&output=json", timeout=15)
            for entry in r.json():
                for n in entry['name_value'].lower().split('\n'):
                    self.subdomains.add(n.replace('*.', '').strip())
        except: pass
        # 2. DNSRECON (Kali)
        try:
            subprocess.run(["dnsrecon", "-d", self.domain, "-t", "std", "--json", "tmp.json"], capture_output=True)
            if os.path.exists("tmp.json"):
                with open("tmp.json") as f:
                    for item in json.load(f):
                        if 'name' in item: self.subdomains.add(item['name'].lower())
                os.remove("tmp.json")
        except: pass
        self.log(f"Total Unique Targets: {len(self.subdomains)}")

    def take_screenshot(self, url, host):
        """Headless Chrome screenshotting"""
        options = Options()
        options.add_argument("--headless")
        options.add_argument("--no-sandbox")
        options.add_argument("--disable-dev-shm-usage")
        try:
            driver = webdriver.Chrome(options=options)
            driver.set_page_load_timeout(10)
            driver.get(url)
            time.sleep(2) # Allow for JS rendering
            filename = f"screenshots/{host}.png"
            driver.save_screenshot(filename)
            driver.quit()
            return filename
        except: return None

    def scan_host(self, host):
        self.log(f"Scanning {host}...")
        try:
            ip = socket.gethostbyname(host)
        except: return None

        # TCP Scan (-sV for banners)
        tcp_out = subprocess.getoutput(f"nmap -sV -T4 -p{TCP_PORTS} {ip}")
        # UDP Scan (Fast touch)
        udp_out = subprocess.getoutput(f"nmap -sU -F -p{UDP_PORTS} {ip}")
        
        # Web & Screenshot
        screenshot_path = None
        web_intel = "None"
        if "80/tcp open" in tcp_out or "443/tcp open" in tcp_out:
            proto = "https" if "443/tcp open" in tcp_out else "http"
            url = f"{proto}://{host}"
            screenshot_path = self.take_screenshot(url, host)
            # Basic User Enum check
            try:
                r = requests.get(f"{url}/wp-login.php", timeout=3, verify=False)
                if r.status_code == 200: web_intel = "WordPress Detected"
            except: pass

        return {
            "FQDN": host, "IP": ip,
            "TCP": self.parse_nmap(tcp_out),
            "UDP": self.parse_nmap(udp_out),
            "Web": web_intel,
            "Screenshot": screenshot_path
        }

    def parse_nmap(self, output):
        hits = []
        for line in output.split('\n'):
            if "open" in line and "tcpwrapped" not in line:
                hits.append(line.strip())
        return hits

    def audit_email(self):
        spf = subprocess.getoutput(f"dig TXT {self.domain} +short")
        dmarc = subprocess.getoutput(f"dig TXT _dmarc.{self.domain} +short")
        spoof = "YES" if "~all" in spf or "p=none" in dmarc or not spf else "NO"
        self.email_security = {"SPF": spf, "DMARC": dmarc, "Spoofable": spoof}

    def run(self):
        self.get_subdomains()
        self.audit_email()
        for sub in list(self.subdomains):
            res = self.scan_host(sub)
            if res: self.results.append(res)
        self.export_html()

    def export_html(self):
        html = f"""<html><body style='font-family:sans-serif; background:#eee; padding:20px;'>
        <div style='background:white; padding:20px; border-radius:10px;'>
        <h1>Firecracker Report: {self.domain}</h1>
        <h3>Spoofable: {self.email_security['Spoofable']}</h3>
        <p>SPF: <code>{self.email_security['SPF']}</code></p>
        <p>DMARC: <code>{self.email_security['DMARC']}</code></p>
        <hr>
        <table border='1' style='width:100%; border-collapse:collapse;'>
            <tr style='background:#2c3e50; color:white;'><th>Host/IP</th><th>Services</th><th>Web/Screenshots</th></tr>"""
        
        for r in self.results:
            services = "<br>".join(r['TCP'] + r['UDP'])
            img_html = f"<img src='{r['Screenshot']}' width='300'><br>" if r['Screenshot'] else ""
            html += f"<tr><td><b>{r['FQDN']}</b><br>{r['IP']}</td><td>{services}</td><td>{img_html}{r['Web']}</td></tr>"
        
        html += "</table></div></body></html>"
        with open("Full_Audit.html", "w") as f: f.write(html)
        self.log("Final Report Saved: Full_Audit.html")

if __name__ == "__main__":
    target = input("Enter target domain: ")
    FirecrackerV5(target).run()
