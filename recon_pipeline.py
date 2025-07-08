#!/usr/bin/env python3
"""
Ethical Reconnaissance Pipeline for Bug Bounty and Security Testing
================================================================

This pipeline automates the reconnaissance phase of ethical hacking and bug bounty hunting.
It includes subdomain enumeration, port scanning, service detection, and vulnerability scanning.

IMPORTANT: Only use this tool on systems you own or have explicit permission to test.
Always follow responsible disclosure practices and bug bounty program rules.

Requirements:
- pip install requests beautifulsoup4 dnspython python-nmap colorama
- Install nmap, subfinder, httpx, nuclei (external tools)
"""

import os
import sys
import json
import time
import socket
import requests
import subprocess
import threading
from datetime import datetime
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed
import dns.resolver
from colorama import Fore, Back, Style, init

# Initialize colorama for cross-platform colored output
init()

class ReconPipeline:
    def __init__(self, target_domain, output_dir="recon_output"):
        self.target_domain = target_domain
        self.output_dir = output_dir
        self.subdomains = set()
        self.live_hosts = set()
        self.open_ports = {}
        self.tech_stack = {}
        self.vulnerabilities = []
        
        # Create output directory
        os.makedirs(self.output_dir, exist_ok=True)
        
        # Initialize logging
        self.log_file = os.path.join(self.output_dir, f"recon_{self.target_domain}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log")
        
    def log(self, message, level="INFO"):
        """Log messages to file and console"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_entry = f"[{timestamp}] [{level}] {message}"
        
        # Color coding for console output
        if level == "INFO":
            print(f"{Fore.BLUE}{log_entry}{Style.RESET_ALL}")
        elif level == "SUCCESS":
            print(f"{Fore.GREEN}{log_entry}{Style.RESET_ALL}")
        elif level == "WARNING":
            print(f"{Fore.YELLOW}{log_entry}{Style.RESET_ALL}")
        elif level == "ERROR":
            print(f"{Fore.RED}{log_entry}{Style.RESET_ALL}")
        
        # Write to log file
        with open(self.log_file, "a") as f:
            f.write(log_entry + "\n")
    
    def banner(self):
        """Display banner"""
        banner_text = f"""
{Fore.CYAN}
╔══════════════════════════════════════════════════════════════╗
║                  ETHICAL RECON PIPELINE                     ║
║                                                              ║
║  Target: {self.target_domain:<47} ║
║  Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S'):<49} ║
║                                                              ║
║  ⚠️  FOR AUTHORIZED TESTING ONLY ⚠️                          ║
╚══════════════════════════════════════════════════════════════╝
{Style.RESET_ALL}
"""
        print(banner_text)
    
    def passive_subdomain_enumeration(self):
        """Passive subdomain enumeration using multiple sources"""
        self.log("Starting passive subdomain enumeration...")
        
        # Method 1: Certificate Transparency (crt.sh)
        try:
            self.log("Querying Certificate Transparency logs...")
            url = f"https://crt.sh/?q=%.{self.target_domain}&output=json"
            response = requests.get(url, timeout=10)
            if response.status_code == 200:
                data = response.json()
                for cert in data:
                    if cert.get('name_value'):
                        names = cert['name_value'].split('\n')
                        for name in names:
                            if name.endswith(self.target_domain):
                                self.subdomains.add(name)
                self.log(f"Found {len(self.subdomains)} subdomains from CT logs", "SUCCESS")
        except Exception as e:
            self.log(f"Error querying CT logs: {e}", "ERROR")
        
        # Method 2: DNS Brute Force (common subdomains)
        common_subdomains = [
            'www', 'mail', 'ftp', 'localhost', 'webmail', 'smtp', 'pop', 'ns1', 'webdisk',
            'ns2', 'cpanel', 'whm', 'autodiscover', 'autoconfig', 'ns3', 'test', 'staging',
            'dev', 'api', 'admin', 'app', 'blog', 'shop', 'forum', 'support', 'help',
            'secure', 'ssl', 'vpn', 'remote', 'email', 'portal', 'mobile', 'm', 'cdn',
            'static', 'assets', 'img', 'images', 'media', 'files', 'download', 'docs'
        ]
        
        self.log("Starting DNS brute force enumeration...")
        for subdomain in common_subdomains:
            try:
                full_domain = f"{subdomain}.{self.target_domain}"
                dns.resolver.resolve(full_domain, 'A')
                self.subdomains.add(full_domain)
                self.log(f"Found subdomain: {full_domain}", "SUCCESS")
            except:
                pass
        
        # Save subdomains to file
        subdomain_file = os.path.join(self.output_dir, f"subdomains_{self.target_domain}.txt")
        with open(subdomain_file, "w") as f:
            for subdomain in sorted(self.subdomains):
                f.write(subdomain + "\n")
        
        self.log(f"Total subdomains found: {len(self.subdomains)}", "SUCCESS")
        return list(self.subdomains)
    
    def check_host_alive(self, host):
        """Check if a host is alive"""
        try:
            # Try to resolve the hostname
            socket.gethostbyname(host)
            
            # Try HTTP/HTTPS connection
            for protocol in ['https', 'http']:
                try:
                    response = requests.get(f"{protocol}://{host}", timeout=5, verify=False)
                    if response.status_code:
                        return True, protocol
                except:
                    continue
            
            # If HTTP/HTTPS fails, try ping
            if os.system(f"ping -c 1 -W 1 {host} > /dev/null 2>&1") == 0:
                return True, "ping"
            
        except:
            pass
        
        return False, None
    
    def host_discovery(self):
        """Discover live hosts from subdomain list"""
        self.log("Starting host discovery...")
        
        def check_host(host):
            alive, method = self.check_host_alive(host)
            if alive:
                self.live_hosts.add(host)
                self.log(f"Live host found: {host} (via {method})", "SUCCESS")
        
        # Use threading for faster host discovery
        with ThreadPoolExecutor(max_workers=20) as executor:
            futures = [executor.submit(check_host, host) for host in self.subdomains]
            for future in as_completed(futures):
                future.result()
        
        # Save live hosts
        live_hosts_file = os.path.join(self.output_dir, f"live_hosts_{self.target_domain}.txt")
        with open(live_hosts_file, "w") as f:
            for host in sorted(self.live_hosts):
                f.write(host + "\n")
        
        self.log(f"Live hosts discovered: {len(self.live_hosts)}", "SUCCESS")
        return list(self.live_hosts)
    
    def port_scanning(self):
        """Perform port scanning on live hosts"""
        self.log("Starting port scanning...")
        
        common_ports = [
            21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 993, 995,
            1723, 3306, 3389, 5432, 5900, 8080, 8443, 8888, 9090, 10000
        ]
        
        def scan_host(host):
            self.log(f"Scanning ports for {host}...")
            open_ports = []
            
            for port in common_ports:
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(1)
                    result = sock.connect_ex((host, port))
                    if result == 0:
                        open_ports.append(port)
                        self.log(f"Open port found: {host}:{port}", "SUCCESS")
                    sock.close()
                except:
                    pass
            
            if open_ports:
                self.open_ports[host] = open_ports
        
        # Scan ports for each live host
        with ThreadPoolExecutor(max_workers=5) as executor:
            futures = [executor.submit(scan_host, host) for host in self.live_hosts]
            for future in as_completed(futures):
                future.result()
        
        # Save port scan results
        ports_file = os.path.join(self.output_dir, f"open_ports_{self.target_domain}.json")
        with open(ports_file, "w") as f:
            json.dump(self.open_ports, f, indent=2)
        
        self.log(f"Port scanning completed for {len(self.open_ports)} hosts", "SUCCESS")
    
    def service_detection(self):
        """Detect services and technologies"""
        self.log("Starting service detection...")
        
        for host in self.live_hosts:
            self.log(f"Detecting services for {host}...")
            services = {}
            
            # Check common web services
            for protocol in ['http', 'https']:
                try:
                    url = f"{protocol}://{host}"
                    response = requests.get(url, timeout=10, verify=False)
                    
                    # Extract server header
                    server = response.headers.get('Server', 'Unknown')
                    services[f"{protocol}_server"] = server
                    
                    # Extract technology headers
                    tech_headers = ['X-Powered-By', 'X-Technology', 'X-Framework']
                    for header in tech_headers:
                        if header in response.headers:
                            services[header.lower()] = response.headers[header]
                    
                    # Basic content analysis
                    content = response.text.lower()
                    if 'wordpress' in content:
                        services['cms'] = 'WordPress'
                    elif 'drupal' in content:
                        services['cms'] = 'Drupal'
                    elif 'joomla' in content:
                        services['cms'] = 'Joomla'
                    
                except Exception as e:
                    self.log(f"Error detecting services for {host}: {e}", "WARNING")
            
            if services:
                self.tech_stack[host] = services
        
        # Save service detection results
        services_file = os.path.join(self.output_dir, f"services_{self.target_domain}.json")
        with open(services_file, "w") as f:
            json.dump(self.tech_stack, f, indent=2)
        
        self.log("Service detection completed", "SUCCESS")
    
    def vulnerability_scanning(self):
        """Basic vulnerability scanning"""
        self.log("Starting vulnerability scanning...")
        
        vulnerabilities = []
        
        for host in self.live_hosts:
            self.log(f"Scanning vulnerabilities for {host}...")
            
            # Check for common vulnerabilities
            for protocol in ['http', 'https']:
                try:
                    base_url = f"{protocol}://{host}"
                    
                    # Check for directory traversal
                    test_paths = [
                        '/admin',
                        '/administrator',
                        '/wp-admin',
                        '/phpmyadmin',
                        '/admin.php',
                        '/login',
                        '/dashboard',
                        '/.git',
                        '/.env',
                        '/config.php',
                        '/database.php'
                    ]
                    
                    for path in test_paths:
                        try:
                            response = requests.get(base_url + path, timeout=5, verify=False)
                            if response.status_code == 200:
                                vulnerabilities.append({
                                    'host': host,
                                    'type': 'Information Disclosure',
                                    'description': f'Accessible path: {path}',
                                    'severity': 'Low',
                                    'url': base_url + path
                                })
                        except:
                            pass
                    
                    # Check for security headers
                    response = requests.get(base_url, timeout=5, verify=False)
                    security_headers = [
                        'X-Frame-Options',
                        'X-XSS-Protection',
                        'X-Content-Type-Options',
                        'Strict-Transport-Security',
                        'Content-Security-Policy'
                    ]
                    
                    missing_headers = []
                    for header in security_headers:
                        if header not in response.headers:
                            missing_headers.append(header)
                    
                    if missing_headers:
                        vulnerabilities.append({
                            'host': host,
                            'type': 'Missing Security Headers',
                            'description': f'Missing headers: {", ".join(missing_headers)}',
                            'severity': 'Medium',
                            'url': base_url
                        })
                
                except Exception as e:
                    self.log(f"Error scanning {host}: {e}", "WARNING")
        
        self.vulnerabilities = vulnerabilities
        
        # Save vulnerability results
        vuln_file = os.path.join(self.output_dir, f"vulnerabilities_{self.target_domain}.json")
        with open(vuln_file, "w") as f:
            json.dump(vulnerabilities, f, indent=2)
        
        self.log(f"Vulnerability scanning completed. Found {len(vulnerabilities)} potential issues", "SUCCESS")
    
    def generate_report(self):
        """Generate comprehensive report"""
        self.log("Generating reconnaissance report...")
        
        report = {
            'target': self.target_domain,
            'scan_date': datetime.now().isoformat(),
            'summary': {
                'subdomains_found': len(self.subdomains),
                'live_hosts': len(self.live_hosts),
                'hosts_with_open_ports': len(self.open_ports),
                'vulnerabilities_found': len(self.vulnerabilities)
            },
            'subdomains': list(self.subdomains),
            'live_hosts': list(self.live_hosts),
            'open_ports': self.open_ports,
            'tech_stack': self.tech_stack,
            'vulnerabilities': self.vulnerabilities
        }
        
        # Save JSON report
        report_file = os.path.join(self.output_dir, f"recon_report_{self.target_domain}.json")
        with open(report_file, "w") as f:
            json.dump(report, f, indent=2)
        
        # Generate HTML report
        html_report = self.generate_html_report(report)
        html_file = os.path.join(self.output_dir, f"recon_report_{self.target_domain}.html")
        with open(html_file, "w") as f:
            f.write(html_report)
        
        self.log(f"Report generated: {report_file}", "SUCCESS")
        self.log(f"HTML report generated: {html_file}", "SUCCESS")
    
    def generate_html_report(self, report):
        """Generate HTML report"""
        html = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Reconnaissance Report - {report['target']}</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 20px; }}
                .header {{ background: #2c3e50; color: white; padding: 20px; border-radius: 5px; }}
                .section {{ margin: 20px 0; padding: 15px; border: 1px solid #ddd; border-radius: 5px; }}
                .vulnerability {{ background: #ffebee; padding: 10px; margin: 5px 0; border-radius: 3px; }}
                .success {{ background: #e8f5e8; padding: 10px; margin: 5px 0; border-radius: 3px; }}
                .warning {{ background: #fff3cd; padding: 10px; margin: 5px 0; border-radius: 3px; }}
                table {{ width: 100%; border-collapse: collapse; }}
                th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
                th {{ background-color: #f2f2f2; }}
            </style>
        </head>
        <body>
            <div class="header">
                <h1>Reconnaissance Report</h1>
                <p>Target: {report['target']}</p>
                <p>Scan Date: {report['scan_date']}</p>
            </div>
            
            <div class="section">
                <h2>Summary</h2>
                <div class="success">
                    <p>Subdomains Found: {report['summary']['subdomains_found']}</p>
                    <p>Live Hosts: {report['summary']['live_hosts']}</p>
                    <p>Hosts with Open Ports: {report['summary']['hosts_with_open_ports']}</p>
                    <p>Potential Vulnerabilities: {report['summary']['vulnerabilities_found']}</p>
                </div>
            </div>
            
            <div class="section">
                <h2>Subdomains</h2>
                <ul>
                    {''.join([f'<li>{sub}</li>' for sub in report['subdomains']])}
                </ul>
            </div>
            
            <div class="section">
                <h2>Live Hosts</h2>
                <ul>
                    {''.join([f'<li>{host}</li>' for host in report['live_hosts']])}
                </ul>
            </div>
            
            <div class="section">
                <h2>Open Ports</h2>
                <table>
                    <tr><th>Host</th><th>Open Ports</th></tr>
                    {''.join([f'<tr><td>{host}</td><td>{", ".join(map(str, ports))}</td></tr>' for host, ports in report['open_ports'].items()])}
                </table>
            </div>
            
            <div class="section">
                <h2>Vulnerabilities</h2>
                {''.join([f'<div class="vulnerability"><strong>{vuln["type"]}</strong> - {vuln["host"]}<br>{vuln["description"]}<br>Severity: {vuln["severity"]}</div>' for vuln in report['vulnerabilities']])}
            </div>
        </body>
        </html>
        """
        return html
    
    def run_full_recon(self):
        """Run the complete reconnaissance pipeline"""
        self.banner()
        
        try:
            # Phase 1: Subdomain Enumeration
            self.log("=== PHASE 1: SUBDOMAIN ENUMERATION ===", "INFO")
            self.passive_subdomain_enumeration()
            
            # Phase 2: Host Discovery
            self.log("=== PHASE 2: HOST DISCOVERY ===", "INFO")
            self.host_discovery()
            
            # Phase 3: Port Scanning
            self.log("=== PHASE 3: PORT SCANNING ===", "INFO")
            self.port_scanning()
            
            # Phase 4: Service Detection
            self.log("=== PHASE 4: SERVICE DETECTION ===", "INFO")
            self.service_detection()
            
            # Phase 5: Vulnerability Scanning
            self.log("=== PHASE 5: VULNERABILITY SCANNING ===", "INFO")
            self.vulnerability_scanning()
            
            # Phase 6: Report Generation
            self.log("=== PHASE 6: REPORT GENERATION ===", "INFO")
            self.generate_report()
            
            self.log("=== RECONNAISSANCE COMPLETE ===", "SUCCESS")
            self.log(f"Results saved in: {self.output_dir}", "SUCCESS")
            
        except KeyboardInterrupt:
            self.log("Reconnaissance interrupted by user", "WARNING")
        except Exception as e:
            self.log(f"Error during reconnaissance: {e}", "ERROR")

def main():
    """Main function"""
    if len(sys.argv) != 2:
        print("Usage: python recon_pipeline.py <target_domain>")
        print("Example: python recon_pipeline.py example.com")
        sys.exit(1)
    
    target_domain = sys.argv[1]
    
    # Validate domain format
    if not target_domain or '.' not in target_domain:
        print("Error: Please provide a valid domain name")
        sys.exit(1)
    
    # Warning message
    print(f"{Fore.RED}{'='*60}")
    print("WARNING: ETHICAL USE ONLY")
    print("This tool is designed for authorized security testing only.")
    print("Do not use this tool against systems you do not own or")
    print("do not have explicit permission to test.")
    print("='*60}{Style.RESET_ALL}")
    
    response = input("Do you have permission to test this target? (yes/no): ")
    if response.lower() != 'yes':
        print("Exiting. Only use this tool on authorized targets.")
        sys.exit(1)
    
    # Initialize and run reconnaissance
    recon = ReconPipeline(target_domain)
    recon.run_full_recon()

if __name__ == "__main__":
    main()
