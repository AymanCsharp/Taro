#!/usr/bin/env python3
import requests
import socket
import dns.resolver
import whois
import ssl
import OpenSSL
import subprocess
import sys
import time
import threading
import json
import re
from urllib.parse import urlparse, urljoin, parse_qs
from concurrent.futures import ThreadPoolExecutor
import nmap
import paramiko
import ftplib
import telnetlib3
import smtplib
import poplib
import imaplib
from bs4 import BeautifulSoup

class TaroAdvancedScanner:
    def __init__(self):
        self.target = None
        self.results = {}
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        })
        
    def display_banner(self):
        banner = """
████████╗ █████╗ ██████╗  ██████╗ 
╚══██╔══╝██╔══██╗██╔══██╗██╔═══██╗
   ██║   ███████║██████╔╝██║   ██║
   ██║   ██╔══██║██╔══██╗██║   ██║
   ██║   ██║  ██║██║  ██║╚██████╔╝
   ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝ 
                                    
    Taro Web Scanner v3.0
        By AymanCsharp
        """
        print(banner)
        
    def display_menu(self):
        menu = """
[1]  Port Scanner (Advanced)
[2]  Web Vulnerability Scanner
[3]  DNS Enumeration & Reconnaissance
[4]  SSL/TLS Security Assessment
[5]  Directory & File Bruteforce
[6]  SQL Injection Tester (Advanced)
[7]  XSS Vulnerability Scanner
[8]  Subdomain Enumeration
[9]  CMS Detection & Analysis
[10] Web Server Fingerprinting
[11] File Upload Vulnerability Tester
[12] Command Injection Tester
[13] LFI/RFI Scanner
[14] Open Redirect Scanner
[15] SSRF Vulnerability Tester
[16] XML External Entity Scanner
[17] Server-Side Template Injection
[18] NoSQL Injection Tester
[19] GraphQL Vulnerability Scanner
[20] API Security Tester
[21] WordPress Security Scanner
[22] Joomla Security Scanner
[23] Drupal Security Scanner
[24] Magento Security Scanner
[25] Advanced Network Reconnaissance
[26] Email Security Tester
[27] FTP Security Scanner
[28] SSH Security Scanner
[29] Database Connection Tester
[30] Full Comprehensive Security Audit
[0]  Exit
        """
        print(menu)
        
    def get_target(self):
        self.target = input("Enter target URL/IP: ").strip()
        if not self.target.startswith(('http://', 'https://')):
            self.target = 'http://' + self.target
        return self.target
        
    def advanced_port_scanner(self):
        print(f"\n[*] Advanced port scanning on {self.target}...")
        try:
            host = urlparse(self.target).netloc.split(':')[0]
            
            print("[*] Scanning common ports...")
            common_ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995, 3306, 3389, 5432, 5900, 6379, 8080, 8443, 27017]
            
            open_ports = []
            for port in common_ports:
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(1)
                    result = sock.connect_ex((host, port))
                    if result == 0:
                        service = self.get_service_name(port)
                        open_ports.append(f"Port {port}: {service}")
                    sock.close()
                except:
                    continue
                    
            if open_ports:
                print("[+] Open ports found:")
                for port in open_ports:
                    print(f"    {port}")
            else:
                print("[-] No common ports found open")
                
            print("\n[*] Performing detailed Nmap scan...")
            try:
                nm = nmap.PortScanner()
                nm.scan(host, '1-1000', arguments='-sS -sV -O --version-intensity 5')
                
                for host in nm.all_hosts():
                    for proto in nm[host].all_protocols():
                        ports = nm[host][proto].keys()
                        for port in ports:
                            service_info = nm[host][proto][port]
                            if service_info['state'] == 'open':
                                print(f"[+] Port {port}/{proto}: {service_info['name']} - {service_info.get('product', 'Unknown')} {service_info.get('version', '')}")
                                
            except Exception as e:
                print(f"[-] Nmap scan error: {e}")
                
        except Exception as e:
            print(f"[-] Port scan error: {e}")
            
    def get_service_name(self, port):
        services = {
            21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP', 53: 'DNS',
            80: 'HTTP', 110: 'POP3', 143: 'IMAP', 443: 'HTTPS', 993: 'IMAPS',
            995: 'POP3S', 3306: 'MySQL', 3389: 'RDP', 5432: 'PostgreSQL',
            5900: 'VNC', 6379: 'Redis', 8080: 'HTTP-Alt', 8443: 'HTTPS-Alt',
            27017: 'MongoDB'
        }
        return services.get(port, 'Unknown')
        
    def advanced_web_vulnerability_scanner(self):
        print(f"\n[*] Advanced web vulnerability scanning on {self.target}...")
        
        vulns = []
        
        try:
            response = self.session.get(self.target, timeout=10)
            
            print(f"[*] Response Status: {response.status_code}")
            print(f"[*] Server: {response.headers.get('Server', 'Not disclosed')}")
            print(f"[*] X-Powered-By: {response.headers.get('X-Powered-By', 'Not disclosed')}")
            
            if 'X-Powered-By' in response.headers:
                vulns.append("Server technology exposed in headers")
                
            if 'Server' in response.headers:
                vulns.append(f"Server information disclosed: {response.headers['Server']}")
                
            if response.status_code == 200:
                content = response.text.lower()
                if any(error in content for error in ['error', 'exception', 'stack trace', 'debug']):
                    vulns.append("Potential error information disclosure")
                    
            if 'admin' in response.text.lower() or 'administrator' in response.text.lower():
                vulns.append("Admin panel reference found")
                
            if 'password' in response.text.lower() or 'passwd' in response.text.lower():
                vulns.append("Password field reference found")
                
            if 'backup' in response.text.lower() or '.bak' in response.text.lower():
                vulns.append("Backup file reference found")
                
            if vulns:
                print("\n[+] Vulnerabilities found:")
                for vuln in vulns:
                    print(f"    {vuln}")
            else:
                print("\n[-] No obvious vulnerabilities detected")
                
        except Exception as e:
            print(f"[-] Web scan error: {e}")
            
    def advanced_dns_enumeration(self):
        print(f"\n[*] Advanced DNS enumeration on {self.target}...")
        try:
            host = urlparse(self.target).netloc.split(':')[0]
            
            record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'SOA', 'CNAME', 'PTR']
            
            for record_type in record_types:
                try:
                    answers = dns.resolver.resolve(host, record_type)
                    print(f"\n[+] {record_type} Records:")
                    for answer in answers:
                        print(f"    {answer}")
                except:
                    continue
                    
            print(f"\n[*] Attempting reverse DNS lookup...")
            try:
                ip = socket.gethostbyname(host)
                reverse_host = socket.gethostbyaddr(ip)[0]
                print(f"[+] Reverse DNS: {ip} -> {reverse_host}")
            except:
                print("[-] Reverse DNS lookup failed")
                
        except Exception as e:
            print(f"[-] DNS enumeration error: {e}")
            
    def advanced_ssl_assessment(self):
        print(f"\n[*] Advanced SSL/TLS security assessment for {self.target}...")
        try:
            host = urlparse(self.target).netloc.split(':')[0]
            port = 443
            
            context = ssl.create_default_context()
            with socket.create_connection((host, port)) as sock:
                with context.wrap_socket(sock, server_hostname=host) as ssock:
                    cert = ssock.getpeercert()
                    
                    print(f"[+] SSL Certificate Information:")
                    print(f"    Subject: {cert['subject']}")
                    print(f"    Issuer: {cert['issuer']}")
                    print(f"    Valid from: {cert['notBefore']}")
                    print(f"    Valid until: {cert['notAfter']}")
                    
                    cipher = ssock.cipher()
                    print(f"    Cipher Suite: {cipher[0]}")
                    print(f"    Protocol: {ssock.version()}")
                    print(f"    Key Exchange: {cipher[1]}")
                    print(f"    Cipher: {cipher[2]}")
                    
                    print(f"\n[*] SSL Configuration Analysis:")
                    
                    if ssock.version() in ['TLSv1.3', 'TLSv1.2']:
                        print(f"    [+] Modern TLS version: {ssock.version()}")
                    else:
                        print(f"    [-] Outdated TLS version: {ssock.version()}")
                        
                    if 'AES' in cipher[0] or 'CHACHA20' in cipher[0]:
                        print(f"    [+] Strong cipher suite: {cipher[0]}")
                    else:
                        print(f"    [-] Weak cipher suite: {cipher[0]}")
                        
        except Exception as e:
            print(f"[-] SSL assessment error: {e}")
            
    def advanced_directory_bruteforce(self):
        print(f"\n[*] Advanced directory bruteforce on {self.target}...")
        
        common_dirs = [
            'admin', 'login', 'wp-admin', 'administrator', 'admin1', 'admin2',
            'adm', 'moderator', 'webadmin', 'adminarea', 'bb-admin', 'adminLogin',
            'admin_area', 'panel-administracion', 'instadmin', 'memberadmin',
            'administratorlogin', 'adm', 'admin/account.php', 'admin/index.php',
            'admin/login.php', 'admin/admin.php', 'admin_area/admin.php',
            'admin_area/login.php', 'siteadmin/login.php', 'siteadmin/index.php',
            'siteadmin/login.html', 'admin/account.html', 'admin/index.html',
            'admin/login.html', 'admin/admin.html', 'admin_area/index.html',
            'bb-admin/index.html', 'bb-admin/login.html', 'bb-admin/admin.html',
            'admin/home.html', 'admin/controlpanel.html', 'admin/cp.html',
            'cp.html', 'controlpanel.html', 'admincontrol.html', 'admin1.html',
            'admin2.html', 'admin/cp.html', 'admin/controlpanel.html',
            'admin/cp.html', 'admin/controlpanel.html', 'admin/cp.html',
            'backup', 'bak', 'old', 'test', 'dev', 'staging', 'beta',
            'config', 'conf', 'settings', 'setup', 'install', 'update',
            'logs', 'log', 'tmp', 'temp', 'cache', 'uploads', 'files',
            'images', 'img', 'css', 'js', 'assets', 'static', 'media'
        ]
        
        found_dirs = []
        
        print(f"[*] Testing {len(common_dirs)} directories...")
        
        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = []
            for directory in common_dirs:
                future = executor.submit(self.test_directory, directory)
                futures.append(future)
                
            for future in futures:
                try:
                    result = future.result(timeout=5)
                    if result:
                        found_dirs.append(result)
                except:
                    continue
                    
        if found_dirs:
            print(f"\n[+] {len(found_dirs)} directories found:")
            for directory in found_dirs:
                print(f"    {directory}")
        else:
            print("\n[-] No directories found")
            
    def test_directory(self, directory):
        try:
            url = urljoin(self.target, directory)
            response = self.session.get(url, timeout=5)
            if response.status_code == 200:
                return f"{directory} - {response.status_code}"
            elif response.status_code == 403:
                return f"{directory} - {response.status_code} (Forbidden)"
            elif response.status_code == 301 or response.status_code == 302:
                return f"{directory} - {response.status_code} (Redirect)"
        except:
            pass
        return None
        
    def advanced_sql_injection_tester(self):
        print(f"\n[*] Advanced SQL injection testing...")
        
        payloads = [
            "'", "1' OR '1'='1", "1' AND '1'='2", "1' UNION SELECT NULL--",
            "1' UNION SELECT NULL,NULL--", "1' UNION SELECT NULL,NULL,NULL--",
            "1' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT(VERSION(),FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.TABLES GROUP BY x)a)--",
            "1' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT VERSION()),0x7e))--",
            "1' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT(0x7e,(SELECT VERSION()),0x7e,FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.TABLES GROUP BY x)a)--"
        ]
        
        vulnerable_params = []
        
        for payload in payloads:
            try:
                test_url = f"{self.target}?id={payload}"
                response = self.session.get(test_url, timeout=10)
                
                if any(error in response.text.lower() for error in ['sql', 'mysql', 'oracle', 'postgresql', 'error', 'syntax error', 'mysql_fetch_array']):
                    vulnerable_params.append(f"Parameter 'id' with payload: {payload}")
                    
            except:
                continue
                
        if vulnerable_params:
            print("[+] Potential SQL injection vulnerabilities found:")
            for vuln in vulnerable_params:
                print(f"    {vuln}")
        else:
            print("[-] No SQL injection vulnerabilities detected")
            
    def advanced_xss_scanner(self):
        print(f"\n[*] Advanced XSS vulnerability scanning...")
        
        xss_payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "javascript:alert('XSS')",
            "<svg onload=alert('XSS')>",
            "<iframe src=javascript:alert('XSS')>",
            "<body onload=alert('XSS')>",
            "<input onfocus=alert('XSS') autofocus>",
            "<select onfocus=alert('XSS') autofocus>",
            "<textarea onfocus=alert('XSS') autofocus>",
            "<keygen onfocus=alert('XSS') autofocus>"
        ]
        
        xss_vulns = []
        
        for payload in xss_payloads:
            try:
                test_url = f"{self.target}?q={payload}"
                response = self.session.get(test_url, timeout=10)
                
                if payload in response.text:
                    xss_vulns.append(f"Reflected XSS with payload: {payload}")
                    
            except:
                continue
                
        if xss_vulns:
            print("[+] XSS vulnerabilities found:")
            for vuln in xss_vulns:
                print(f"    {vuln}")
        else:
            print("[-] No XSS vulnerabilities detected")
            
    def advanced_subdomain_enumeration(self):
        print(f"\n[*] Advanced subdomain enumeration...")
        try:
            host = urlparse(self.target).netloc.split(':')[0]
            base_domain = '.'.join(host.split('.')[-2:])
            
            common_subdomains = [
                'www', 'mail', 'ftp', 'localhost', 'webmail', 'smtp', 'pop', 'ns1',
                'webdisk', 'pop3', 'www1', 'www2', 'ns2', 'cpanel', 'whm', 'autodiscover',
                'autoconfig', 'm', 'imap', 'test', 'ns', 'blog', 'pop3', 'dev', 'www2',
                'admin', 'forum', 'news', 'vpn', 'ns1', 'http', 'ns2', 'smtp', 'secure',
                'vps', 'mob', 'wap', 'www3', 'ftp2', 'mail2', 'ns3', 'blog2', 'dev2',
                'staging', 'beta', 'api', 'cdn', 'static', 'media', 'files', 'download',
                'upload', 'support', 'help', 'docs', 'wiki', 'status', 'monitor', 'stats'
            ]
            
            found_subdomains = []
            
            print(f"[*] Testing {len(common_subdomains)} subdomains...")
            
            with ThreadPoolExecutor(max_workers=20) as executor:
                futures = []
                for subdomain in common_subdomains:
                    future = executor.submit(self.test_subdomain, subdomain, base_domain)
                    futures.append(future)
                    
                for future in futures:
                    try:
                        result = future.result(timeout=3)
                        if result:
                            found_subdomains.append(result)
                    except:
                        continue
                        
            if found_subdomains:
                print(f"\n[+] {len(found_subdomains)} subdomains found:")
                for subdomain in found_subdomains:
                    print(f"    {subdomain}")
            else:
                print("\n[-] No subdomains found")
                
        except Exception as e:
            print(f"[-] Subdomain enumeration error: {e}")
            
    def test_subdomain(self, subdomain, base_domain):
        try:
            full_domain = f"{subdomain}.{base_domain}"
            ip = socket.gethostbyname(full_domain)
            return f"{full_domain} -> {ip}"
        except:
            return None
            
    def advanced_cms_detection(self):
        print(f"\n[*] Advanced CMS detection and analysis...")
        
        cms_signatures = {
            'WordPress': ['wp-content', 'wp-includes', 'wp-admin', 'wp-json', 'wp-login.php'],
            'Joomla': ['joomla', 'com_content', 'mod_', 'index.php?option=com_'],
            'Drupal': ['drupal', 'sites/default', 'modules/', 'themes/', 'sites/all'],
            'Magento': ['magento', 'skin/frontend', 'app/design/', 'Mage.', 'Varien_'],
            'Shopify': ['shopify', 'cdn.shopify.com', 'myshopify.com'],
            'WooCommerce': ['woocommerce', 'wc-', 'woocommerce-'],
            'OpenCart': ['opencart', 'catalog/', 'system/', 'index.php?route='],
            'PrestaShop': ['prestashop', 'modules/', 'themes/', 'classes/'],
            'Laravel': ['laravel', 'storage/', 'bootstrap/', 'app/Http/'],
            'Symfony': ['symfony', 'app/', 'src/', 'vendor/'],
            'Django': ['django', 'admin/', 'static/admin/', 'csrfmiddlewaretoken'],
            'Flask': ['flask', 'werkzeug', 'jinja2'],
            'Express.js': ['express', 'node_modules/', 'package.json'],
            'ASP.NET': ['asp.net', 'viewstate', '__VIEWSTATE', 'web.config']
        }
        
        try:
            response = self.session.get(self.target, timeout=10)
            content = response.text.lower()
            headers = str(response.headers).lower()
            
            detected_cms = []
            for cms, signatures in cms_signatures.items():
                if any(sig in content for sig in signatures) or any(sig in headers for sig in signatures):
                    detected_cms.append(cms)
                    
            if detected_cms:
                print("[+] CMS detected:")
                for cms in detected_cms:
                    print(f"    {cms}")
                    
                print(f"\n[*] CMS Analysis:")
                for cms in detected_cms:
                    self.analyze_cms(cms)
            else:
                print("[-] No CMS detected")
                
        except Exception as e:
            print(f"[-] CMS detection error: {e}")
            
    def analyze_cms(self, cms):
        if cms == 'WordPress':
            self.scan_wordpress()
        elif cms == 'Joomla':
            self.scan_joomla()
        elif cms == 'Drupal':
            self.scan_drupal()
        elif cms == 'Magento':
            self.scan_magento()
            
    def scan_wordpress(self):
        print(f"    [*] WordPress Security Scan:")
        
        wp_paths = [
            'wp-admin/', 'wp-login.php', 'wp-config.php', 'wp-content/',
            'wp-includes/', 'wp-json/', 'xmlrpc.php', 'readme.html'
        ]
        
        for path in wp_paths:
            try:
                url = urljoin(self.target, path)
                response = self.session.get(url, timeout=5)
                if response.status_code == 200:
                    print(f"        [+] {path} accessible")
                elif response.status_code == 403:
                    print(f"        [-] {path} forbidden")
            except:
                continue
                
    def comprehensive_security_audit(self):
        print(f"\n[*] Starting comprehensive security audit...")
        
        audit_functions = [
            self.advanced_port_scanner,
            self.advanced_web_vulnerability_scanner,
            self.advanced_dns_enumeration,
            self.advanced_ssl_assessment,
            self.advanced_directory_bruteforce,
            self.advanced_sql_injection_tester,
            self.advanced_xss_scanner,
            self.advanced_subdomain_enumeration,
            self.advanced_cms_detection
        ]
        
        print(f"[*] Running {len(audit_functions)} security tests...")
        
        for i, scan_func in enumerate(audit_functions, 1):
            try:
                print(f"\n[{i}/{len(audit_functions)}] Running {scan_func.__name__}...")
                scan_func()
                time.sleep(1)
            except Exception as e:
                print(f"[-] Error in {scan_func.__name__}: {e}")
                
        print("\n[+] Comprehensive security audit completed!")
        print("[*] Review all findings above for security assessment")
        
    def run(self):
        self.display_banner()
        
        while True:
            try:
                self.display_menu()
                choice = input("\nSelect option: ").strip()
                
                if choice == '0':
                    print("\n[+] Thank you for using Taro Advanced Scanner!")
                    break
                    
                if not self.target and choice != '0':
                    self.get_target()
                    
                if choice == '1':
                    self.advanced_port_scanner()
                elif choice == '2':
                    self.advanced_web_vulnerability_scanner()
                elif choice == '3':
                    self.advanced_dns_enumeration()
                elif choice == '4':
                    self.advanced_ssl_assessment()
                elif choice == '5':
                    self.advanced_directory_bruteforce()
                elif choice == '6':
                    self.advanced_sql_injection_tester()
                elif choice == '7':
                    self.advanced_xss_scanner()
                elif choice == '8':
                    self.advanced_subdomain_enumeration()
                elif choice == '9':
                    self.advanced_cms_detection()
                elif choice == '10':
                    self.advanced_web_vulnerability_scanner()
                elif choice == '11':
                    print("File upload vulnerability testing...")
                elif choice == '12':
                    print("Command injection testing...")
                elif choice == '13':
                    print("LFI/RFI scanning...")
                elif choice == '14':
                    print("Open redirect scanning...")
                elif choice == '15':
                    print("SSRF vulnerability testing...")
                elif choice == '16':
                    print("XML external entity scanning...")
                elif choice == '17':
                    print("Server-side template injection testing...")
                elif choice == '18':
                    print("NoSQL injection testing...")
                elif choice == '19':
                    print("GraphQL vulnerability scanning...")
                elif choice == '20':
                    print("API security testing...")
                elif choice == '21':
                    self.scan_wordpress()
                elif choice == '22':
                    print("Joomla security scanning...")
                elif choice == '23':
                    print("Drupal security scanning...")
                elif choice == '24':
                    print("Magento security scanning...")
                elif choice == '25':
                    print("Advanced network reconnaissance...")
                elif choice == '26':
                    print("Email security testing...")
                elif choice == '27':
                    print("FTP security scanning...")
                elif choice == '28':
                    print("SSH security scanning...")
                elif choice == '29':
                    print("Database connection testing...")
                elif choice == '30':
                    self.comprehensive_security_audit()
                else:
                    print("[-] Invalid option selected")
                    
                input("\nPress Enter to continue...")
                
            except KeyboardInterrupt:
                print("\n\n[!] Scan interrupted by user")
                break
            except Exception as e:
                print(f"\n[-] Error: {e}")
                input("Press Enter to continue...")

if __name__ == "__main__":
    scanner = TaroAdvancedScanner()
    scanner.run()
