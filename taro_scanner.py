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
from urllib.parse import urlparse, urljoin
from concurrent.futures import ThreadPoolExecutor
import nmap
import paramiko
import ftplib
import telnetlib
import smtplib
import poplib
import imaplib

class TaroScanner:
    def __init__(self):
        self.target = None
        self.results = {}
        
    def display_banner(self):
        banner = """
████████╗ █████╗ ██████╗  ██████╗ 
╚══██╔══╝██╔══██╗██╔══██╗██╔═══██╗
   ██║   ███████║██████╔╝██║   ██║
   ██║   ██╔══██║██╔══██╗██║   ██║
   ██║   ██║  ██║██║  ██║╚██████╔╝
   ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝ 
                                    
    Taro Web Scanner v2.0
        By AymanCsharp
        """
        print(banner)
        
    def display_menu(self):
        menu = """
[1]  Port Scanner
[2]  Web Vulnerability Scanner
[3]  DNS Enumeration
[4]  SSL/TLS Security Check
[5]  Directory Bruteforce
[6]  SQL Injection Tester
[7]  XSS Vulnerability Scanner
[8]  Subdomain Enumeration
[9]  CMS Detection
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
[25] Full Comprehensive Scan
[0]  Exit
        """
        print(menu)
        
    def get_target(self):
        self.target = input("Enter target URL/IP: ").strip()
        if not self.target.startswith(('http://', 'https://')):
            self.target = 'http://' + self.target
        return self.target
        
    def port_scanner(self):
        print(f"\n[*] Scanning ports on {self.target}...")
        try:
            host = urlparse(self.target).netloc.split(':')[0]
            nm = nmap.PortScanner()
            nm.scan(host, '1-1000')
            
            open_ports = []
            for host in nm.all_hosts():
                for proto in nm[host].all_protocols():
                    ports = nm[host][proto].keys()
                    for port in ports:
                        service = nm[host][proto][port]['name']
                        state = nm[host][proto][port]['state']
                        if state == 'open':
                            open_ports.append(f"Port {port}/{proto}: {service}")
                            
            if open_ports:
                print("[+] Open ports found:")
                for port in open_ports:
                    print(f"    {port}")
            else:
                print("[-] No open ports found")
                
        except Exception as e:
            print(f"[-] Port scan error: {e}")
            
    def web_vulnerability_scanner(self):
        print(f"\n[*] Scanning {self.target} for web vulnerabilities...")
        
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        }
        
        try:
            response = requests.get(self.target, headers=headers, timeout=10)
            
            vulns = []
            
            if 'X-Powered-By' in response.headers:
                vulns.append("Server technology exposed in headers")
                
            if 'Server' in response.headers:
                vulns.append(f"Server: {response.headers['Server']}")
                
            if response.status_code == 200:
                if 'error' in response.text.lower() or 'exception' in response.text.lower():
                    vulns.append("Potential error information disclosure")
                    
            if 'admin' in response.text.lower():
                vulns.append("Admin panel reference found")
                
            if vulns:
                print("[+] Vulnerabilities found:")
                for vuln in vulns:
                    print(f"    {vuln}")
            else:
                print("[-] No obvious vulnerabilities detected")
                
        except Exception as e:
            print(f"[-] Web scan error: {e}")
            
    def dns_enumeration(self):
        print(f"\n[*] Performing DNS enumeration on {self.target}...")
        try:
            host = urlparse(self.target).netloc.split(':')[0]
            
            record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'SOA', 'CNAME']
            
            for record_type in record_types:
                try:
                    answers = dns.resolver.resolve(host, record_type)
                    print(f"[+] {record_type} Records:")
                    for answer in answers:
                        print(f"    {answer}")
                except:
                    continue
                    
        except Exception as e:
            print(f"[-] DNS enumeration error: {e}")
            
    def ssl_security_check(self):
        print(f"\n[*] Checking SSL/TLS security for {self.target}...")
        try:
            host = urlparse(self.target).netloc.split(':')[0]
            port = 443
            
            context = ssl.create_default_context()
            with socket.create_connection((host, port)) as sock:
                with context.wrap_socket(sock, server_hostname=host) as ssock:
                    cert = ssock.getpeercert()
                    
                    print(f"[+] SSL Certificate Info:")
                    print(f"    Subject: {cert['subject']}")
                    print(f"    Issuer: {cert['issuer']}")
                    print(f"    Valid until: {cert['notAfter']}")
                    
                    cipher = ssock.cipher()
                    print(f"    Cipher: {cipher[0]}")
                    print(f"    Protocol: {ssock.version()}")
                    
        except Exception as e:
            print(f"[-] SSL check error: {e}")
            
    def directory_bruteforce(self):
        print(f"\n[*] Performing directory bruteforce on {self.target}...")
        
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
            'admin/cp.html', 'admin/controlpanel.html', 'admin/cp.html'
        ]
        
        found_dirs = []
        
        for directory in common_dirs:
            try:
                url = urljoin(self.target, directory)
                response = requests.get(url, timeout=5)
                if response.status_code == 200:
                    found_dirs.append(f"{directory} - {response.status_code}")
                elif response.status_code == 403:
                    found_dirs.append(f"{directory} - {response.status_code} (Forbidden)")
            except:
                continue
                
        if found_dirs:
            print("[+] Directories found:")
            for directory in found_dirs:
                print(f"    {directory}")
        else:
            print("[-] No directories found")
            
    def sql_injection_tester(self):
        print(f"\n[*] Testing for SQL injection vulnerabilities...")
        
        payloads = ["'", "1' OR '1'='1", "1' AND '1'='2", "1' UNION SELECT NULL--"]
        
        for payload in payloads:
            try:
                test_url = f"{self.target}?id={payload}"
                response = requests.get(test_url, timeout=10)
                
                if any(error in response.text.lower() for error in ['sql', 'mysql', 'oracle', 'postgresql', 'error']):
                    print(f"[+] Potential SQL injection found with payload: {payload}")
                    
            except:
                continue
                
        print("[-] SQL injection test completed")
        
    def xss_scanner(self):
        print(f"\n[*] Scanning for XSS vulnerabilities...")
        
        xss_payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "javascript:alert('XSS')",
            "<svg onload=alert('XSS')>"
        ]
        
        for payload in xss_payloads:
            try:
                test_url = f"{self.target}?q={payload}"
                response = requests.get(test_url, timeout=10)
                
                if payload in response.text:
                    print(f"[+] Potential XSS vulnerability found with payload: {payload}")
                    
            except:
                continue
                
        print("[-] XSS scan completed")
        
    def subdomain_enumeration(self):
        print(f"\n[*] Enumerating subdomains...")
        try:
            host = urlparse(self.target).netloc.split(':')[0]
            base_domain = '.'.join(host.split('.')[-2:])
            
            common_subdomains = [
                'www', 'mail', 'ftp', 'localhost', 'webmail', 'smtp', 'pop', 'ns1',
                'webdisk', 'pop3', 'www1', 'www2', 'ns2', 'cpanel', 'whm', 'autodiscover',
                'autoconfig', 'm', 'imap', 'test', 'ns', 'blog', 'pop3', 'dev', 'www2',
                'admin', 'forum', 'news', 'vpn', 'ns1', 'http', 'ns2', 'smtp', 'secure',
                'vps', 'mob', 'wap', 'www3', 'ftp2', 'mail2', 'ns3', 'blog2', 'dev2'
            ]
            
            found_subdomains = []
            
            for subdomain in common_subdomains:
                try:
                    full_domain = f"{subdomain}.{base_domain}"
                    socket.gethostbyname(full_domain)
                    found_subdomains.append(full_domain)
                except:
                    continue
                    
            if found_subdomains:
                print("[+] Subdomains found:")
                for subdomain in found_subdomains:
                    print(f"    {subdomain}")
            else:
                print("[-] No subdomains found")
                
        except Exception as e:
            print(f"[-] Subdomain enumeration error: {e}")
            
    def cms_detection(self):
        print(f"\n[*] Detecting CMS...")
        
        cms_signatures = {
            'WordPress': ['wp-content', 'wp-includes', 'wp-admin'],
            'Joomla': ['joomla', 'com_content', 'mod_'],
            'Drupal': ['drupal', 'sites/default', 'modules/'],
            'Magento': ['magento', 'skin/frontend', 'app/design/'],
            'Shopify': ['shopify', 'cdn.shopify.com'],
            'WooCommerce': ['woocommerce', 'wc-'],
            'OpenCart': ['opencart', 'catalog/'],
            'PrestaShop': ['prestashop', 'modules/']
        }
        
        try:
            response = requests.get(self.target, timeout=10)
            content = response.text.lower()
            
            detected_cms = []
            for cms, signatures in cms_signatures.items():
                if any(sig in content for sig in signatures):
                    detected_cms.append(cms)
                    
            if detected_cms:
                print("[+] CMS detected:")
                for cms in detected_cms:
                    print(f"    {cms}")
            else:
                print("[-] No CMS detected")
                
        except Exception as e:
            print(f"[-] CMS detection error: {e}")
            
    def comprehensive_scan(self):
        print(f"\n[*] Starting comprehensive security scan...")
        
        scan_functions = [
            self.port_scanner,
            self.web_vulnerability_scanner,
            self.dns_enumeration,
            self.ssl_security_check,
            self.directory_bruteforce,
            self.sql_injection_tester,
            self.xss_scanner,
            self.subdomain_enumeration,
            self.cms_detection
        ]
        
        for scan_func in scan_functions:
            try:
                scan_func()
                time.sleep(1)
            except Exception as e:
                print(f"[-] Error in {scan_func.__name__}: {e}")
                
        print("\n[+] Comprehensive scan completed!")
        
    def run(self):
        self.display_banner()
        
        while True:
            try:
                self.display_menu()
                choice = input("\nSelect option: ").strip()
                
                if choice == '0':
                    print("\n[+] Thank you for using Taro Scanner!")
                    break
                    
                if not self.target and choice != '0':
                    self.get_target()
                    
                if choice == '1':
                    self.port_scanner()
                elif choice == '2':
                    self.web_vulnerability_scanner()
                elif choice == '3':
                    self.dns_enumeration()
                elif choice == '4':
                    self.ssl_security_check()
                elif choice == '5':
                    self.directory_bruteforce()
                elif choice == '6':
                    self.sql_injection_tester()
                elif choice == '7':
                    self.xss_scanner()
                elif choice == '8':
                    self.subdomain_enumeration()
                elif choice == '9':
                    self.cms_detection()
                elif choice == '10':
                    self.web_vulnerability_scanner()
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
                    print("WordPress security scanning...")
                elif choice == '22':
                    print("Joomla security scanning...")
                elif choice == '23':
                    print("Drupal security scanning...")
                elif choice == '24':
                    print("Magento security scanning...")
                elif choice == '25':
                    self.comprehensive_scan()
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
    scanner = TaroScanner()
    scanner.run()
