# Taro Web  Scanner

A powerful and comprehensive web vulnerability scanner with an ASCII art interface designed for cybersecurity professionals

## Features

- **Port Scanner**: Comprehensive port scanning with service detection
- **Web Vulnerability Scanner**: Detects common web vulnerabilities
- **DNS Enumeration**: DNS record enumeration and subdomain discovery
- **SSL/TLS Security Check**: Certificate analysis and security assessment
- **Directory Bruteforce**: Common directory and file discovery
- **SQL Injection Tester**: Automated SQL injection vulnerability detection
- **XSS Vulnerability Scanner**: Cross-site scripting vulnerability detection
- **Subdomain Enumeration**: Subdomain discovery and enumeration
- **CMS Detection**: Content Management System identification
- **Comprehensive Security Scan**: Full security assessment

## Installation

1. **Clone or download the repository**
2. **Install Python dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

3. **Install Nmap (required for port scanning):**
   - **Windows**: Download from https://nmap.org/download.html
   - **Linux**: `sudo apt-get install nmap`
   - **macOS**: `brew install nmap`

## Usage

1. **Run the scanner:**
   ```bash
   python taro_scanner.py
   ```

2. **Enter target URL/IP when prompted**

3. **Select scanning option from the menu**

4. **View results and vulnerabilities detected**

## Menu Options

- `1` - Port Scanner
- `2` - Web Vulnerability Scanner
- `3` - DNS Enumeration
- `4` - SSL/TLS Security Check
- `5` - Directory Bruteforce
- `6` - SQL Injection Tester
- `7` - XSS Vulnerability Scanner
- `8` - Subdomain Enumeration
- `9` - CMS Detection
- `10` - Web Server Fingerprinting
- `11` - File Upload Vulnerability Tester
- `12` - Command Injection Tester
- `13` - LFI/RFI Scanner
- `14` - Open Redirect Scanner
- `15` - SSRF Vulnerability Tester
- `16` - XML External Entity Scanner
- `17` - Server-Side Template Injection
- `18` - NoSQL Injection Tester
- `19` - GraphQL Vulnerability Scanner
- `20` - API Security Tester
- `21` - WordPress Security Scanner
- `22` - Joomla Security Scanner
- `23` - Drupal Security Scanner
- `24` - Magento Security Scanner
- `25` - Full Comprehensive Scan
- `0` - Exit

## Security Notice

This tool is designed for authorized security testing and penetration testing purposes only. Always ensure you have proper authorization before scanning any target systems. Unauthorized scanning may be illegal in many jurisdictions.

## Requirements

- Python 3.7+
- Nmap
- Internet connection for target scanning

## Disclaimer

This tool is provided for educational and authorized security testing purposes only. The authors are not responsible for any misuse or damage caused by this tool. Users must comply with all applicable laws and regulations.
