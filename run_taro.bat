@echo off
title Taro Web Scanner
color 0a

echo.
echo [*] Starting Taro Web Vulnerability Scanner...
echo.

echo [*] Checking and installing required Python libraries...
python -m pip install --upgrade pip

pip install requests
pip install dnspython
pip install python-whois
pip install pyOpenSSL
pip install python-nmap
pip install paramiko
pip install beautifulsoup4
pip install lxml
pip install urllib3
pip install cryptography
pip install telnetlib3

echo.
echo [*] All required libraries installed (if no errors appeared).
echo.

echo [*] Running Taro Scanner...
python taro_scanner.py

pause