Python Penetration Testing Toolkit

A Python-based penetration testing toolkit that combines multiple basic security assessment techniques into a single command-line application. This project is designed for educational use and demonstrates how common penetration testing tasks are implemented programmatically using Python.

Overview

The toolkit provides several commonly used penetration testing features such as port scanning, banner grabbing, directory brute forcing, SQL injection testing, XSS testing, hash cracking, and subdomain enumeration. Each module is accessible through a simple menu-driven interface, making the tool easy to understand and use for beginners in cybersecurity.

Features

TCP port scanning on common service ports

Banner grabbing for service identification

Directory brute force discovery

SQL Injection vulnerability testing

Cross-Site Scripting (XSS) detection

MD5 hash cracking using a wordlist

Subdomain enumeration

Tools and Techniques Included

Port Scanner
Scans common ports to identify open services on a target system.

Banner Grabbing
Retrieves service banners to identify running applications and versions.

Directory Bruteforce
Attempts to discover hidden directories using a predefined wordlist.

SQL Injection Scanner
Tests URL parameters for basic SQL injection vulnerabilities.

XSS Scanner
Checks for reflected cross-site scripting vulnerabilities.

Hash Cracker
Attempts to crack MD5 hashes using a simple dictionary attack.

Subdomain Enumeration
Identifies valid subdomains associated with a target domain.

Requirements

Python 3.7 or higher

requests

beautifulsoup4

Install dependencies:

pip install requests beautifulsoup4

Usage

Run the program:

python toolkit.py


Follow the on-screen menu and provide the required inputs for each module.

Disclaimer

This tool is intended strictly for educational purposes and authorized penetration testing only. Performing security testing on systems without permission is illegal and unethical. The author is not responsible for misuse of this software.

Future Improvements

Advanced port scanning with threading

Support for POST-based SQL injection testing

Stored XSS detection

Larger and customizable wordlists

Exportable scan reports
