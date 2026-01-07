import socket
import requests
import hashlib
from bs4 import BeautifulSoup
from urllib.parse import urljoin

# =========================
# 1. PORT SCANNER
# =========================
def port_scanner(target, ports):
    print("\n[+] Port Scanning Started")
    for port in ports:
        try:
            sock = socket.socket()
            sock.settimeout(1)
            sock.connect((target, port))
            print(f"[OPEN] Port {port}")
            sock.close()
        except:
            pass

# =========================
# 2. BANNER GRABBING
# =========================
def banner_grab(target, port):
    try:
        sock = socket.socket()
        sock.settimeout(2)
        sock.connect((target, port))
        sock.send(b"HEAD / HTTP/1.0\r\n\r\n")
        banner = sock.recv(1024)
        print(f"[+] Banner on port {port}:\n{banner.decode(errors='ignore')}")
        sock.close()
    except:
        print("[-] Banner grabbing failed")

# =========================
# 3. DIRECTORY BRUTE FORCE
# =========================
def dir_bruteforce(url, wordlist):
    print("\n[+] Directory Bruteforcing Started")
    for word in wordlist:
        full_url = urljoin(url, word)
        r = requests.get(full_url)
        if r.status_code == 200:
            print(f"[FOUND] {full_url}")

# =========================
# 4. SQL INJECTION SCANNER
# =========================
def sql_injection_scan(url):
    payloads = ["'", "' OR '1'='1", "'--"]
    print("\n[+] SQL Injection Scan")
    for payload in payloads:
        r = requests.get(url + payload)
        if "sql" in r.text.lower() or "mysql" in r.text.lower():
            print(f"[VULNERABLE] SQL Injection at {url}")
            print(f"Payload: {payload}")
            return
    print("[-] No SQL Injection Found")

# =========================
# 5. XSS SCANNER
# =========================
def xss_scan(url):
    payload = "<script>alert(1)</script>"
    r = requests.get(url + payload)
    if payload in r.text:
        print(f"[VULNERABLE] XSS Found at {url}")
    else:
        print("[-] No XSS Found")

# =========================
# 6. HASH CRACKER (MD5)
# =========================
def hash_cracker(hash_value, wordlist):
    print("\n[+] Hash Cracking Started")
    for word in wordlist:
        if hashlib.md5(word.encode()).hexdigest() == hash_value:
            print(f"[CRACKED] Password: {word}")
            return
    print("[-] Password not found")

# =========================
# 7. SUBDOMAIN ENUMERATION
# =========================
def subdomain_enum(domain, subs):
    print("\n[+] Subdomain Enumeration")
    for sub in subs:
        url = f"http://{sub}.{domain}"
        try:
            r = requests.get(url, timeout=2)
            if r.status_code < 400:
                print(f"[FOUND] {url}")
        except:
            pass

# =========================
# MAIN MENU
# =========================
def main():
    print("""
    === PYTHON PENETRATION TESTING TOOLKIT ===
    1. Port Scan
    2. Banner Grab
    3. Directory Bruteforce
    4. SQL Injection Scan
    5. XSS Scan
    6. Hash Cracker
    7. Subdomain Enumeration
    """)

    choice = input("Select option: ")

    if choice == "1":
        target = input("Target IP: ")
        ports = [21, 22, 80, 443, 3306]
        port_scanner(target, ports)

    elif choice == "2":
        target = input("Target IP: ")
        port = int(input("Port: "))
        banner_grab(target, port)

    elif choice == "3":
        url = input("Target URL: ")
        wordlist = ["admin", "login", "uploads", "images"]
        dir_bruteforce(url, wordlist)

    elif choice == "4":
        url = input("Target URL with parameter (e.g. ?id=1): ")
        sql_injection_scan(url)

    elif choice == "5":
        url = input("Target URL with parameter: ")
        xss_scan(url)

    elif choice == "6":
        hash_value = input("MD5 Hash: ")
        wordlist = ["admin", "password", "123456", "test"]
        hash_cracker(hash_value, wordlist)

    elif choice == "7":
        domain = input("Domain: ")
        subs = ["www", "mail", "ftp", "test", "dev"]
        subdomain_enum(domain, subs)

    else:
        print("Invalid choice")

if __name__ == "__main__":
    main()
