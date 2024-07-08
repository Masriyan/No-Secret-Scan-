import requests
from bs4 import BeautifulSoup
import re
import argparse
import pyfiglet
from tqdm import tqdm
import json
import csv
import time
import dns.resolver
from typing import List, Dict, Optional
from requests.exceptions import SSLError

# ASCII Banner
def print_banner() -> None:
    ascii_banner = pyfiglet.figlet_format("No Secret Scan")
    print(ascii_banner)
    print("by sudo3rs\n")

# Function to resolve domain using a custom DNS server
def resolve_domain(domain: str, dns_server: str) -> str:
    resolver = dns.resolver.Resolver()
    resolver.nameservers = [dns_server]
    answers = resolver.resolve(domain, 'A')
    return answers[0].address

# Function to find credentials in HTML content
def find_credentials(url: str, user_agent: str, custom_regex: Optional[str] = None, specific_strings: Optional[List[str]] = None, progress_bar: Optional[tqdm] = None, dns_server: Optional[str] = None, verify_ssl: bool = True) -> Dict[str, List[str]]:
    headers = {'User-Agent': user_agent}
    domain = url.split("//")[-1].split("/")[0]

    if dns_server:
        try:
            ip_address = resolve_domain(domain, dns_server)
            url = url.replace(domain, ip_address)
            headers['Host'] = domain
        except Exception as e:
            print(f"DNS resolution failed: {e}")
            return {}

    for attempt in range(3):
        try:
            response = requests.get(url, headers=headers, verify=verify_ssl)
            response.raise_for_status()
            break
        except SSLError as e:
            if not verify_ssl:
                print(f"SSL error ignored: {e}")
                continue
            print(f"SSL error: {e}")
            return {}
        except requests.exceptions.RequestException as e:
            print(f"Attempt {attempt + 1} failed: {e}")
            time.sleep(5)
    else:
        print(f"Failed to fetch the URL: {url}")
        return {}

    credentials_found = {}
    if response.status_code == 200:
        soup = BeautifulSoup(response.text, 'html.parser')
        text_content = soup.get_text()

        patterns = {
            'Email': r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',
            'API Key': r'(?i)api[_-]?key["\']?\s*[:=]\s*["\'][a-zA-Z0-9_\-]+["\']',
            'Token': r'(?i)token["\']?\s*[:=]\s*["\'][a-zA-Z0-9_\-]+["\']',
            'Admin Path': r'/admin[^\s"\']*',
            'Open .env or env.js': r'(\.env|env\.js)[^\s"\']*',
            'AWS Access Key ID': r'AKIA[0-9A-Z]{16}',
            'AWS Secret Access Key': r'(?i)aws[_-]?secret[_-]?access[_-]?key["\']?\s*[:=]\s*["\'][a-zA-Z0-9/+=]{40}["\']',
            'GCP API Key': r'AIza[0-9A-Za-z-_]{35}',
            '.git Directory': r'/\.git',
        }

        if custom_regex:
            patterns['Custom Regex'] = custom_regex

        total_patterns = len(patterns) + (1 if specific_strings else 0)
        step = 100 // total_patterns
        
        for name, pattern in patterns.items():
            matches = re.findall(pattern, text_content)
            if matches:
                credentials_found[name] = matches
            if progress_bar:
                progress_bar.update(step)

        if specific_strings:
            specific_matches = [s for s in specific_strings if s in text_content]
            if specific_matches:
                credentials_found['Specific Strings'] = specific_matches
            if progress_bar:
                progress_bar.update(step)
    
    return credentials_found

# Function to save results to CSV
def save_to_csv(data: Dict[str, List[str]], filename: str) -> None:
    with open(filename, 'w', newline='') as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(['Type', 'Match'])
        for key, values in data.items():
            for value in values:
                writer.writerow([key, value])

# Function to save results to JSON
def save_to_json(data: Dict[str, List[str]], filename: str) -> None:
    with open(filename, 'w') as jsonfile:
        json.dump(data, jsonfile, indent=4)

# Main function to run the script
def main() -> None:
    print_banner()

    parser = argparse.ArgumentParser(description='Scan websites for secrets and hardcoded credentials.')
    parser.add_argument('url', type=str, help='URL of the website to scan')
    parser.add_argument('-r', '--regex', type=str, help='Custom regex pattern for search', default=None)
    parser.add_argument('-fs', '--find-specific', nargs='+', help='Specific secret strings to find', default=None)
    parser.add_argument('-o', '--output', type=str, help='Output filename with format (e.g., results.json or results.csv)', default=None)
    parser.add_argument('-ua', '--user-agent', type=str, help='Custom User-Agent', default='Mozilla/5.0')
    parser.add_argument('--dns', type=str, help='Custom DNS server', default=None)
    parser.add_argument('--no-verify-ssl', action='store_true', help='Disable SSL certificate verification')

    args = parser.parse_args()

    url = args.url
    custom_regex = args.regex
    specific_strings = args.find_specific
    output_file = args.output
    user_agent = args.user_agent
    dns_server = args.dns
    verify_ssl = not args.no_verify_ssl

    print(f"Scanning {url}...\n")

    with tqdm(total=100, desc="Scanning Progress", unit='%') as progress_bar:
        credentials = find_credentials(url, user_agent, custom_regex, specific_strings, progress_bar, dns_server, verify_ssl)
    
    if credentials:
        for name, matches in credentials.items():
            print(f"{name} found: {matches}")
    else:
        print("No credentials found.")

    if output_file:
        if output_file.endswith('.csv'):
            save_to_csv(credentials, output_file)
        elif output_file.endswith('.json'):
            save_to_json(credentials, output_file)
        else:
            print(f"Unsupported file extension for output: {output_file}")
        print(f"Results saved to {output_file}")

    # Placeholder: Implement progress bar for search engine lookups
    for _ in tqdm(range(100), desc="Looking up search engines"):
        time.sleep(0.1)  # Simulate work

if __name__ == '__main__':
    main()
