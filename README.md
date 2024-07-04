# No Secret Scan

![No Secret Scan Banner](https://github.com/Masriyan/No-Secret-Scan-/blob/main/nosecre.png)

## Overview
**No Secret Scan** is a Python script designed to scan websites for secrets and hardcoded credentials. It helps identify sensitive information such as emails, tokens, API keys, admin paths, and exposed configuration files like `.env` or `env.js`. The script utilizes regex patterns and specific string searches to locate these potentially insecure elements within the HTML content of a given URL.

## Features
- **Customizable Scans**: Supports custom regex patterns and specific strings to tailor searches based on specific needs.
- **DNS Resolution**: Allows resolving domains using custom DNS servers for accurate scanning.
- **Output Options**: Results can be saved in JSON or CSV format for further analysis and reporting.
- **SSL Verification**: Option to enable or disable SSL certificate verification during scans.

## Usage
usage: nosecret.py [-h] [-r REGEX] [-fs FIND_SPECIFIC [FIND_SPECIFIC ...]] [-o OUTPUT] [-ua USER_AGENT] [--dns DNS] [--no-verify-ssl] url

Scan websites for secrets and hardcoded credentials.

positional arguments:
url URL of the website to scan

options:
-h, --help show this help message and exit
-r REGEX, --regex REGEX
Custom regex pattern for search
-fs FIND_SPECIFIC [FIND_SPECIFIC ...], --find-specific FIND_SPECIFIC [FIND_SPECIFIC ...]
Specific secret strings to find
-o OUTPUT, --output OUTPUT
Output filename with format (e.g., results.json or results.csv)
-ua USER_AGENT, --user-agent USER_AGENT
Custom User-Agent
--dns DNS Custom DNS server
--no-verify-ssl Disable SSL certificate verification


### Example
Run the script with the target URL and optional parameters to scan a website for secrets:

python nosecret.py https://example.com -r "custom_regex_pattern" -fs secret_string1 secret_string2 -o results.json


## Installation
1. Clone the repository: git clone https://github.com/Masriyan/No-Secret-Scan-.git

2. Install dependencies:
pip install -r requirements.txt


## Contributions
Contributions and feedback are welcome! Feel free to fork the repository, add new features, or suggest improvements through issues and pull requests.

## License
This project is Unlicensed - see the [LICENSE](LICENSE) file for details.



