import os
from colorama import Fore, Style, init
import re
import urllib.parse
from typing import Optional

# Initialize colorama
init(autoreset=True)

def print_banner() -> None:
    """Print the application banner"""
    banner = """
    🔒 Anti-Phishing Protection System 🔒
    ====================================
    Protecting students from online threats
    """
    print(Fore.GREEN + banner)

def normalize_url(url: str) -> str:
    """Normalize URL for consistent checking"""
    url = url.lower().strip()
    parsed = urllib.parse.urlparse(url if '://' in url else 'http://' + url)
    return f"{parsed.netloc}{parsed.path}"

def check_suspicious_patterns(url: str) -> Optional[str]:
    """Check URL against suspicious patterns"""
    patterns = {
        r'\.tk$': 'Suspicious TLD',
        r'\.xyz$': 'Suspicious TLD',
        r'bit\.ly': 'URL shortener',
        r'tiny\.cc': 'URL shortener',
        r'password.*required': 'Suspicious keywords',
        r'login.*verify': 'Suspicious keywords',
        r'[0-9]{10,}': 'Suspicious long numbers',
        r'[a-zA-Z0-9]{25,}': 'Suspicious random string'
    }

    for pattern, reason in patterns.items():
        if re.search(pattern, url):
            return reason
    return None
