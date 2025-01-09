import os
import logging
from colorama import Fore, Style, init
import re
import urllib.parse
from typing import Optional

# Initialize colorama
init(autoreset=True)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

def print_banner() -> None:
    """Print the application banner"""
    hacker_face = """
                     .::!!!!!!!:.
                  .!!!!!:..:!!!!!!!!!!!!
                  ~~~~!!!!!!..:::::!!!!!!! 
                      :::::!!:::::::!!!!!!'
                         :::::!!::::!!!!!'
                           ::::!!!!!!!!!!'
                            '::::!!!!!!!'
                              '::::!!!'
                                '::!'
                                  '
         ▄█   █▄     ▄████████  ▄████████    ▄█   ▄█▄    ▄████████    ▄████████ 
        ███   ███   ███    ███ ███    ███   ███ ▄███▀   ███    ███   ███    ███ 
        ███   ███   ███    ███ ███    █▀    ███▐██▀     ███    █▀    ███    ███ 
        ███   ███   ███    ███ ███         ▄█████▀     ▄███▄▄▄      ▄███▄▄▄▄██▀ 
        ███   ███ ▀███████████ ███        ▀▀█████▄    ▀▀███▀▀▀     ▀▀███▀▀▀▀▀   
        ███   ███   ███    ███ ███    █▄    ███▐██▄     ███    █▄  ▀███████████ 
        ███   ███   ███    ███ ███    ███   ███ ▀███▄   ███    ███   ███    ███ 
         ▀█   █▀    ███    █▀  ████████▀    ███   ▀█▀   ██████████   ███    ███ 
                                            ▀                          ███    ███ 

                             ██████╗██╗████████╗██╗
                            ██╔════╝██║╚══██╔══╝██║
                            ██║     ██║   ██║   ██║
                            ██║     ██║   ██║   ██║
                            ╚██████╗██║   ██║   ██║
                             ╚═════╝╚═╝   ╚═╝   ╚═╝
"""
    banner = """
                                    🔒 Anti-Phishing Detection System 🔒
                                     ====================================
                                    Protecting students from online threats
    """
    print(Fore.RED + hacker_face + Fore.GREEN + banner)
def normalize_url(url: str) -> str:
    """Normalize URL for consistent checking"""
    url = url.lower().strip()
    
    # Add http:// if no protocol specified
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url
        
    try:
        parsed = urllib.parse.urlparse(url)
        
        # Remove www.
        domain = parsed.netloc.replace('www.', '')
        
        # Get path without trailing slash
        path = parsed.path.rstrip('/')
        
        # Include query parameters in normalized form if present
        query = '?' + parsed.query if parsed.query else ''
        
        return f"{domain}{path}{query}"
    except Exception as e:
        logging.error(f"Error normalizing URL {url}: {e}")
        return url

def check_suspicious_patterns(url: str) -> Optional[str]:
    """Check URL against suspicious patterns"""
    patterns = {
        # Suspicious TLDs
        r'\.(tk|xyz|pw|top|gq|ml|ga|cf)$': 'Suspicious Top-Level Domain',
        
        # URL Shorteners
        r'(bit\.ly|tinyurl\.com|goo\.gl|t\.co|is\.gd|cli\.gs|ow\.ly|tiny\.cc)': 'URL Shortener Service',
        
        # Suspicious Keywords
        r'(login|sign-?in|verify|account|secure|update|password|verify).*\.(com|net|org)': 'Suspicious Login Page',
        r'(bank|paypal|apple|google|microsoft|amazon).*\.(tk|xyz|pw|top)': 'Suspicious Service Domain',
        
        # Suspicious Patterns
        r'[0-9]{10,}': 'Suspicious Long Numbers',
        r'[a-zA-Z0-9]{25,}': 'Suspicious Random String',
        r'(password|login|username|email).*required': 'Suspicious Form Keywords',
        r'(urgent|action|required|verify|suspend|restrict)': 'Suspicious Urgency Keywords',
        
        # Lookalike Domains
        r'(g00gle|faceb00k|l1nked1n|paypaI|appIe)': 'Suspicious Lookalike Domain',
        
        # Suspicious Characters
        r'[^\x00-\x7F]': 'Non-ASCII Characters in Domain',
        
        # Multiple Subdomains
        r'([a-zA-Z0-9-]+\.){4,}': 'Excessive Subdomains'
    }

    normalized_url = url.lower()
    
    for pattern, reason in patterns.items():
        if re.search(pattern, normalized_url):
            return reason
            
    return None

async def check_url_safety(url: str) -> dict:
    """Comprehensive URL safety check"""
    try:
        normalized_url = normalize_url(url)
        results = {
            'original_url': url,
            'normalized_url': normalized_url,
            'is_suspicious': False,
            'threats': [],
            'safety_score': 100
        }
        
        # Check suspicious patterns
        suspicious = check_suspicious_patterns(normalized_url)
        if suspicious:
            results['is_suspicious'] = True
            results['threats'].append(suspicious)
            results['safety_score'] -= 30
            
        # Additional checks can be added here
        
        return results
    except Exception as e:
        logging.error(f"Error checking URL safety: {e}")
        return {'error': str(e)}
