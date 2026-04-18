import re
import secrets
import string
import json
import ssl
import socket
import requests
try:
    import whois as python_whois
except ImportError:
    python_whois = None
from urllib.parse import urlparse
from datetime import datetime, timedelta
import hashlib

import random
import math
import logging
import ipaddress
import secrets
import subprocess
import dns.resolver
import dns.exception
from datetime import datetime, timezone


# Set up logging for debugging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

class SecurityAnalyzer:
    def __init__(self):
        self.common_passwords = [
            'password', '123456', 'password123', 'admin', 'qwerty',
            'letmein', 'welcome', 'monkey', '1234567890', 'abc123',
            'football', 'iloveyou', 'admin', 'welcome', 'sunshine',
            'princess', 'dragon', 'passw0rd', 'abc123', 'football'
        ]
        
        self.phishing_indicators = [
            'secure-bank-login', 'paypal-security', 'amazon-verification',
            'microsoft-account', 'google-security', 'facebook-security',
            'apple-id-verify', 'netflix-billing', 'spotify-premium',
            'phishing', 'suspicious', 'verify-account', 'urgent-action'
        ]
        
        self.malware_indicators = [
            'malware', 'virus', 'trojan', 'ransomware', 'spyware',
            'adware', 'rootkit', 'keylogger', 'botnet', 'exploit'
        ]
        
        # Comprehensive trusted domains list
        self.trusted_domains = {
            'google.com', 'www.google.com', 'youtube.com', 'gmail.com',
            'microsoft.com', 'office.com', 'live.com', 'outlook.com',
            'apple.com', 'icloud.com', 'amazon.com', 'amazonaws.com',
            'facebook.com', 'instagram.com', 'twitter.com', 'linkedin.com',
            'github.com', 'stackoverflow.com', 'wikipedia.org',
            'paypal.com', 'chase.com', 'bankofamerica.com', 'wellsfargo.com',
            'netflix.com', 'spotify.com', 'hulu.com', 'disney.com',
            'salesforce.com', 'oracle.com', 'ibm.com', 'dropbox.com',
            'zoom.us', 'slack.com', 'cloudflare.com'
        }
        
        # Government and educational TLDs
        self.highly_trusted_tlds = {'.gov', '.mil', '.edu', '.ac.uk', '.gov.uk'}
        
        # Suspicious TLDs
        self.suspicious_tlds = {
            '.tk', '.ml', '.ga', '.cf', '.click', '.download', '.loan',
            '.win', '.racing', '.stream', '.science', '.party', '.review'
        }
    
    def _is_trusted_domain(self, domain):
        """Check if domain is in trusted list"""
        if ':' in domain:
            domain = domain.split(':')[0]
        
        if domain in self.trusted_domains:
            return True
        
        if domain.startswith('www.'):
            clean_domain = domain[4:]
            if clean_domain in self.trusted_domains:
                return True
        
        for trusted in self.trusted_domains:
            if domain.endswith('.' + trusted):
                return True
        
        return False
    
    def analyze_url_comprehensive(self, url):
        """Comprehensive URL analysis with detailed mistake descriptions"""
        try:
            if not url.startswith(('http://', 'https://')):
                url = 'https://' + url
            
            parsed = urlparse(url)
            domain = parsed.netloc.lower()
            
            if ':' in domain:
                domain = domain.split(':')[0]
            
            clean_domain = domain.replace('www.', '')
            
            result = {
                'url': url,
                'is_safe': True,
                'threat_types': [],
                'security_score': 50,
                'phishing_status': 'Clean',
                'ssl_status': 'Unknown',
                'domain_age': None,
                'malware_status': 'Clean',
                'details': {},
                'mistake_description': '',
                'recommendations': [],
                'detailed_analysis': {}
            }
            
            is_trusted = self._is_trusted_domain(clean_domain) or self._is_trusted_domain(domain)
            is_highly_trusted = any(clean_domain.endswith(tld) for tld in self.highly_trusted_tlds)
            
            if is_highly_trusted:
                security_score = 98
                result['recommendations'].append('This is a highly trusted government or educational domain.')
            elif is_trusted:
                security_score = 85
                result['recommendations'].append('This is a well-known trusted domain.')
            else:
                security_score = 50
                result['recommendations'].append('Unknown domain - exercise caution when entering personal information.')
            
            # Check SSL certificate
            ssl_result = self._check_ssl_certificate(domain)
            result['ssl_status'] = ssl_result['status']
            result['detailed_analysis']['ssl'] = ssl_result
            
            if ssl_result['status'] == 'Valid':
                security_score += 10
                result['recommendations'].append('SSL certificate is valid and secure.')
            elif ssl_result['status'] == 'Expired':
                security_score -= 25
                result['mistake_description'] += 'SSL certificate has expired, which means the connection is not secure. '
                result['recommendations'].append('Avoid entering sensitive information on sites with expired SSL certificates.')
            elif ssl_result['status'] == 'No SSL':
                security_score -= 15
                result['mistake_description'] += 'No SSL certificate found, connection is not encrypted. '
                result['recommendations'].append('Only visit HTTPS sites when entering personal or financial information.')
            
            # Check for phishing indicators
            phishing_result = self._check_phishing(url, domain)
            result['phishing_status'] = phishing_result['status']
            result['detailed_analysis']['phishing'] = phishing_result
            
            if phishing_result['suspicious'] and not is_trusted:
                result['is_safe'] = False
                result['threat_types'].append('Phishing')
                security_score -= 30
                result['mistake_description'] += 'This URL contains phishing indicators that suggest it may be impersonating a legitimate service. '
                result['recommendations'].append('Verify the URL carefully and check for official domain names.')
                result['recommendations'].append('Be cautious of URLs with suspicious subdomains or misspellings.')
            
            # Check for malware indicators
            malware_result = self._check_malware_indicators(url, domain)
            result['malware_status'] = malware_result['status']
            result['detailed_analysis']['malware'] = malware_result
            
            if malware_result['suspicious']:
                result['is_safe'] = False
                result['threat_types'].append('Malware')
                security_score -= 40
                result['mistake_description'] += 'This URL contains malware-related keywords that suggest potential threats. '
                result['recommendations'].append('Run a full antivirus scan if you have visited this site.')
                result['recommendations'].append('Avoid downloading files from suspicious websites.')
            
            # Check domain age
            domain_age_result = self._get_domain_age(clean_domain)
            result['detailed_analysis']['domain_age_details'] = domain_age_result
            
            # Get IP address and DNS information
            network_info = self._get_network_information(clean_domain)
            result['detailed_analysis']['network_info'] = network_info
            
            # Check for additional security indicators
            security_indicators = self._check_advanced_security_indicators(url, clean_domain)
            result['detailed_analysis']['advanced_security'] = security_indicators
            
            if domain_age_result['age_days'] is not None:
                domain_age = domain_age_result['age_days']
                result['domain_age'] = domain_age
                
                if domain_age < 30 and not is_trusted:
                    security_score -= 15
                    result['mistake_description'] += f'This domain is very new (only {domain_age} days old), which is often associated with malicious sites. '
                    result['recommendations'].append('Be extra cautious with very new domains that ask for personal information.')
                elif domain_age > 365:
                    security_score += 5
                    result['recommendations'].append('This domain has been established for over a year, which is generally positive.')
            else:
                result['recommendations'].append('Domain age information is not available - exercise normal caution.')
            
            # Check for suspicious TLD
            tld = '.' + clean_domain.split('.')[-1] if '.' in clean_domain else ''
            if tld in self.suspicious_tlds and not is_trusted:
                security_score -= 20
                result['threat_types'].append('Suspicious TLD')
                result['mistake_description'] += f'The domain uses a suspicious top-level domain ({tld}) commonly associated with malicious sites. '
                result['recommendations'].append('Be wary of domains using unusual or free top-level domains.')
            
            # HTTPS bonus
            if parsed.scheme == 'https':
                security_score += 5
                result['recommendations'].append('Site uses HTTPS encryption, which is good for security.')
            else:
                result['mistake_description'] += 'Site does not use HTTPS encryption, making it vulnerable to eavesdropping. '
                result['recommendations'].append('Always prefer HTTPS sites for sensitive activities.')
            
            # Ensure score bounds
            security_score = max(0, min(100, security_score))
            result['security_score'] = security_score
            
            # Determine overall safety
            if security_score < 30:
                result['is_safe'] = False
                if not result['mistake_description']:
                    result['mistake_description'] = 'This URL has multiple security concerns that make it potentially dangerous to visit.'
            
            # Add general recommendations if none exist
            if not result['recommendations']:
                result['recommendations'].append('Always verify URLs before entering personal information.')
                result['recommendations'].append('Use up-to-date antivirus software and browser security features.')
            
            return result
            
        except Exception as e:
            logger.error(f"Error analyzing URL {url}: {str(e)}")
            return {
                'url': url,
                'is_safe': False,
                'threat_types': ['Analysis Error'],
                'security_score': 0,
                'phishing_status': 'Error',
                'ssl_status': 'Error',
                'domain_age': None,
                'malware_status': 'Error',
                'details': {'error': str(e)},
                'mistake_description': f'Analysis failed due to technical error: {str(e)}',
                'recommendations': ['Try analyzing the URL again or consult with a cybersecurity expert.'],
                'detailed_analysis': {'error': str(e)}
            }
    
    

    def _get_domain_age(self, domain):
        """Get domain age information using python-whois"""
        if python_whois is None:
            return {
                'age_days': None,
                'creation_date': None,
                'expiry_date': None,
                'registrar': None,
                'status': 'WHOIS unavailable'
            }

        try:
            domain_info = python_whois.whois(domain)

            if not domain_info:
                return {
                    'age_days': None,
                    'creation_date': None,
                    'expiry_date': None,
                    'registrar': None,
                    'status': 'No WHOIS data found'
                }

            # Extract values safely
            creation_date = getattr(domain_info, 'creation_date', None)
            expiry_date = getattr(domain_info, 'expiration_date', None)
            registrar = getattr(domain_info, 'registrar', None)

            # Handle list responses (some WHOIS return lists)
            if isinstance(creation_date, list):
                creation_date = creation_date[0]
            if isinstance(expiry_date, list):
                expiry_date = expiry_date[0]

            age_days = None

            if creation_date:
                # Handle timezone-aware vs naive datetime
                if isinstance(creation_date, datetime):
                    now = datetime.now(timezone.utc)
                    if creation_date.tzinfo is None:
                        creation_date = creation_date.replace(tzinfo=timezone.utc)
                    try:
                        age_days = (now - creation_date).days
                    except Exception as tz_err:
                        logger.debug(f"Timezone subtraction error: {tz_err}")
                        age_days = None

                elif isinstance(creation_date, str):
                    # Try parsing date strings
                    for fmt in ('%Y-%m-%d %H:%M:%S', '%Y-%m-%d'):
                        try:
                            parsed = datetime.strptime(creation_date, fmt)
                            age_days = (datetime.now() - parsed).days
                            break
                        except ValueError:
                            continue

            return {
                'age_days': age_days,
                'creation_date': creation_date.isoformat() if isinstance(creation_date, datetime) else str(creation_date),
                'expiry_date': expiry_date.isoformat() if isinstance(expiry_date, datetime) else str(expiry_date),
                'registrar': registrar,
                'status': 'Success' if age_days is not None else 'Limited data'
            }

        except Exception as e:
            logger.debug(f"Could not get domain age for {domain}: {str(e)}")
            return {
                'age_days': None,
                'creation_date': None,
                'expiry_date': None,
                'registrar': None,
                'status': f'Error: {str(e)}'
            }

            
   
    
    def _get_network_information(self, domain):
        """Get comprehensive network information for a domain"""
        network_info = {
            'ip_addresses': [],
            'dns_records': {},
            'geolocation': {},
            'port_scan': {},
            'status': 'Unknown'
        }
        
        try:
            # Get IP addresses
            try:
                ip_addresses = socket.gethostbyname_ex(domain)
                network_info['ip_addresses'] = ip_addresses[2]
                network_info['canonical_name'] = ip_addresses[0]
            except socket.gaierror as e:
                logger.debug(f"Could not resolve IP for {domain}: {str(e)}")
                network_info['ip_addresses'] = []
            
            # Get DNS records
            dns_records = {}
            record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME']
            
            for record_type in record_types:
                try:
                    answers = dns.resolver.resolve(domain, record_type)
                    dns_records[record_type] = [str(rdata) for rdata in answers]
                except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.DNSException):
                    dns_records[record_type] = []
            
            network_info['dns_records'] = dns_records
            
            # Basic port scanning for common ports
            if network_info['ip_addresses']:
                main_ip = network_info['ip_addresses'][0]
                common_ports = [80, 443, 21, 22, 25, 53, 110, 143, 993, 995]
                open_ports = []
                
                for port in common_ports:
                    try:
                        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        sock.settimeout(1)
                        result = sock.connect_ex((main_ip, port))
                        if result == 0:
                            open_ports.append(port)
                        sock.close()
                    except Exception:
                        pass
                
                network_info['port_scan'] = {
                    'open_ports': open_ports,
                    'scanned_ports': common_ports,
                    'ip_scanned': main_ip
                }
            
            network_info['status'] = 'Success'
            
        except Exception as e:
            logger.debug(f"Network information error for {domain}: {str(e)}")
            network_info['status'] = f'Error: {str(e)}'
        
        return network_info
    
    def _check_advanced_security_indicators(self, url, domain):
        """Check for advanced security indicators"""
        indicators = {
            'url_structure': {},
            'domain_reputation': {},
            'hosting_analysis': {},
            'security_headers': {},
            'status': 'Unknown'
        }
        
        try:
            # Analyze URL structure
            parsed = urlparse(url)
            indicators['url_structure'] = {
                'scheme': parsed.scheme,
                'has_port': bool(parsed.port),
                'port': parsed.port,
                'path_depth': len([p for p in parsed.path.split('/') if p]),
                'has_query': bool(parsed.query),
                'has_fragment': bool(parsed.fragment),
                'subdomain_count': len(domain.split('.')) - 2 if '.' in domain else 0,
                'suspicious_chars': bool(re.search(r'[^\w\.-]', domain.replace('-', '').replace('.', '')))
            }
            
            # Check domain reputation indicators
            reputation_score = 50
            reputation_factors = []
            
            # Length-based indicators
            if len(domain) > 50:
                reputation_score -= 10
                reputation_factors.append('Very long domain name')
            elif len(domain) > 30:
                reputation_score -= 5
                reputation_factors.append('Long domain name')
            
            # Character analysis
            if '-' in domain and domain.count('-') > 3:
                reputation_score -= 15
                reputation_factors.append('Excessive hyphens')
            
            if any(char.isdigit() for char in domain.replace('.', '')):
                digit_count = sum(1 for char in domain.replace('.', '') if char.isdigit())
                if digit_count > 3:
                    reputation_score -= 10
                    reputation_factors.append('Many digits in domain')
            
            # Check for homograph attacks (basic)
            suspicious_chars = ['0', '1', 'l', 'I', 'o', 'O']
            if any(char in domain for char in suspicious_chars):
                reputation_factors.append('Contains potentially confusing characters')
                reputation_score -= 5
            
            indicators['domain_reputation'] = {
                'score': max(0, reputation_score),
                'factors': reputation_factors
            }
            
            # Try to get security headers
            try:
                response = requests.head(url, timeout=5, allow_redirects=True)
                security_headers = {
                    'strict-transport-security': response.headers.get('Strict-Transport-Security'),
                    'x-frame-options': response.headers.get('X-Frame-Options'),
                    'x-content-type-options': response.headers.get('X-Content-Type-Options'),
                    'content-security-policy': response.headers.get('Content-Security-Policy'),
                    'x-xss-protection': response.headers.get('X-XSS-Protection'),
                    'server': response.headers.get('Server'),
                    'status_code': response.status_code
                }
                
                # Count security headers present
                headers_present = sum(1 for v in security_headers.values() if v is not None and v != response.status_code)
                indicators['security_headers'] = {
                    'headers': security_headers,
                    'security_score': min(100, headers_present * 20),
                    'headers_present': headers_present
                }
                
            except Exception as e:
                indicators['security_headers'] = {
                    'error': str(e),
                    'security_score': 0,
                    'headers_present': 0
                }
            
            indicators['status'] = 'Success'
            
        except Exception as e:
            logger.debug(f"Advanced security check error for {domain}: {str(e)}")
            indicators['status'] = f'Error: {str(e)}'
        
        return indicators
    
    def _check_ssl_certificate(self, domain):
        """Check SSL certificate validity"""
        try:
            context = ssl.create_default_context()
            with socket.create_connection((domain, 443), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert()
                    not_after = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                    
                    if not_after > datetime.now():
                        return {
                            'status': 'Valid', 
                            'score_penalty': 0,
                            'expiry_date': not_after.isoformat(),
                            'details': 'SSL certificate is valid and properly configured.'
                        }
                    else:
                        return {
                            'status': 'Expired', 
                            'score_penalty': 25,
                            'expiry_date': not_after.isoformat(),
                            'details': 'SSL certificate has expired and needs renewal.'
                        }
        except Exception as e:
            logger.debug(f"SSL check failed for {domain}: {str(e)}")
            return {
                'status': 'No SSL', 
                'score_penalty': 15,
                'details': f'No SSL certificate found or connection failed: {str(e)}'
            }
    
    def _check_phishing(self, url, domain):
        """Check for phishing indicators"""
        url_lower = url.lower()
        domain_lower = domain.lower()
        
        suspicious = False
        indicators_found = []
        
        for indicator in self.phishing_indicators:
            if indicator in url_lower or indicator in domain_lower:
                suspicious = True
                indicators_found.append(indicator)
        
        # Check for suspicious patterns
        if len(domain.split('.')) > 4:  # Too many subdomains
            suspicious = True
            indicators_found.append('excessive_subdomains')
        
        if suspicious:
            return {
                'status': 'Suspicious', 
                'suspicious': True,
                'indicators': indicators_found,
                'details': f'Found phishing indicators: {", ".join(indicators_found)}'
            }
        else:
            return {
                'status': 'Clean', 
                'suspicious': False,
                'indicators': [],
                'details': 'No phishing indicators detected.'
            }
    
    def _check_malware_indicators(self, url, domain):
        """Check for malware indicators"""
        url_lower = url.lower()
        indicators_found = []
        
        for indicator in self.malware_indicators:
            if indicator in url_lower:
                indicators_found.append(indicator)
        
        if indicators_found:
            return {
                'status': 'Suspicious', 
                'suspicious': True,
                'indicators': indicators_found,
                'details': f'Found malware-related keywords: {", ".join(indicators_found)}'
            }
        
        return {
            'status': 'Clean', 
            'suspicious': False,
            'indicators': [],
            'details': 'No malware indicators detected.'
        }
    
    def analyze_password_strength(self, password):
        """Analyze password strength with detailed feedback and mistake descriptions"""
        result = {
            'strength_score': 0,
            'strength_level': 'Very Weak',
            'feedback': [],
            'has_uppercase': False,
            'has_lowercase': False,
            'has_numbers': False,
            'has_symbols': False,
            'entropy': 0,
            'mistake_description': '',
            'recommendations': [],
            'detailed_analysis': {}
        }
        
        if not password:
            result['feedback'].append('Password cannot be empty')
            result['mistake_description'] = 'Empty password provides no security protection.'
            result['recommendations'].append('Create a password with at least 8 characters.')
            return result
        
        # Check character types
        result['has_uppercase'] = bool(re.search(r'[A-Z]', password))
        result['has_lowercase'] = bool(re.search(r'[a-z]', password))
        result['has_numbers'] = bool(re.search(r'[0-9]', password))
        result['has_symbols'] = bool(re.search(r'[^A-Za-z0-9]', password))
        
        # Store character analysis
        result['detailed_analysis']['character_types'] = {
            'uppercase': result['has_uppercase'],
            'lowercase': result['has_lowercase'],
            'numbers': result['has_numbers'],
            'symbols': result['has_symbols'],
            'length': len(password)
        }
        
        # Calculate base score
        score = 0
        mistakes = []
        
        # Length scoring
        if len(password) >= 8:
            score += 25
        else:
            mistakes.append(f'Password is too short ({len(password)} characters). Minimum recommended length is 8 characters.')
        
        if len(password) >= 12:
            score += 15
        elif len(password) >= 8:
            result['recommendations'].append('Consider using at least 12 characters for better security.')
            
        if len(password) >= 16:
            score += 10
        
        # Character type scoring
        if result['has_uppercase']:
            score += 15
        else:
            mistakes.append('Missing uppercase letters (A-Z).')
            
        if result['has_lowercase']:
            score += 15
        else:
            mistakes.append('Missing lowercase letters (a-z).')
            
        if result['has_numbers']:
            score += 15
        else:
            mistakes.append('Missing numbers (0-9).')
            
        if result['has_symbols']:
            score += 20
        else:
            mistakes.append('Missing special characters (!@#$%^&*).')
        
        # Check against common passwords
        if password.lower() in [p.lower() for p in self.common_passwords]:
            score -= 50
            mistakes.append('This is a commonly used password that appears in password dictionaries.')
            result['feedback'].append('This is a commonly used password')
        
        # Check for patterns
        if re.search(r'(.)\1{2,}', password):  # Repeated characters
            score -= 10
            mistakes.append('Contains repeated characters which reduce security.')
        
        if re.search(r'(012|123|234|345|456|567|678|789|890)', password):  # Sequential numbers
            score -= 10
            mistakes.append('Contains sequential numbers which are easily guessed.')
        
        if re.search(r'(abc|bcd|cde|def|efg|fgh|ghi|hij|ijk|jkl|klm|lmn|mno|nop|opq|pqr|qrs|rst|stu|tuv|uvw|vwx|wxy|xyz)', password.lower()):  # Sequential letters
            score -= 10
            mistakes.append('Contains sequential letters which reduce security.')
        
        # Calculate entropy
        charset_size = 0
        if result['has_lowercase']:
            charset_size += 26
        if result['has_uppercase']:
            charset_size += 26
        if result['has_numbers']:
            charset_size += 10
        if result['has_symbols']:
            charset_size += 32
        
        if charset_size > 0:
            result['entropy'] = len(password) * math.log2(charset_size)
            result['detailed_analysis']['entropy'] = result['entropy']
        
        # Ensure score bounds
        score = max(0, min(100, score))
        result['strength_score'] = score
        
        # Determine strength level
        if score >= 80:
            result['strength_level'] = 'Very Strong'
        elif score >= 60:
            result['strength_level'] = 'Strong'
        elif score >= 40:
            result['strength_level'] = 'Moderate'
        elif score >= 20:
            result['strength_level'] = 'Weak'
        else:
            result['strength_level'] = 'Very Weak'
        
        # Generate mistake description
        if mistakes:
            result['mistake_description'] = 'Password weaknesses identified: ' + ' '.join(mistakes)
        
        # Generate feedback
        if len(password) < 8:
            result['feedback'].append('Use at least 8 characters')
            result['recommendations'].append('Increase password length to at least 8 characters.')
        if not result['has_uppercase']:
            result['feedback'].append('Add uppercase letters')
            result['recommendations'].append('Include uppercase letters (A-Z) for better security.')
        if not result['has_lowercase']:
            result['feedback'].append('Add lowercase letters')
            result['recommendations'].append('Include lowercase letters (a-z) for better security.')
        if not result['has_numbers']:
            result['feedback'].append('Add numbers')
            result['recommendations'].append('Include numbers (0-9) to increase complexity.')
        if not result['has_symbols']:
            result['feedback'].append('Add special characters')
            result['recommendations'].append('Include special characters (!@#$%^&*) for maximum security.')
        
        # Add general recommendations
        if score < 60:
            result['recommendations'].append('Consider using a passphrase made of multiple random words.')
            result['recommendations'].append('Use a password manager to generate and store strong passwords.')
        
        result['recommendations'].append('Never reuse passwords across multiple accounts.')
        result['recommendations'].append('Enable two-factor authentication where available.')
        
        return result
    
   

    


    def generate_secure_password(self, purpose, length=12,
                                 include_uppercase=True,
                                 include_lowercase=True,
                                 include_numbers=True,
                                 include_symbols=True,
                                 exclude_ambiguous=False):
        SYMBOLS = "!@#$%^&*()_+-=[]{}|;:,.<>?"
        charset = ""

        if include_lowercase:
            charset += string.ascii_lowercase
        if include_uppercase:
            charset += string.ascii_uppercase
        if include_numbers:
            charset += string.digits
        if include_symbols:
            charset += SYMBOLS

        if exclude_ambiguous:
            ambiguous_chars = "il1Lo0O"
            charset = ''.join(c for c in charset if c not in ambiguous_chars)

        if not charset:
            raise ValueError("No character set selected for password generation")

        # Purpose-related words
        purpose_words = {
            "bank": ["money", "cash", "safe", "vault", "secure"],
            "email": ["mail", "inbox", "post", "msg", "send"],
            # ... rest omitted for brevity
        }

        # Ensure minimum length
        min_required = sum([include_lowercase, include_uppercase, include_numbers, include_symbols])
        if length < min_required:
            raise ValueError(f"Password length must be at least {min_required}")

        # Start password
        password = []
        if include_lowercase:
            password.append(secrets.choice(string.ascii_lowercase))
        if include_uppercase:
            password.append(secrets.choice(string.ascii_uppercase))
        if include_numbers:
            password.append(secrets.choice(string.digits))
        if include_symbols:
            password.append(secrets.choice(SYMBOLS))

        # Purpose-related word
        word_part = ""
        if purpose:
            key = purpose.lower().strip()
            if key in purpose_words:
                word_part = secrets.choice(purpose_words[key])
            else:
                word_part = re.sub(r'[^A-Za-z0-9]', '', key)[:4]

            substitutions = {'a': '@', 'i': '1', 'o': '0', 's': '$', 'e': '3'}
            word_part = ''.join(substitutions.get(c.lower(), c) for c in word_part)
            password.extend(list(word_part))

        # Fill remaining characters
        current_len = len(password)
        remaining = max(0, length - current_len)
        for _ in range(remaining):
            password.append(secrets.choice(charset))

        # Shuffle
        secrets.SystemRandom().shuffle(password)
        return ''.join(password)
    
    def generate_personal_passwords(self, personal_info):
        """Generate 3+ strong passwords based on personal information"""
        passwords = []
        
        # Extract info with defaults
        name = personal_info.get('name', '').strip()
        age = personal_info.get('age', '').strip()
        dob = personal_info.get('dob', '').strip()
        school = personal_info.get('school', '').strip()
        pet = personal_info.get('pet', '').strip()
        color = personal_info.get('color', '').strip()
        
        # Clean and prepare base words
        base_words = []
        if name: base_words.append(name.replace(' ', ''))
        if school: base_words.append(school.replace(' ', ''))
        if pet: base_words.append(pet.replace(' ', ''))
        if color: base_words.append(color.replace(' ', ''))
        
        # Special characters and numbers for strengthening
        special_chars = ['!', '@', '#', '$', '%', '^', '&', '*']
        
        # Pattern 1: Name + Age + Special + Year
        if name and age:
            year = dob.split('-')[0] if '-' in dob else '2024'
            password1 = f"{name.capitalize()}{age}{secrets.choice(special_chars)}{year}"
            passwords.append({
                'password': password1,
                'pattern': 'Name + Age + Special + Year',
                'description': f'Based on your name "{name}", age "{age}", and year from date of birth'
            })
        
        # Pattern 2: School + Pet + Special Characters
        if school and pet:
            school_short = school[:4] if len(school) > 4 else school
            pet_cap = pet.capitalize()
            special_combo = ''.join(secrets.choice(special_chars) for _ in range(2))
            password2 = f"{school_short}{pet_cap}{special_combo}{secrets.randbelow(100):02d}"
            passwords.append({
                'password': password2,
                'pattern': 'School + Pet + Specials + Random Numbers',
                'description': f'Combination of "{school}" and pet "{pet}" with security additions'
            })
        
        # Pattern 3: Color + Name + Birth Year + Symbols
        if color and name and dob:
            birth_year = dob.split('-')[0] if '-' in dob else str(2024 - int(age) if age.isdigit() else 2000)
            color_cap = color.capitalize()
            name_first = name.split()[0] if ' ' in name else name
            symbols = ''.join(secrets.choice(special_chars) for _ in range(2))
            password3 = f"{color_cap}{name_first[:3]}{birth_year}{symbols}"
            passwords.append({
                'password': password3,
                'pattern': 'Color + Name + Birth Year + Symbols',
                'description': f'Your favorite color "{color}", name, and birth year with security symbols'
            })
        
        # Pattern 4: Mix all elements creatively
        if len(base_words) >= 2:
            word1 = base_words[0][:3] if len(base_words[0]) > 3 else base_words[0]
            word2 = base_words[1][:3] if len(base_words[1]) > 3 else base_words[1]
            random_num = secrets.randbelow(999)
            special = secrets.choice(special_chars)
            password4 = f"{word1.capitalize()}{word2.lower()}{random_num}{special}"
            passwords.append({
                'password': password4,
                'pattern': 'Mixed Personal Elements + Random',
                'description': f'Creative mix of your personal information with security enhancements'
            })
        
        # Pattern 5: Sentence-based password
        if name and pet and color:
            # Create a sentence and use first letters + numbers
            sentence_parts = [name.split()[0] if ' ' in name else name, 'loves', pet, color]
            initials = ''.join(word[0].upper() if i % 2 == 0 else word[0].lower() 
                             for i, word in enumerate(sentence_parts) if word)
            year_digits = dob.split('-')[0][-2:] if '-' in dob and len(dob.split('-')[0]) >= 2 else '24'
            symbols = ''.join(secrets.choice(special_chars) for _ in range(2))
            password5 = f"{initials}{year_digits}{symbols}"
            passwords.append({
                'password': password5,
                'pattern': 'Sentence Method',
                'description': f'Based on sentence: "{name} loves {pet} {color}" converted to secure format'
            })
        
        # Ensure we have at least 3 passwords
        while len(passwords) < 3 and base_words:
            word = secrets.choice(base_words)
            random_suffix = secrets.randbelow(9999)
            special = ''.join(secrets.choice(special_chars) for _ in range(2))
            fallback_password = f"{word.capitalize()}{random_suffix}{special}"
            passwords.append({
                'password': fallback_password,
                'pattern': 'Enhanced Personal Word',
                'description': f'Enhanced version of "{word}" with security additions'
            })
        
        # If still not enough, generate some generic strong passwords
        while len(passwords) < 3:
            generic_password = self.generate_secure_password(length=12, include_symbols=True)
            passwords.append({
                'password': generic_password,
                'pattern': 'Random Secure',
                'description': 'Strong random password as backup option'
            })
        
        # Analyze strength of each password
        for pwd_info in passwords:
            analysis = self.analyze_password_strength(pwd_info['password'])
            pwd_info['strength_score'] = analysis['strength_score']
            pwd_info['strength_level'] = analysis['strength_level']
        
        return passwords[:5]  # Return maximum 5 passwords
