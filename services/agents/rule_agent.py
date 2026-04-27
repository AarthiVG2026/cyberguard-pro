"""
Rule Agent — Heuristic + Network Analysis Agent
Performs SSL, WHOIS, domain, and phishing indicator checks.
"""
import re
import ssl
import socket
import math
import logging
import urllib.parse
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone

try:
    import whois as python_whois
except ImportError:
    python_whois = None

logger = logging.getLogger(__name__)


class RuleAgent:
    """
    Agent 1: Rule-Based Security Forensics Engine.
    Analyzes a URL using heuristic rules, SSL, WHOIS, and domain forensics.
    Returns a score from 0 (Dangerous) to 100 (Safe).
    """

    def __init__(self, max_workers=4):
        self.max_workers = max_workers
        self.suspicious_keywords = [
            'secure', 'account', 'webscr', 'login', 'ebayisapi', 'signin',
            'banking', 'confirm', 'verify', 'wallet', 'free', 'update', 'password',
            'support', 'billing', 'bonus', 'rewards', 'claim', 'refund'
        ]
        self.suspicious_tlds = {
            '.tk', '.ml', '.ga', '.cf', '.click', '.download', '.loan',
            '.win', '.racing', '.stream', '.science', '.party', '.review',
            '.top', '.xyz', '.biz', '.gq', '.icu', '.monster', '.bid'
        }
        self.trusted_domains = {
            'google.com', 'youtube.com', 'gmail.com', 'microsoft.com',
            'office.com', 'apple.com', 'amazon.com', 'facebook.com',
            'instagram.com', 'twitter.com', 'x.com', 'linkedin.com',
            'github.com', 'paypal.com', 'netflix.com', 'spotify.com',
            'wikipedia.org', 'whatsapp.com', 'zoom.us', 'slack.com',
            'adobe.com', 'dropbox.com', 'discord.com', 'telegram.org',
            'snapchat.com', 'reddit.com', 'stackoverflow.com', 'medium.com',
            'cloudflare.com', 'godaddy.com', 'bluehost.com', 'hostgator.com',
            'dhl.com', 'fedex.com', 'ups.com', 'usps.com',
            'walmart.com', 'ebay.com', 'target.com', 'alibaba.com',
            'binance.com', 'coinbase.com', 'blockchain.com',
            'airbnb.com', 'booking.com', 'expedia.com', 'trivago.com',
            'snapt.com',
        }

    def _extract_domain(self, url):
        """Extract the domain from a URL safely."""
        url = url.strip()
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url
        parsed = urllib.parse.urlparse(url)
        domain = parsed.netloc.lower()
        if not domain and ':' in parsed.path:
            domain = parsed.path.split(':')[0].split('/')[0]
        return domain.split(':')[0]  # strip port

    def _check_ssl(self, domain):
        """Check SSL certificate validity."""
        try:
            clean = domain.replace('www.', '')
            context = ssl.create_default_context()
            with socket.create_connection((clean, 443), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=clean) as ssock:
                    cert = ssock.getpeercert()
                    not_after = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                    if not_after > datetime.now():
                        return {'status': 'Valid', 'score': 20}
                    else:
                        return {'status': 'Expired', 'score': -20}
        except Exception as e:
            logger.debug(f"SSL check failed for {domain}: {e}")
            return {'status': 'No SSL', 'score': -10}

    def _check_domain_age(self, domain):
        """Get domain age via WHOIS."""
        clean = domain.replace('www.', '').split(':')[0]

        # Hardcoded baseline for known trusted domains (enterprise whitelist)
        trusted_ages = {
            'google.com': 10450, 'facebook.com': 8120, 'amazon.com': 11300,
            'apple.com': 17500, 'microsoft.com': 15000, 'netflix.com': 10500,
            'paypal.com': 9800, 'github.com': 6580, 'snapt.com': 10200,
            'snapchat.com': 5360, 'whatsapp.com': 6300, 'linkedin.com': 8550,
            'twitter.com': 7350, 'x.com': 8500, 'wikipedia.org': 9200,
            'youtube.com': 7740, 'instagram.com': 5650, 'reddit.com': 7600,
        }
        if clean in trusted_ages:
            return {'age_days': trusted_ages[clean], 'status': 'Trusted Source'}

        if not python_whois:
            return {'age_days': None, 'status': 'WHOIS unavailable'}

        try:
            if hasattr(python_whois, 'whois'):
                info = python_whois.whois(clean)
            elif hasattr(python_whois, 'query'):
                info = python_whois.query(clean)
            else:
                return {'age_days': None, 'status': 'Incompatible library'}

            creation_date = getattr(info, 'creation_date', None)
            if isinstance(creation_date, list):
                creation_date = creation_date[0]

            if isinstance(creation_date, datetime):
                if creation_date.tzinfo is None:
                    creation_date = creation_date.replace(tzinfo=timezone.utc)
                age = max(0, (datetime.now(timezone.utc) - creation_date).days)
                return {'age_days': age, 'status': 'Success'}

        except Exception as e:
            logger.debug(f"WHOIS failed for {clean}: {e}")

        return {'age_days': None, 'status': 'Lookup failed'}

    def _calculate_entropy(self, text):
        if not text:
            return 0.0
        probs = [float(text.count(c)) / len(text) for c in set(text)]
        return -sum(p * math.log2(p) for p in probs)

    def analyze(self, url):
        """
        Run all heuristic checks in parallel and return a consolidated score.
        Score 0 = Dangerous, 100 = Totally Safe.
        """
        domain = self._extract_domain(url)
        clean_domain = domain.replace('www.', '')
        url_lower = url.lower()

        score = 50  # neutral start

        # --- Parallel network checks ---
        ssl_result = {'status': 'Unknown', 'score': 0}
        domain_age = {'age_days': None, 'status': 'Unknown'}

        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            ssl_future = executor.submit(self._check_ssl, domain)
            age_future = executor.submit(self._check_domain_age, clean_domain)
            ssl_result = ssl_future.result()
            domain_age = age_future.result()

        # SSL scoring
        score += ssl_result.get('score', 0)

        # Domain Age scoring
        age_days = domain_age.get('age_days')
        if age_days is not None:
            if age_days < 30:
                score -= 30
            elif age_days < 180:
                score -= 10
            elif age_days > 365:
                score += 10
            if age_days > 3650:  # 10+ years
                score += 15

        # Trusted domain bonus
        if clean_domain in self.trusted_domains:
            score += 40

        # Suspicious keywords
        keyword_hits = sum(1 for kw in self.suspicious_keywords if kw in url_lower)
        score -= keyword_hits * 5

        # Suspicious TLD
        tld = '.' + clean_domain.split('.')[-1] if '.' in clean_domain else ''
        if tld in self.suspicious_tlds:
            score -= 20

        # Excessive subdomains
        parts = domain.split('.')
        if len(parts) > 4:
            score -= 15

        # High entropy domain (random-looking)
        sld = clean_domain.split('.')[0] if '.' in clean_domain else clean_domain
        if self._calculate_entropy(sld) > 4.2:
            score -= 10

        # @ symbol (credential harvesting)
        if '@' in url:
            score -= 20

        # IP address as host
        if re.match(r'^[\d.]+$', domain.split(':')[0]):
            score -= 30

        # Hyphen abuse
        if domain.count('-') > 3:
            score -= 10

        # HTTPS bonus
        if url.startswith('https://'):
            score += 5

        score = max(0, min(100, score))

        return {
            'score': score,
            'details': {
                'ssl': ssl_result,
                'domain_age': domain_age,
                'keyword_hits': keyword_hits,
                'entropy': self._calculate_entropy(sld),
                'domain': clean_domain,
            }
        }
