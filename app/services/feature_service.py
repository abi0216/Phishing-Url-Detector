import re
import os
import math
from collections import Counter
from urllib.parse import urlparse
import whois
import dns.resolver
from datetime import datetime

class FeatureService:
    FEATURE_NAMES = [
        'url_len', 'domain_len', 'path_len', 'query_len',
        'total_dots', 'domain_dots', 'total_hyphens', 'num_at',
        'num_question', 'num_ampersand', 'num_equal', 'num_underscore',
        'num_double_slash', 'digit_ratio', 'special_ratio', 'is_https',
        'has_ip', 'has_shortener', 'entropy', 'is_homograph',
        'keyword_count', 'subdomain_count', 'tld_len', 'alpha_ratio', 'vowel_count',
        'domain_hyphens', 'domain_digits', 'subdir_count', 'is_encoded', 'suspicious_tld',
        'path_ratio', 'domain_ratio', 'brand_spoof', 'client_kw_count', 'double_hyphen',
        'path_digits', 'query_digits', 'susp_ext', 'max_rep', 'query_keys'
    ]

    @staticmethod
    def get_url_entropy(text):
        """Calculates the Shannon entropy of a string."""
        if not text:
            return 0
        probs = [n / len(text) for n in Counter(text).values()]
        entropy = -sum(p * math.log2(p) for p in probs)
        return entropy

    @staticmethod
    def get_external_info(url):
        """Retrieves WHOIS and DNS information."""
        results = {
            "domain_age_days": -1,
            "is_new_domain": 0,
            "dns_valid": 0,
            "registrar": "Not Found",
            "expiration_date": "Unknown"
        }
        try:
            raw_url = url
            if not url.startswith(('http://', 'https://')):
                url = 'https://' + url
            parsed_url = urlparse(url)
            domain = parsed_url.netloc.lower()
            if not domain:
                domain = url.split('/')[0].lower()

            if ':' in domain:
                domain = domain.split(':')[0]

            try:
                dns.resolver.resolve(domain, 'A')
                results["dns_valid"] = 1
            except Exception:
                pass

            parts = domain.split('.')
            root_domain = ".".join(parts[-2:]) if len(parts) >= 2 else domain

            # 1. Instant local dictionary for top-trust whitelisted domains (0ms resolution)
            WHITELIST_WHOIS = {
                'google.com': ('MarkMonitor Inc.', '1997-09-15'),
                'youtube.com': ('MarkMonitor Inc.', '2005-02-15'),
                'microsoft.com': ('MarkMonitor Inc.', '1991-05-02'),
                'apple.com': ('Apple Inc.', '1987-02-19'),
                'amazon.com': ('MarkMonitor Inc.', '1994-11-01'),
                'facebook.com': ('Registrar Safe, LLC', '1997-03-29'),
                'instagram.com': ('Registrar Safe, LLC', '2004-06-04'),
                'netflix.com': ('MarkMonitor Inc.', '1997-11-05'),
                'linkedin.com': ('MarkMonitor Inc.', '2002-11-02'),
                'twitter.com': ('CSC Corporate Domains, Inc.', '2000-01-21'),
                'github.com': ('MarkMonitor Inc.', '2007-11-27'),
                'wikipedia.org': ('MarkMonitor Inc.', '2001-01-13'),
                'outlook.com': ('MarkMonitor Inc.', '1996-06-12'),
                'live.com': ('MarkMonitor Inc.', '1995-10-18'),
                'zoom.us': ('GoDaddy.com, LLC', '2011-05-24'),
                'medium.com': ('MarkMonitor Inc.', '1998-05-18'),
                'stackoverflow.com': ('Name.com, Inc.', '2003-12-26'),
                'reddit.com': ('MarkMonitor Inc.', '2005-04-29'),
                'openai.com': ('GoDaddy.com, LLC', '1998-03-04'),
                'gmail.com': ('MarkMonitor Inc.', '1995-08-13'),
                'yahoo.com': ('MarkMonitor Inc.', '1995-01-18'),
                'bing.com': ('MarkMonitor Inc.', '1995-01-26'),
                'dropbox.com': ('MarkMonitor Inc.', '1995-06-16'),
                'spotify.com': ('MarkMonitor Inc.', '2006-07-14'),
                'adobe.com': ('CSC Corporate Domains, Inc.', '1986-11-17'),
            }

            if root_domain in WHITELIST_WHOIS:
                reg, creation_str = WHITELIST_WHOIS[root_domain]
                results["registrar"] = reg
                creation_date = datetime.strptime(creation_str, '%Y-%m-%d')
                age = (datetime.now() - creation_date).days
                results["domain_age_days"] = max(0, age)
                results["is_new_domain"] = 1 if age < 60 else 0
                results["dns_valid"] = 1
                return results

            whois_success = False
            # 2. Try HTTP-based RDAP first (extremely fast, works over port 443)
            try:
                import requests
                import urllib3
                urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
                
                headers = {
                    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
                }
                rdap_url = f"https://rdap.org/domain/{root_domain}"
                # Enforce a tight timeout of 1.0 second
                response = requests.get(rdap_url, headers=headers, timeout=1.0, verify=False)
                if response.status_code == 200:
                    rdap_data = response.json()
                    
                    # Extract registrar name
                    extracted_reg = None
                    for entity in rdap_data.get('entities', []):
                        if 'registrar' in entity.get('roles', []):
                            vcard = entity.get('vcardArray')
                            if isinstance(vcard, list) and len(vcard) > 1:
                                properties = vcard[1]
                                for prop in properties:
                                    if isinstance(prop, list) and len(prop) > 3 and prop[0] == 'fn':
                                        extracted_reg = prop[3]
                                        break
                                if extracted_reg:
                                    break
                    
                    if extracted_reg:
                        results["registrar"] = str(extracted_reg)
                    else:
                        for entity in rdap_data.get('entities', []):
                            vcard = entity.get('vcardArray')
                            if isinstance(vcard, list) and len(vcard) > 1:
                                properties = vcard[1]
                                for prop in properties:
                                    if isinstance(prop, list) and len(prop) > 3 and prop[0] == 'fn':
                                        extracted_reg = prop[3]
                                        break
                                if extracted_reg:
                                    results["registrar"] = str(extracted_reg)
                                    break

                    # Extract creation date
                    creation_date = None
                    for event in rdap_data.get('events', []):
                        if event.get('eventAction') == 'registration':
                            date_str = event.get('eventDate')
                            if date_str:
                                try:
                                    creation_date = datetime.strptime(date_str[:10], '%Y-%m-%d')
                                    break
                                except Exception:
                                    pass
                    
                    if creation_date:
                        age = (datetime.now() - creation_date).days
                        results["domain_age_days"] = max(0, age)
                        results["is_new_domain"] = 1 if age < 60 else 0
                        whois_success = True
            except Exception:
                pass

            # 3. Try standard python-whois library if RDAP failed or returned Not Found
            if not whois_success or results["registrar"] == "Not Found":
                import socket
                old_timeout = socket.getdefaulttimeout()
                try:
                    # Enforce a tight timeout of 1.0 second
                    socket.setdefaulttimeout(1.0)
                    w = whois.whois(root_domain, timeout=1.0)
                    if w:
                        reg = getattr(w, 'registrar', None)
                        if isinstance(reg, list):
                            reg = reg[0]
                        results["registrar"] = str(reg) if reg else "Hidden"

                        creation_date = getattr(w, 'creation_date', None)
                        if isinstance(creation_date, list):
                            creation_date = creation_date[0]
                        if creation_date and isinstance(creation_date, datetime):
                            age = (datetime.now() - creation_date.replace(tzinfo=None)).days
                            results["domain_age_days"] = max(0, age)
                            results["is_new_domain"] = 1 if age < 60 else 0
                except Exception:
                    pass
                finally:
                    socket.setdefaulttimeout(old_timeout)
        except Exception:
            pass
        return results

    @classmethod
    def extract_features(cls, url, include_external=False):
        """Main entry point for feature engineering."""
        # Setup defaults
        raw_url = url
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
        parsed = urlparse(url)
        domain = parsed.netloc
        path = parsed.path
        query = parsed.query

        external_info = cls.get_external_info(raw_url) if include_external else {"domain_age_days": -1}
        
        features = []
        # 1-4. Lengths
        features.extend([len(raw_url), len(domain), len(path), len(query)])
        # 5-13. Counts
        features.extend([
            raw_url.count('.'), domain.count('.'), raw_url.count('-'),
            raw_url.count('@'), raw_url.count('?'), raw_url.count('&'),
            raw_url.count('='), raw_url.count('_'), raw_url.count('//')
        ])
        # 14-15. Ratios
        features.append(sum(c.isdigit() for c in raw_url) / len(raw_url) if raw_url else 0)
        features.append(sum(not (c.isalnum() or c in "/.-") for c in raw_url) / len(raw_url) if raw_url else 0)
        # 16-18. Flags
        features.append(1 if raw_url.startswith('https') else 0)
        features.append(1 if re.search(r"(([0-9]{1,3}\.){3}[0-9]{1,3})", domain) else 0)
        features.append(1 if re.search(r"bit\.ly|goo\.gl|shorte\.st|t\.co", raw_url) else 0)
        # 19-25. Advanced
        features.append(cls.get_url_entropy(raw_url))
        is_homograph = 0
        try: is_homograph = 1 if domain.encode('idna').decode('ascii').startswith("xn--") else 0
        except: pass
        features.append(is_homograph)
        keywords = ['login', 'verify', 'update', 'banking', 'signin', 'wp-admin', 'secure', 'account', 'paypal', 'ebayisapi']
        features.append(sum(1 for kw in keywords if kw in raw_url.lower()))
        features.append(len(domain.split('.')))
        features.append(len(domain.split('.')[-1]) if '.' in domain else 0)
        features.append(sum(c.isalpha() for c in raw_url) / len(raw_url) if raw_url else 0)
        features.append(sum(1 for c in raw_url.lower() if c in 'aeiou'))
        
        # 26-30. Domain/Structure
        features.append(domain.count('-'))
        features.append(sum(c.isdigit() for c in domain))
        features.append(path.count('/'))
        features.append(1 if '%' in raw_url else 0)
        susp_tlds = ['.xyz', '.top', '.pw', '.bit', '.tk', '.ml', '.ga', '.cf', '.gq', '.icu', '.monster']
        features.append(1 if any(raw_url.lower().endswith(t) for t in susp_tlds) else 0)
        
        # 31-40. Ratios and Spoofing
        features.append(len(path) / len(raw_url) if raw_url else 0)
        features.append(len(domain) / len(raw_url) if raw_url else 0)
        brand_spoof = 0
        brands = ['google', 'facebook', 'apple', 'microsoft', 'amazon', 'netflix', 'paypal', 'ebay', 'binance', 'coinbase']
        for b in brands:
            if b in raw_url.lower():
                domain_parts = domain.split('.')
                main_domain = domain_parts[-2] if len(domain_parts) >= 2 else domain
                if b not in main_domain.lower():
                    brand_spoof = 1
                    break
        features.append(brand_spoof)
        client_kws = ['admin', 'client', 'server', 'update', 'verification', 'billing', 'invoice', 'secure', 'vault', 'portal']
        features.append(sum(1 for kw in client_kws if kw in raw_url.lower()))
        features.append(1 if '--' in raw_url else 0)
        features.append(sum(c.isdigit() for c in path))
        features.append(sum(c.isdigit() for c in query))
        susp_ext = ['.php', '.html', '.exe', '.zip', '.apk', '.asp', '.js', '.scr']
        features.append(1 if any(path.lower().endswith(e) for e in susp_ext) else 0)
        
        # Repetition
        max_rep = 0
        if raw_url:
            c = 1
            for i in range(1, len(raw_url)):
                if raw_url[i] == raw_url[i-1]: c += 1
                else: max_rep = max(max_rep, c); c = 1
            max_rep = max(max_rep, c)
        features.append(max_rep)
        features.append(query.count('=') if query else 0)
        
        return features, external_info
