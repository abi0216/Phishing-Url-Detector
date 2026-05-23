from urllib.parse import urlparse
from config.settings import Config

def is_whitelisted(url):
    """Checks if the domain is in the high-trust whitelist."""
    try:
        parsed = urlparse(url)
        domain = parsed.netloc.lower()
        if not domain:
            domain = url.split('/')[0].lower()
        if domain.startswith('www.'): domain = domain[4:]
        
        # Exact match or subdomain match
        if domain in Config.WHITELIST: return True
        for d in Config.WHITELIST:
            if domain.endswith('.' + d): return True
        return False
    except:
        return False

def format_domain_age(days):
    """Converts raw days into a human-readable string (Years, Months, Days)."""
    if days == -1:
        return "Unknown"
    
    years = days // 365
    remaining_days = days % 365
    months = remaining_days // 30
    days_left = remaining_days % 30
    
    parts = []
    if years > 0:
        parts.append(f"{years} {'year' if years == 1 else 'years'}")
    if months > 0:
        parts.append(f"{months} {'month' if months == 1 else 'months'}")
    if days_left > 0 or not parts:
        parts.append(f"{days_left} {'day' if days_left == 1 else 'days'}")
    
    return ", ".join(parts)
