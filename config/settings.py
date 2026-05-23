import os
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

class Config:
    """Base configuration."""
    SECRET_KEY = os.getenv("FLASK_SECRET_KEY", "dev-key-12345")
    
    # API Keys
    VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")
    GOOGLE_SAFE_BROWSING_KEY = os.getenv("GOOGLE_SAFE_BROWSING_KEY")
    
    # Paths
    BASE_DIR = os.path.abspath(os.path.dirname(os.path.dirname(__file__)))
    MODEL_DIR = os.path.join(BASE_DIR, "models")
    LOG_DIR = os.path.join(BASE_DIR, "logs")
    CACHE_DIR = os.path.join(BASE_DIR, "cache")
    
    # Caching
    CACHE_TYPE = "FileSystemCache"
    CACHE_DIR = CACHE_DIR
    CACHE_DEFAULT_TIMEOUT = 3600

    # Whitelist
    WHITELIST = {
        'google.com', 'youtube.com', 'microsoft.com', 'apple.com', 'amazon.com', 
        'facebook.com', 'instagram.com', 'netflix.com', 'linkedin.com', 'twitter.com',
        'github.com', 'wikipedia.org', 'outlook.com', 'live.com', 'zoom.us',
        'paypal.com', 'office.com', 'salesforce.com', 'slack.com', 'adobe.com',
        'medium.com', 'stackoverflow.com', 'reddit.com', 'openai.com', 'gmail.com',
        'yahoo.com', 'bing.com', 'dropbox.com', 'spotify.com'
    }
