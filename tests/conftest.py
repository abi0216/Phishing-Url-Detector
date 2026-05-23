import pytest
import os
import sys
from unittest.mock import patch, MagicMock

# Add project root to sys.path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import create_app
from app.services.intel_service import IntelService
from app.services.feature_service import FeatureService

@pytest.fixture
def app():
    app = create_app()
    app.config.update({
        "TESTING": True,
        "CACHE_TYPE": "SimpleCache",
        "VIRUSTOTAL_API_KEY": "test_key",
        "GOOGLE_SAFE_BROWSING_KEY": "test_key"
    })
    return app

@pytest.fixture
def client(app):
    return app.test_client()

@pytest.fixture
def runner(app):
    return app.test_cli_runner()

@pytest.fixture(autouse=True)
def mock_external_services():
    """Mock WHOIS, DNS and Threat Intel globally to ensure tests don't hit the network."""
    with patch('app.services.feature_service.FeatureService.get_external_info') as mock_ext, \
         patch('app.services.intel_service.IntelService.check_virustotal') as mock_vt, \
         patch('app.services.intel_service.IntelService.check_google_safebrowsing') as mock_gsb:
        
        # Default mock behavior: Safe URL
        mock_ext.return_value = {
            "domain_age_days": 5000,
            "is_new_domain": 0,
            "dns_valid": 1,
            "registrar": "Google LLC",
            "formatted_age": "13 years, 8 months"
        }
        mock_vt.return_value = {"malicious": 0, "suspicious": 0, "harmless": 70}
        mock_gsb.return_value = []
        
        yield {
            "ext": mock_ext,
            "vt": mock_vt,
            "gsb": mock_gsb
        }

@pytest.fixture
def test_urls():
    return {
        "safe": [
            "https://google.com", "https://github.com", "https://wikipedia.org",
            "https://openai.com", "https://microsoft.com"
        ],
        "tricky_safe": [
            "https://accounts.google.com", "https://signin.aws.amazon.com",
            "https://support.microsoft.com", "https://secure.paypal.com"
        ],
        "phishing": [
            "http://paypal-account-verification.example",
            "http://amazon-security-alert.example/login",
            "http://netflix-billing-update.example"
        ],
        "tricky_phishing": [
            "http://192.168.1.5/paypal-login",
            "http://secure-paypal-login-check.example",
            "http://paypal.verify.security.example"
        ]
    }
