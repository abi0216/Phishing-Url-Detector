import pytest
from app.services.feature_service import FeatureService

def test_feature_vector_structure():
    """Verify exact 40-feature output and naming alignment."""
    url = "https://secure-login.paypal.verification.com/update?session=123"
    features, _ = FeatureService.extract_features(url)
    
    assert len(features) == 40
    assert len(FeatureService.FEATURE_NAMES) == 40
    assert all(isinstance(f, (int, float)) for f in features)

def test_homograph_attack_detection():
    """Verify detection of internationalized domain names (IDN) / Punycode."""
    # Homograph attack (looks like apple.com but uses Cyrillic 'a')
    malicious_url = "https://xn--pple-43d.com" 
    features, _ = FeatureService.extract_features(malicious_url)
    
    # Feature index 19 (is_homograph)
    assert features[19] == 1, "Should detect homograph/punycode domain"

def test_entropy_and_complexity():
    """Verify that entropy responds to string randomness."""
    simple_url = "http://aaa.com"
    complex_url = "http://a1b2c3d4e5f6g7h8.com"
    
    feat_simple, _ = FeatureService.extract_features(simple_url)
    feat_complex, _ = FeatureService.extract_features(complex_url)
    
    # Feature index 18 (entropy)
    assert feat_complex[18] > feat_simple[18]

def test_suspicious_tld_flagging():
    """Verify that non-standard TLDs are flagged."""
    phish_tld = "http://login.account.verify.xyz" # .xyz is suspicious
    safe_tld = "http://google.com"
    
    feat_phish, _ = FeatureService.extract_features(phish_tld)
    feat_safe, _ = FeatureService.extract_features(safe_tld)
    
    # Feature index 29 (suspicious_tld)
    assert feat_phish[29] == 1
    assert feat_safe[29] == 0

def test_keyword_overlap_and_spoofing():
    """Verify brand spoofing and keyword scoring."""
    url = "http://google.com.secure-login.net"
    features, _ = FeatureService.extract_features(url)
    
    # Feature index 32 (brand_spoof)
    assert features[32] == 1, "Should flag 'google' used as a subdomain on a different primary domain"
    # Feature index 20 (keyword_count)
    assert features[20] >= 2 # 'login', 'secure'

def test_path_and_query_metrics():
    """Check ratio and digit extraction for paths and queries."""
    url = "http://example.com/login/verify.php?id=12345&token=abc"
    features, _ = FeatureService.extract_features(url)
    
    # 35: Path digits, 36: Query digits
    assert features[35] == 0
    assert features[36] == 5
    # 37: Suspicious extension (.php)
    assert features[37] == 1
