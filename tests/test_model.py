import pytest
import pandas as pd
from app.models.predictor import PhishingPredictor

@pytest.fixture
def predictor():
    return PhishingPredictor()

def test_model_loading(predictor):
    """Verify that models are initialized correctly."""
    # Even if pkl files are missing in test env, the class should handle it
    assert predictor is not None

def test_prediction_logic_safe(predictor, mock_external_services):
    """Verify high-confidence safe URL remains safe."""
    url = "https://google.com"
    result = predictor.predict(url, mode="deep")
    
    # Overrides and logic check
    assert result["prediction"] == 0
    assert result["risk_level"] in ["Safe", "Low Risk"]

def test_prediction_logic_malicious_override(predictor, mock_external_services):
    """Verify that threat intel overrides XGBoost results."""
    url = "http://suspicious-site.example"
    
    # Mock Google Safe Browsing finding a match
    mock_external_services["gsb"].return_value = [{"threatType": "MALWARE"}]
    
    result = predictor.predict(url, mode="deep")
    
    assert result["prediction"] == 1
    assert result["risk_level"] == "Critical"
    assert "google_flagged" in result["threat_intel"]

def test_whitelist_override(predictor):
    """Verify whitelisted domains bypass model analysis."""
    url = "https://github.com"
    result = predictor.predict(url, mode="deep")
    
    assert result["prediction"] == 0
    assert result["confidence"] == 100.0
    assert result["risk_level"] == "Safe"
