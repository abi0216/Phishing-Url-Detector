import pytest
import json

def test_index_page(client):
    """Verify the home page loads correctly."""
    response = client.get('/')
    assert response.status_code == 200
    assert b"PHISHGUARD" in response.data

def test_single_predict_safe_url(client, mock_external_services):
    """Test single scan API with a safe URL."""
    url = "https://google.com"
    response = client.post('/predict_async', 
                           data=json.dumps({"url": url, "mode": "deep"}),
                           content_type='application/json')
    
    assert response.status_code == 200
    data = json.loads(response.data)
    assert data["url"] == url
    assert data["prediction"] == 0
    assert "confidence" in data
    assert data["risk_level"] in ["Safe", "Low Risk"]

def test_single_predict_malicious_url(client, mock_external_services, test_urls):
    """Test single scan API with a known phishing keyword URL."""
    url = test_urls["phishing"][0]
    
    # Force VT to report malicious to ensure the model/override works
    mock_external_services["vt"].return_value = {"malicious": 5, "suspicious": 1, "harmless": 20}
    
    response = client.post('/predict_async', 
                           data=json.dumps({"url": url, "mode": "deep"}),
                           content_type='application/json')
    
    data = json.loads(response.data)
    assert data["prediction"] == 1
    assert data["risk_level"] == "Critical"

def test_bulk_scan_mixed(client, test_urls):
    """Test bulk scan handles mixed URLs and whitespace."""
    urls = test_urls["safe"][:2] + ["   ", "   "] + test_urls["phishing"][:1]
    
    # Frontend usually sends bulk URLs one by one, but let's test the endpoint logic
    for url in urls:
        if not url.strip(): continue
        response = client.post('/predict_async', 
                               data=json.dumps({"url": url.strip(), "mode": "deep"}),
                               content_type='application/json')
        assert response.status_code == 200

def test_api_missing_url(client):
    """Verify 400 error when no URL is provided."""
    response = client.post('/predict_async', 
                           data=json.dumps({"url": "", "mode": "deep"}),
                           content_type='application/json')
    assert response.status_code == 400
    assert b"error" in response.data
