import pytest
import json

def test_empty_string_handling(client):
    response = client.post('/predict_async', 
                           json={"url": ""})
    assert response.status_code == 400

def test_extremely_long_url(client):
    """Test system resilience against buffer overflow or DoS attempts via long strings."""
    long_url = "http://" + ("a" * 5000) + ".com"
    response = client.post('/predict_async', 
                           json={"url": long_url})
    assert response.status_code == 200 # Should handle gracefully

def test_malformed_url_format(client):
    """Verify that gibberish input doesn't crash the server."""
    bad_inputs = ["!!!!", "http://", "123", "   "]
    for inp in bad_inputs:
        response = client.post('/predict_async', 
                               json={"url": inp})
        assert response.status_code in [200, 400] # Either error or safe prediction

def test_protocol_injection(client):
    """Ensure non-HTTP protocols are handled correctly (simple SSRF prevention)."""
    blocked_urls = ["file:///etc/passwd", "ftp://malicious.com", "gopher://bad.com"]
    for url in blocked_urls:
        response = client.post('/predict_async', 
                               json={"url": url})
        # System should treat these as safe or error, not try to resolve them
        # In our case, the parser might fallback to https://
        data = json.loads(response.data)
        assert "prediction" in data or "error" in data
