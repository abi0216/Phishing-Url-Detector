import pytest
import sys
import os

# Add the parent directory to sys.path so we can import app
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import create_app

@pytest.fixture
def client():
    app = create_app()
    app.config['TESTING'] = True
    with app.test_client() as client:
        yield client

def test_home_route(client):
    """Test if home page loads."""
    rv = client.get('/')
    assert rv.status_code == 200
    assert b"PHISH" in rv.data
    assert b"GUARD" in rv.data

def test_predict_route_missing_url(client):
    """Test handling of empty URL input."""
    import json
    rv = client.post('/predict_async', 
                     data=json.dumps(dict(url="")),
                     content_type='application/json')
    assert rv.status_code == 400
    data = json.loads(rv.data)
    assert "error" in data

def test_predict_async(client):
    """Test AJAX endpoint returns JSON."""
    import json
    response = client.post('/predict_async', 
                           data=json.dumps(dict(url="http://example.com")),
                           content_type='application/json')
    assert response.status_code == 200
    data = json.loads(response.data)
    assert 'prediction' in data
    assert 'confidence' in data
