import pytest
import time
from app.services.feature_service import FeatureService

def test_feature_extraction_performance(benchmark):
    """Benchmark the 40-feature extraction engine."""
    url = "https://very-long-subdomain.with-many-parts.google.com/path/to/resource?id=123&query=testing_performance"
    
    def run_extraction():
        FeatureService.extract_features(url, include_external=False)
        
    benchmark(run_extraction)

def test_single_scan_latency(client, benchmark):
    """Benchmark end-to-end API latency for a single scan."""
    url = "https://example.com"
    
    def run_api_call():
        client.post('/predict_async', 
                    json={"url": url, "mode": "deep"})
        
    benchmark(run_api_call)

def test_cache_hit_performance(client, app):
    """Verify cache hits are significantly faster than real scans."""
    url = "https://cached-test.com"
    
    # First call (Cold)
    start_cold = time.time()
    client.post('/predict_async', json={"url": url, "mode": "deep"})
    end_cold = time.time()
    
    # Second call (Warm Cache)
    start_warm = time.time()
    client.post('/predict_async', json={"url": url, "mode": "deep"})
    end_warm = time.time()
    
    cold_time = end_cold - start_cold
    warm_time = end_warm - start_warm
    
    assert warm_time < cold_time or warm_time < 0.005
    print(f"\nCold: {cold_time:.4f}s | Warm: {warm_time:.4f}s")
