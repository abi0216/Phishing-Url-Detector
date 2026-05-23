import time
import os
import sys
import psutil
import statistics
import numpy as np
import joblib

# Add the current directory to sys.path to import local modules
current_dir = os.path.dirname(os.path.abspath(__file__))
if current_dir not in sys.path:
    sys.path.append(current_dir)

def profile_loading():
    print("Profiling Flask app and model loading...")
    process = psutil.Process(os.getpid())
    mem_before = process.memory_info().rss / 1024 / 1024
    start_time = time.time()
    
    # Import app and extract_features
    # This will trigger model loading in app.py
    import app
    from feature_extraction import extract_features
    
    end_time = time.time()
    mem_after = process.memory_info().rss / 1024 / 1024
    
    return {
        "loading_time": end_time - start_time,
        "memory_used_mb": mem_after - mem_before,
        "total_memory_mb": mem_after,
        "app": app,
        "extract_features": extract_features
    }

def benchmark_features(extract_features, urls):
    results = {}
    for url in urls:
        print(f"Benchmarking feature extraction for: {url}")
        times = []
        # Warm up
        try:
            extract_features(url, include_external=True)
        except:
            pass
            
        for _ in range(3): # Run 3 times for average
            start = time.time()
            try:
                extract_features(url, include_external=True)
            except Exception as e:
                print(f"Error extracting features for {url}: {e}")
            times.append(time.time() - start)
        results[url] = statistics.mean(times) if times else 0
    return results

def benchmark_apis(app_mod, url):
    print(f"Benchmarking External APIs for: {url}")
    # Time VirusTotal
    vt_times = []
    for _ in range(2):
        start = time.time()
        try:
            app_mod.check_virustotal(url)
        except:
            pass
        vt_times.append(time.time() - start)
    
    # Time Safe Browsing
    sb_times = []
    for _ in range(2):
        start = time.time()
        try:
            app_mod.check_google_safebrowsing(url)
        except:
            pass
        sb_times.append(time.time() - start)
        
    return {
        "virustotal": statistics.mean(vt_times) if vt_times else 0,
        "safebrowsing": statistics.mean(sb_times) if sb_times else 0
    }

def benchmark_model(model, extract_features, url):
    print("Benchmarking Model Prediction speed...")
    try:
        features, _ = extract_features(url, include_external=False)
        # Ensure it's the right shape for the model
        features_arr = np.array([features])
        
        times = []
        # Warm up
        model.predict(features_arr)
        
        for _ in range(50): # 50 runs for model prediction
            start = time.time()
            model.predict(features_arr)
            times.append(time.time() - start)
            
        return statistics.mean(times)
    except Exception as e:
        print(f"Model prediction error: {e}")
        return 0

def conduct_audit():
    # 1. Profile Loading
    loading_info = profile_loading()
    
    app_mod = loading_info['app']
    extract_features = loading_info['extract_features']
    
    # 2. Benchmark Features
    urls = [
        "google.com",
        "example.com",
        "login.secure-update.xyz"
    ]
    feat_results = benchmark_features(extract_features, urls)
    
    # 3. Benchmark APIs
    api_results = benchmark_apis(app_mod, "https://google.com")
    
    # 4. Benchmark Model
    model_time = 0
    if hasattr(app_mod, 'model') and app_mod.model:
        model_time = benchmark_model(app_mod.model, extract_features, "https://google.com")
    
    # 5. Count Tests
    test_dir = os.path.join(current_dir, 'tests')
    test_count = 0
    if os.path.exists(test_dir):
        import glob
        test_files = glob.glob(os.path.join(test_dir, "test_*.py"))
        for f in test_files:
            with open(f, 'r') as tf:
                content = tf.read()
                test_count += len(re.findall(r'def test_', content))

    # Output Summary
    print("\n" + "="*50)
    print("AUDIT & BENCHMARK SUMMARY")
    print("="*50)
    print(f"Flask/Model Loading Time: {loading_info['loading_time']:.4f}s")
    print(f"Memory Usage Increment:  {loading_info['memory_used_mb']:.2f} MB")
    print(f"Total RSS Memory:        {loading_info['total_memory_mb']:.2f} MB")
    print("-" * 30)
    print("Average Feature Extraction Latency (External=True):")
    for url, t in feat_results.items():
        print(f"  - {url:25}: {t:.4f}s")
    print("-" * 30)
    print("External API Latency:")
    print(f"  - VirusTotal:             {api_results['virustotal']:.4f}s")
    print(f"  - Google Safe Browsing:   {api_results['safebrowsing']:.4f}s")
    print("-" * 30)
    print(f"Model Prediction Latency: {model_time*1000:.4f}ms")
    print("-" * 30)
    print(f"Total Tests Found:        {test_count}")
    print("="*50)

if __name__ == "__main__":
    import re
    conduct_audit()
