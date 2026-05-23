from flask import Blueprint, render_template, request, jsonify, current_app
from app.models.predictor import PhishingPredictor
from app import cache

main_bp = Blueprint('main', __name__)
predictor = PhishingPredictor()

@main_bp.route('/')
def index():
    return render_template('index.html')

@main_bp.route('/predict_async', methods=['POST'])
def predict_async():
    data = request.get_json()
    url = data.get('url')
    mode = data.get('mode', 'quick')
    
    if not url:
        return jsonify({"error": "No URL provided"}), 400
        
    cache_key = f"{mode}:{url}"
    
    cached_res = cache.get(cache_key)
    if cached_res:
        cached_res["cached"] = True
        return jsonify(cached_res)

    result = predictor.predict(url, mode=mode)
    
    if "error" not in result:
        result["cached"] = False
        cache.set(cache_key, result)
        
    return jsonify(result)
