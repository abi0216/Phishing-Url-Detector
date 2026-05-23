import os
import joblib
import numpy as np
import pandas as pd
from concurrent.futures import ThreadPoolExecutor
from config.settings import Config
from app.services.feature_service import FeatureService
from app.services.intel_service import IntelService
from app.utils.helpers import is_whitelisted, format_domain_age

class PhishingPredictor:
    def __init__(self):
        self.quick_model = None
        self.deep_model = None
        self._load_models()

    def _load_models(self):
        try:
            quick_path = os.path.join(Config.MODEL_DIR, 'phishing_model_optimized.pkl')
            deep_path = os.path.join(Config.MODEL_DIR, 'phishing_model.pkl')
            
            if os.path.exists(quick_path):
                self.quick_model = joblib.load(quick_path)
            if os.path.exists(deep_path):
                self.deep_model = joblib.load(deep_path)
            
            print(f"Models loaded successfully from {Config.MODEL_DIR}")
        except Exception as e:
            print(f"Error loading models: {e}")

    def predict(self, url, mode="quick"):
        if not url:
            return {"error": "Invalid URL"}
            
        is_white = is_whitelisted(url)
        use_external = (mode == "deep")
        
        # Parallel Data Retrieval
        with ThreadPoolExecutor(max_workers=3) as executor:
            feat_future = executor.submit(FeatureService.extract_features, url, include_external=use_external)
            
            vt_res = None
            google_res = None
            if use_external and not is_white:
                vt_future = executor.submit(IntelService.check_virustotal, url)
                google_future = executor.submit(IntelService.check_google_safebrowsing, url)
                vt_res = vt_future.result()
                google_res = google_future.result()

            features, external_info = feat_future.result()

        # Format age
        if external_info and "domain_age_days" in external_info:
            external_info["formatted_age"] = format_domain_age(external_info["domain_age_days"])

        # Threat Intel Summary
        vt_pos = vt_res["malicious"] if vt_res else 0
        threat_intel = {
            "pos": vt_pos,
            "google_flagged": len(google_res) > 0 if google_res else False,
            "summary": "Clean" if vt_pos == 0 else f"Flagged by {vt_pos} engines"
        }
        
        # Model Prediction
        active_model = self.quick_model if mode == "quick" else self.deep_model
        prediction = 0
        confidence = 0.0

        if active_model:
            try:
                expected_n = active_model.n_features_in_
                # Use DataFrame to avoid UserWarning about feature names
                features_df = pd.DataFrame([features[:expected_n]], columns=FeatureService.FEATURE_NAMES[:expected_n])
                prediction = int(active_model.predict(features_df)[0])
                confidence = float(active_model.predict_proba(features_df)[0][prediction] * 100)
            except Exception as e:
                print(f"Prediction Error: {e}")
                prediction = 0
                confidence = 50.0

        # Risk Scoring
        risk_level = "Safe"
        if prediction == 1:
            risk_level = "High" if confidence > 85 else "Medium"
        else:
            risk_level = "Safe" if confidence > 90 else "Low Risk"

        # Expert Heuristic Rule Overrides (Improves Accuracy on edge cases)
        f_map = dict(zip(FeatureService.FEATURE_NAMES, features))
        
        # 1. Homograph Check (100% Phishing Indicator)
        if f_map.get('is_homograph', 0) == 1:
            prediction = 1
            confidence = max(confidence, 99.0)
            risk_level = "Critical"
            threat_intel["summary"] = "Flagged: Homograph/IDN brand impersonation detected."
            
        # 2. Direct IP + Sensitive Portal keywords (99% Phishing Indicator)
        elif f_map.get('has_ip', 0) == 1 and f_map.get('keyword_count', 0) >= 1:
            prediction = 1
            confidence = max(confidence, 98.0)
            risk_level = "Critical"
            threat_intel["summary"] = "Flagged: Raw IP hosting with sensitive access keywords."
            
        # 3. Brand spoofing (Impending impersonation attack)
        elif f_map.get('brand_spoof', 0) == 1 and f_map.get('keyword_count', 0) >= 1:
            prediction = 1
            confidence = max(confidence, 95.0)
            risk_level = "High"
            threat_intel["summary"] = "Flagged: Brand impersonation domain detected."
            
        # 4. Suspicious TLD + High Keyword Count
        elif f_map.get('suspicious_tld', 0) == 1 and f_map.get('keyword_count', 0) >= 2:
            prediction = 1
            confidence = max(confidence, 92.0)
            risk_level = "High"
            threat_intel["summary"] = "Flagged: Suspicious TLD hosting a multi-keyword portal."
            
        # 5. Domain age override: if domain age is new (<10 days) and it has any keywords
        if external_info and "domain_age_days" in external_info:
            age = external_info.get("domain_age_days", -1)
            if 0 <= age < 10 and f_map.get('keyword_count', 0) >= 1:
                prediction = 1
                confidence = max(confidence, 90.0)
                risk_level = "High"
                threat_intel["summary"] = "Flagged: Newly registered domain (<10 days) with portal keywords."

        # 6. Legacy Trust Override: If domain is older than 2 years and has clean intel
        if external_info and "domain_age_days" in external_info:
            age_days = external_info.get("domain_age_days", -1)
            if age_days > 730 and threat_intel["pos"] == 0 and not threat_intel["google_flagged"]:
                # Significantly downgrade risk for established clean domains
                if prediction == 1 and confidence < 95.0:
                    prediction, confidence, risk_level = 0, 98.0, "Safe"
                    threat_intel["summary"] = "Verified: Long-standing legacy domain with clean reputation."

        # Hard Overrides
        if is_white:
            prediction, confidence, risk_level = 0, 100.0, "Safe"
        elif threat_intel["google_flagged"] or threat_intel["pos"] > 0:
            prediction, confidence, risk_level = 1, 100.0, "Critical"

        # Explainable AI (XAI) Data Generation
        xai_report = self._generate_xai_report(url, features, external_info, threat_intel)

        return {
            "url": url,
            "prediction": prediction,
            "confidence": round(confidence, 2),
            "mode": mode,
            "risk_level": risk_level,
            "external_info": external_info,
            "threat_intel": threat_intel,
            "xai_report": xai_report
        }

    def _generate_xai_report(self, url, features, external_info, threat_intel):
        """Calculates normalized impact scores for various feature categories."""
        # Mapping FeatureService.FEATURE_NAMES to indices or values
        # Index-based mapping (0: url_len, 4: total_dots, etc.)
        f_map = dict(zip(FeatureService.FEATURE_NAMES, features))
        
        report = [
            {
                "label": "Suspicious Keywords",
                "value": f"{int(f_map.get('keyword_count', 0))} detected",
                "score": min(f_map.get('keyword_count', 0) * 20, 100),
                "desc": "Check for phishing terms like 'login', 'update', 'verify'."
            },
            {
                "label": "Subdomain Depth",
                "value": f"{int(f_map.get('subdomain_count', 0))} layers",
                "score": min(f_map.get('subdomain_count', 0) * 25, 100),
                "desc": "Excessive subdomains are often used to spoof legitimate brands."
            },
            {
                "label": "Visual Spoofing",
                "value": "Detected" if f_map.get('is_homograph', 0) == 1 else "None",
                "score": 100 if f_map.get('is_homograph', 0) == 1 else 0,
                "desc": "Cyrillic or look-alike characters used to deceive users."
            },
            {
                "label": "String Entropy",
                "value": f"{f_map.get('entropy', 0):.2f}",
                "score": min(max(0, (f_map.get('entropy', 0) - 3) * 25), 100),
                "desc": "High randomness (entropy) often indicates obfuscated URLs."
            },
            {
                "label": "Domain Authority",
                "value": f"{external_info.get('domain_age_days', -1)} days old",
                "score": 100 if external_info.get('domain_age_days', 0) < 30 and external_info.get('domain_age_days', 0) != -1 else 0,
                "desc": "New domains (<30 days) are statistically high risk."
            },
            {
                "label": "IP-Based Request",
                "value": "Yes" if f_map.get('has_ip', 0) == 1 else "No",
                "score": 100 if f_map.get('has_ip', 0) == 1 else 0,
                "desc": "Direct IP usage bypasses DNS reputation filters."
            },
            {
                "label": "Threat Intelligence",
                "value": threat_intel.get('summary', 'Clean'),
                "score": min(threat_intel.get('pos', 0) * 40, 100),
                "desc": "Global reputation database matches (VirusTotal/Google)."
            },
            {
                "label": "DNS Integrity",
                "value": "Verified" if external_info.get('dns_valid', 0) == 1 else "Missing",
                "score": 0 if external_info.get('dns_valid', 0) == 1 else 80,
                "desc": "Invalid DNS records can indicate temporary malicious setups."
            }
        ]
        
        # Calculate "SHAP" Feature Importance (Top contributing features)
        # We simulate this based on the normalized scores
        shap_values = []
        for item in report:
            if item["score"] > 0:
                shap_values.append({
                    "feature": item["label"],
                    "impact": item["score"],
                    "type": "negative"
                })
        
        # Sort and return
        return {
            "insights": report,
            "shap": sorted(shap_values, key=lambda x: x["impact"], reverse=True)[:5],
            "full_features": f_map
        }
