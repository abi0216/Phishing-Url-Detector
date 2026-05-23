import requests
import base64
from config.settings import Config

class IntelService:
    @staticmethod
    def check_virustotal(url):
        """Checks VirusTotal for malicious reputation."""
        if not Config.VIRUSTOTAL_API_KEY:
            return None
        try:
            url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
            headers = {"x-apikey": Config.VIRUSTOTAL_API_KEY}
            response = requests.get(f"https://www.virustotal.com/api/v3/urls/{url_id}", headers=headers, timeout=5)
            if response.status_code == 200:
                data = response.json()
                stats = data['data']['attributes']['last_analysis_stats']
                return {"malicious": stats['malicious'], "suspicious": stats['suspicious'], "harmless": stats['harmless']}
        except Exception as e:
            print(f"VirusTotal Error: {e}")
        return None

    @staticmethod
    def check_google_safebrowsing(url):
        """Checks Google Safe Browsing for threats."""
        if not Config.GOOGLE_SAFE_BROWSING_KEY:
            return None
        try:
            api_url = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={Config.GOOGLE_SAFE_BROWSING_KEY}"
            payload = {
                "client": {"clientId": "phish-guard", "clientVersion": "1.0.0"},
                "threatInfo": {
                    "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE"],
                    "platformTypes": ["ANY_PLATFORM"],
                    "threatEntryTypes": ["URL"],
                    "threatEntries": [{"url": url}]
                }
            }
            response = requests.post(api_url, json=payload, timeout=5)
            if response.status_code == 200:
                data = response.json()
                return data.get('matches', [])
        except Exception as e:
            print(f"Google Safe Browsing Error: {e}")
        return None
