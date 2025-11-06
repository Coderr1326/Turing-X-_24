from flask import Flask, request, jsonify, render_template
import requests
import base64
import os
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

app = Flask(__name__)

# Get API keys from environment variables
GEOLOCATION_API_KEY = os.getenv('GEOLOCATION_API_KEY')
VIRUSTOTAL_API_KEY = os.getenv('VIRUSTOTAL_API_KEY')
ALIENVAULT_API_KEY = os.getenv('ALIENVAULT_API_KEY')
IPINFO_API_KEY = os.getenv('IPINFO_API_KEY')
app = Flask(__name__)


# ============================================
# IPINFO.IO API (for Geolocation + ASN)
# ============================================
def get_ipinfo_data(ip):
    """Query ipinfo.io API for geolocation and ASN"""
    try:
        url = f"https://api.ipinfo.io/lite/{ip}?token={IPINFO_API_KEY}"
        response = requests.get(url, timeout=10)
        
        if response.status_code == 200:
            data = response.json()
            
            return {
                'ip': data.get('ip', ip),
                'asn': data.get('asn', 'N/A'),
                'as_name': data.get('as_name', 'N/A'),
                'as_domain': data.get('as_domain', 'N/A'),
                'country': data.get('country', 'N/A'),
                'country_code': data.get('country_code', 'N/A'),
                'continent': data.get('continent', 'N/A'),
                'continent_code': data.get('continent_code', 'N/A'),
                'city': 'N/A',  # Lite API doesn't include city
                'region': 'N/A',
                'timezone': 'N/A',
                'latitude': 'N/A',
                'longitude': 'N/A'
            }
        else:
            return {'ip': ip, 'asn': 'Error', 'as_name': 'Error', 'country': 'Error', 'city': 'N/A', 'region': 'N/A', 'timezone': 'N/A', 'latitude': 'N/A', 'longitude': 'N/A'}
    except Exception as e:
        return {'ip': ip, 'asn': 'Error', 'as_name': str(e), 'country': 'Error', 'city': 'N/A', 'region': 'N/A', 'timezone': 'N/A', 'latitude': 'N/A', 'longitude': 'N/A'}


# ============================================
# VirusTotal API
# ============================================
def get_virustotal_data(ip):
    """Query VirusTotal API"""
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    headers = {"x-apikey": VIRUSTOTAL_API_KEY}

    try:
        response = requests.get(url, headers=headers, timeout=10)
        if response.status_code == 200:
            data = response.json()
            stats = data.get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
            
            malicious = stats.get('malicious', 0)
            suspicious = stats.get('suspicious', 0)
            harmless = stats.get('harmless', 0)
            undetected = stats.get('undetected', 0)
            total = malicious + suspicious + harmless + undetected
            
            score = 0
            if total > 0:
                score = int(((malicious * 100) + (suspicious * 50)) / total)
            
            categories = []
            if malicious > 0:
                categories.append('malicious')
            if suspicious > 0:
                categories.append('suspicious')
            
            return {
                'source': 'VirusTotal',
                'detected': malicious > 0 or suspicious > 0,
                'score': score,
                'categories': categories,
                'malicious': malicious,
                'suspicious': suspicious,
                'harmless': harmless,
                'undetected': undetected,
                'details': f"Malicious: {malicious}, Suspicious: {suspicious}, Harmless: {harmless}",
                'raw_data': data
            }
        else:
            return {'source': 'VirusTotal', 'detected': False, 'score': 0, 'categories': [], 'malicious': 0, 'suspicious': 0, 'harmless': 0, 'undetected': 0, 'details': 'API Error or No Data', 'error': True}
    except Exception as e:
        return {'source': 'VirusTotal', 'detected': False, 'score': 0, 'categories': [], 'malicious': 0, 'suspicious': 0, 'harmless': 0, 'undetected': 0, 'details': str(e), 'error': True}


# ============================================
# AlienVault OTX API
# ============================================
def get_alienvault_data(ip):
    """Query AlienVault OTX API"""
    url = f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/general"
    headers = {"X-OTX-API-KEY": ALIENVAULT_API_KEY}

    try:
        response = requests.get(url, headers=headers, timeout=10)
        if response.status_code == 200:
            data = response.json()
            pulse_count = data.get('pulse_info', {}).get('count', 0)
            
            # If IP is in pulses, it's likely malicious
            detected = pulse_count > 0
            score = min(pulse_count * 10, 100) if detected else 0
            
            categories = []
            if detected:
                categories.append('threat-pulse')
            
            return {
                'source': 'AlienVault OTX',
                'detected': detected,
                'score': score,
                'categories': categories,
                'malicious': pulse_count if detected else 0,
                'suspicious': 0,
                'harmless': 0 if detected else 1,
                'undetected': 0,
                'details': f"Found in {pulse_count} threat pulses",
                'raw_data': data
            }
        else:
            return {'source': 'AlienVault OTX', 'detected': False, 'score': 0, 'categories': [], 'malicious': 0, 'suspicious': 0, 'harmless': 0, 'undetected': 0, 'details': 'API Error or No Data', 'error': True}
    except Exception as e:
        return {'source': 'AlienVault OTX', 'detected': False, 'score': 0, 'categories': [], 'malicious': 0, 'suspicious': 0, 'harmless': 0, 'undetected': 0, 'details': str(e), 'error': True}


# ============================================
# MULTI-SOURCE AGGREGATION
# ============================================
def aggregate_threat_data(sources_data):
    """Aggregate and normalize data from multiple sources"""
    total_score = 0
    total_weight = 0
    all_categories = set()
    detected_count = 0
    
    total_malicious = 0
    total_suspicious = 0
    total_harmless = 0
    total_undetected = 0
    
    # Weight each source
    source_weights = {
        'VirusTotal': 2.0,  # Highest weight
        'AlienVault OTX': 1.0
    }
    
    for source in sources_data:
        if not source.get('error'):
            weight = source_weights.get(source['source'], 1.0)
            total_score += source['score'] * weight
            total_weight += weight
            
            if source['detected']:
                detected_count += 1
            
            all_categories.update(source.get('categories', []))
            
            # Aggregate reputation stats
            total_malicious += source.get('malicious', 0)
            total_suspicious += source.get('suspicious', 0)
            total_harmless += source.get('harmless', 0)
            total_undetected += source.get('undetected', 0)
    
    # Calculate aggregated score
    aggregated_score = int(total_score / total_weight) if total_weight > 0 else 0
    
    # Determine threat level based on ACTUAL DETECTIONS and SCORE
    if total_malicious > 0:
        # If ANY source detected malicious, classify based on score
        if aggregated_score >= 70:
            threat_level = 'critical'
        elif aggregated_score >= 50:
            threat_level = 'high'
        elif aggregated_score >= 30:
            threat_level = 'medium'
        else:
            threat_level = 'low'
    elif total_suspicious > 0:
        threat_level = 'medium'
    else:
        threat_level = 'safe'
    
    # Calculate confidence (100% if any detections, scaled by agreement)
    if detected_count > 0:
        confidence = max(50, int((detected_count / len([s for s in sources_data if not s.get('error')])) * 100))
    else:
        confidence = 100  # 100% confident it's safe if no detections
    
    return {
        'aggregatedScore': aggregated_score,
        'threatLevel': threat_level,
        'confidenceScore': confidence,
        'categories': list(all_categories),
        'sourcesQueried': [s['source'] for s in sources_data if not s.get('error')],
        'detectionCount': detected_count,
        'reputation': {
            'malicious': total_malicious,
            'suspicious': total_suspicious,
            'harmless': total_harmless,
            'undetected': total_undetected
        }
    }


# ============================================
# MAIN ANALYSIS FUNCTION
# ============================================
def get_complete_ip_analysis(ip):
    """Combine all sources and return unified threat profile"""
    
    # Query all sources
    virustotal_result = get_virustotal_data(ip)
    alienvault_result = get_alienvault_data(ip)
    
    # Get IPInfo data for geolocation + ASN
    ipinfo_data = get_ipinfo_data(ip)
    
    # Combine threat intelligence sources
    multi_source_data = [virustotal_result, alienvault_result]
    
    # Aggregate the data
    aggregated = aggregate_threat_data(multi_source_data)
    
    # Build unified response
    unified_response = {
        'ip': ip,
        'value': ip,
        **aggregated,
        'multiSourceData': multi_source_data,
        'geolocation': {
            'country': ipinfo_data.get('country', 'N/A'),
            'country_code': ipinfo_data.get('country_code', 'N/A'),
            'continent': ipinfo_data.get('continent', 'N/A'),
            'city': ipinfo_data.get('city', 'N/A'),
            'region': ipinfo_data.get('region', 'N/A'),
            'timezone': ipinfo_data.get('timezone', 'N/A'),
            'latitude': ipinfo_data.get('latitude', 'N/A'),
            'longitude': ipinfo_data.get('longitude', 'N/A'),
            'asn': ipinfo_data.get('asn', 'N/A'),
            'isp': ipinfo_data.get('as_name', 'N/A'),
            'as_domain': ipinfo_data.get('as_domain', 'N/A')
        },
        'type': 'IPv4',
        'lastUpdated': '2025-11-07T00:08:00Z',
        'metadata': {
            'threatLevel': aggregated['threatLevel']
        }
    }
    
    return unified_response


# ============================================
# FLASK ROUTES
# ============================================
@app.route('/')
def index():
    return render_template('index.html')


@app.route('/check/<ip>', methods=['GET'])
def check_ip(ip):
    """Main endpoint for IP analysis"""
    result = get_complete_ip_analysis(ip)
    return jsonify(result)


@app.route('/check', methods=['POST'])
def check_ip_post():
    """POST endpoint for IP analysis"""
    data = request.get_json()
    ip = data.get('ip')
    
    if not ip:
        return jsonify({'error': True, 'message': 'IP address required'}), 400
    
    result = get_complete_ip_analysis(ip)
    return jsonify(result)


if __name__ == '__main__':
    app.run(debug=True)
