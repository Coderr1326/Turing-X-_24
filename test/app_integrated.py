from flask import Flask, request, jsonify, render_template
import requests
import os
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# Get API keys from environment variables
VIRUSTOTAL_API_KEY = os.getenv('VIRUSTOTAL_API_KEY')
ALIENVAULT_API_KEY = os.getenv('ALIENVAULT_API_KEY')
IPINFO_API_KEY = os.getenv('IPINFO_API_KEY')
SHODAN_API_KEY = os.getenv('SHODAN_API_KEY')

# Validate that all keys are loaded
if not all([VIRUSTOTAL_API_KEY, ALIENVAULT_API_KEY, IPINFO_API_KEY, SHODAN_API_KEY]):
    raise ValueError("Missing one or more API keys in .env file! Please check your .env configuration.")

app = Flask(__name__)


# ============================================
# IPINFO.IO API (for Geolocation + ASN)
# ============================================
def get_ipinfo_data(ip):
    """Query ipinfo.io API for geolocation and ASN"""
    try:
        url = f"https://ipinfo.io/{ip}/json?token={IPINFO_API_KEY}"
        response = requests.get(url, timeout=10)
        
        if response.status_code == 200:
            data = response.json()
            
            loc = data.get('loc', ',').split(',')
            latitude = loc[0] if len(loc) > 0 else 'N/A'
            longitude = loc[1] if len(loc) > 1 else 'N/A'
            
            return {
                'ip': data.get('ip', ip),
                'city': data.get('city', 'N/A'),
                'region': data.get('region', 'N/A'),
                'country': data.get('country', 'N/A'),
                'timezone': data.get('timezone', 'N/A'),
                'latitude': latitude,
                'longitude': longitude,
                'asn': data.get('org', 'N/A').split()[0] if data.get('org') else 'N/A',
                'isp': data.get('org', 'N/A'),
            }
        else:
            return {'ip': ip, 'asn': 'Error', 'isp': 'Error', 'country': 'Error', 'city': 'N/A', 'region': 'N/A', 'timezone': 'N/A', 'latitude': 'N/A', 'longitude': 'N/A'}
    except Exception as e:
        return {'ip': ip, 'asn': 'Error', 'isp': str(e), 'country': 'Error', 'city': 'N/A', 'region': 'N/A', 'timezone': 'N/A', 'latitude': 'N/A', 'longitude': 'N/A'}


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
                'details': f"Malicious: {malicious}, Suspicious: {suspicious}, Harmless: {harmless}"
            }
        else:
            return {'source': 'VirusTotal', 'detected': False, 'score': 0, 'categories': [], 'malicious': 0, 'suspicious': 0, 'harmless': 0, 'undetected': 0, 'details': 'API Error', 'error': True}
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
                'details': f"Found in {pulse_count} threat pulses"
            }
        else:
            return {'source': 'AlienVault OTX', 'detected': False, 'score': 0, 'categories': [], 'malicious': 0, 'suspicious': 0, 'harmless': 0, 'undetected': 0, 'details': 'No Data', 'error': True}
    except Exception as e:
        return {'source': 'AlienVault OTX', 'detected': False, 'score': 0, 'categories': [], 'malicious': 0, 'suspicious': 0, 'harmless': 0, 'undetected': 0, 'details': str(e), 'error': True}


# ============================================
# SHODAN API
# ============================================
def get_shodan_data(ip):
    """Query Shodan API for exposed services and ports"""
    url = f"https://api.shodan.io/shodan/host/{ip}?key={SHODAN_API_KEY}"
    
    try:
        response = requests.get(url, timeout=10)
        if response.status_code == 200:
            data = response.json()
            
            ports = data.get('ports', [])
            vulns = data.get('vulns', [])
            hostnames = data.get('hostnames', [])
            org = data.get('org', 'N/A')
            isp = data.get('isp', 'N/A')
            
            port_count = len(ports)
            vuln_count = len(vulns)
            
            score = 0
            detected = False
            categories = []
            
            if vuln_count > 0:
                score = min(vuln_count * 20, 100)
                detected = True
                categories.append('vulnerable-services')
            elif port_count > 10:
                score = 30
                detected = True
                categories.append('exposed-services')
            
            return {
                'source': 'Shodan',
                'detected': detected,
                'score': score,
                'categories': categories,
                'malicious': vuln_count,
                'suspicious': 1 if port_count > 10 else 0,
                'harmless': 0 if detected else 1,
                'undetected': 0,
                'details': f"Open Ports: {port_count}, Vulnerabilities: {vuln_count}",
                'ports': ports[:10],
                'hostnames': hostnames,
                'org': org,
                'isp': isp
            }
        else:
            return {'source': 'Shodan', 'detected': False, 'score': 0, 'categories': [], 'malicious': 0, 'suspicious': 0, 'harmless': 0, 'undetected': 0, 'details': 'No Data', 'error': True}
    except Exception as e:
        return {'source': 'Shodan', 'detected': False, 'score': 0, 'categories': [], 'malicious': 0, 'suspicious': 0, 'harmless': 0, 'undetected': 0, 'details': str(e), 'error': True}


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
    
    source_weights = {
        'VirusTotal': 2.0,
        'AlienVault OTX': 1.5,
        'Shodan': 1.0
    }
    
    for source in sources_data:
        if not source.get('error'):
            weight = source_weights.get(source['source'], 1.0)
            total_score += source['score'] * weight
            total_weight += weight
            
            if source['detected']:
                detected_count += 1
            
            all_categories.update(source.get('categories', []))
            
            total_malicious += source.get('malicious', 0)
            total_suspicious += source.get('suspicious', 0)
            total_harmless += source.get('harmless', 0)
            total_undetected += source.get('undetected', 0)
    
    aggregated_score = int(total_score / total_weight) if total_weight > 0 else 0
    
    if total_malicious > 0:
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
    
    if detected_count > 0:
        confidence = max(50, int((detected_count / len([s for s in sources_data if not s.get('error')])) * 100))
    else:
        confidence = 100
    
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
    
    virustotal_result = get_virustotal_data(ip)
    alienvault_result = get_alienvault_data(ip)
    shodan_result = get_shodan_data(ip)
    ipinfo_data = get_ipinfo_data(ip)
    
    multi_source_data = [virustotal_result, alienvault_result, shodan_result]
    aggregated = aggregate_threat_data(multi_source_data)
    
    unified_response = {
        'ip': ip,
        'value': ip,
        **aggregated,
        'multiSourceData': multi_source_data,
        'geolocation': ipinfo_data,
        'type': 'IPv4',
        'lastUpdated': '2025-11-07T03:15:00Z'
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


if __name__ == '__main__':
    app.run(debug=True)
