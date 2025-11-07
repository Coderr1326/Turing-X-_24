from flask import Flask, request, jsonify, render_template
import requests
import os
from dotenv import load_dotenv
from datetime import datetime

# Load environment variables
load_dotenv()

# API Keys
VIRUSTOTAL_API_KEY = os.getenv('VIRUSTOTAL_API_KEY')
IPINFO_API_KEY = os.getenv('IPINFO_API_KEY')
SHODAN_API_KEY = os.getenv('SHODAN_API_KEY')

app = Flask(__name__)


# ============================================
# AI THREAT CATEGORIZATION MODEL
# ============================================

def categorize_threat(ip_data):
    """
    AI-based threat categorization using rule-based ML approach
    Analyzes multiple signals to categorize threat type
    """
    categories = []
    confidence_scores = {}
    
    # Extract features from all sources
    vt_data = next((s for s in ip_data.get('multiSourceData', []) if s.get('source') == 'VirusTotal'), {})
    shodan_data = next((s for s in ip_data.get('multiSourceData', []) if s.get('source') == 'Shodan'), {})
    
    vt_malicious = vt_data.get('malicious', 0)
    vt_suspicious = vt_data.get('suspicious', 0)
    shodan_vulns = shodan_data.get('malicious', 0)  # vuln count
    shodan_ports = len(shodan_data.get('ports', []))
    dangerous_ports = len(shodan_data.get('dangerous_ports', []))
    
    # ========================================
    # BOTNET DETECTION
    # ========================================
    botnet_score = 0
    if vt_malicious > 3:
        botnet_score += 40
    if 'malicious' in vt_data.get('categories', []):
        botnet_score += 30
    if shodan_ports > 15:  # Many open ports
        botnet_score += 20
    if 445 in shodan_data.get('ports', []) or 3389 in shodan_data.get('ports', []):
        botnet_score += 10
    
    if botnet_score >= 50:
        categories.append('Botnet / C2 Server')
        confidence_scores['Botnet'] = min(botnet_score, 100)
    
    # ========================================
    # MALWARE DISTRIBUTION
    # ========================================
    malware_score = 0
    if vt_malicious >= 5:
        malware_score += 50
    if 80 in shodan_data.get('ports', []) or 443 in shodan_data.get('ports', []):
        malware_score += 20
    if shodan_ports > 5:
        malware_score += 15
    
    if malware_score >= 45:
        categories.append('Malware Distribution')
        confidence_scores['Malware'] = min(malware_score, 100)
    
    # ========================================
    # PHISHING / SCAM
    # ========================================
    phishing_score = 0
    if vt_suspicious >= 3:
        phishing_score += 35
    if 80 in shodan_data.get('ports', []) or 443 in shodan_data.get('ports', []):
        phishing_score += 25
    if vt_malicious >= 2 and vt_malicious < 5:
        phishing_score += 25
    
    if phishing_score >= 40:
        categories.append('Phishing / Scam')
        confidence_scores['Phishing'] = min(phishing_score, 100)
    
    # ========================================
    # BRUTE FORCE / SCANNER
    # ========================================
    scanner_score = 0
    if dangerous_ports >= 2:
        scanner_score += 40
    if 22 in shodan_data.get('ports', []):  # SSH
        scanner_score += 20
    if 3389 in shodan_data.get('ports', []):  # RDP
        scanner_score += 20
    if shodan_ports > 10:
        scanner_score += 20
    
    if scanner_score >= 50:
        categories.append('Brute Force / Scanner')
        confidence_scores['Scanner'] = min(scanner_score, 100)
    
    # ========================================
    # VULNERABLE SERVER
    # ========================================
    vuln_score = 0
    if shodan_vulns > 0:
        vuln_score += shodan_vulns * 30
    if dangerous_ports >= 1:
        vuln_score += 30
    
    if vuln_score >= 40:
        categories.append('Vulnerable Server')
        confidence_scores['Vulnerable'] = min(vuln_score, 100)
    
    # ========================================
    # SPAM / PROXY
    # ========================================
    spam_score = 0
    if vt_suspicious >= 2:
        spam_score += 30
    if 25 in shodan_data.get('ports', []) or 587 in shodan_data.get('ports', []):  # SMTP
        spam_score += 30
    if 8080 in shodan_data.get('ports', []) or 3128 in shodan_data.get('ports', []):  # Proxy
        spam_score += 25
    
    if spam_score >= 40:
        categories.append('Spam / Proxy')
        confidence_scores['Spam'] = min(spam_score, 100)
    
    # If no categories detected
    if not categories:
        categories = ['Unknown / General Threat' if ip_data.get('threatLevel') != 'safe' else 'Legitimate / Safe']
        confidence_scores['General'] = 50
    
    return {
        'categories': categories,
        'confidence_scores': confidence_scores,
        'primary_threat': categories[0] if categories else 'Unknown'
    }


# ============================================
# THREAT INTELLIGENCE SOURCES
# ============================================

def get_ipinfo_data(ip):
    """IPInfo.io - Geolocation & ASN"""
    try:
        url = f"https://ipinfo.io/{ip}/json?token={IPINFO_API_KEY}"
        response = requests.get(url, timeout=10)
        
        if response.status_code == 200:
            data = response.json()
            loc = data.get('loc', ',').split(',')
            
            latitude = loc[0] if len(loc) > 0 else 'N/A'
            longitude = loc[1] if len(loc) > 1 else 'N/A'
            
            org = data.get('org', '')
            asn = org.split()[0] if org else 'N/A'
            
            return {
                'ip': data.get('ip', ip),
                'city': data.get('city', 'N/A'),
                'region': data.get('region', 'N/A'),
                'country': data.get('country', 'N/A'),
                'timezone': data.get('timezone', 'N/A'),
                'latitude': latitude,
                'longitude': longitude,
                'asn': asn,
                'isp': org,
            }
        else:
            return {'ip': ip, 'error': True}
    except Exception as e:
        return {'ip': ip, 'error': True}


def get_virustotal_data(ip):
    """VirusTotal - Malware & Threat Detection"""
    try:
        url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
        headers = {"x-apikey": VIRUSTOTAL_API_KEY}
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
                score = int(((malicious * 100) + (suspicious * 60)) / total)
            
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
        elif response.status_code == 429:
            return {
                'source': 'VirusTotal',
                'detected': False,
                'score': 0,
                'categories': [],
                'malicious': 0,
                'suspicious': 0,
                'harmless': 0,
                'undetected': 0,
                'details': '⏰ Rate Limited - Try again later',
                'error': True,
                'rate_limited': True
            }
        else:
            return {'source': 'VirusTotal', 'error': True, 'detected': False, 'score': 0, 'categories': [], 'malicious': 0, 'suspicious': 0, 'harmless': 0, 'undetected': 0}
    except:
        return {'source': 'VirusTotal', 'error': True, 'detected': False, 'score': 0, 'categories': [], 'malicious': 0, 'suspicious': 0, 'harmless': 0, 'undetected': 0}


def get_shodan_data(ip):
    """Shodan - Open Ports & Vulnerabilities"""
    try:
        url = f"https://api.shodan.io/shodan/host/{ip}?key={SHODAN_API_KEY}"
        response = requests.get(url, timeout=10)
        
        if response.status_code == 200:
            data = response.json()
            
            ports = data.get('ports', [])
            vulns = data.get('vulns', []) or []
            hostnames = data.get('hostnames', [])
            org = data.get('org', 'N/A')
            os_info = data.get('os', 'N/A')
            
            port_count = len(ports)
            vuln_count = len(vulns)
            
            score = 0
            detected = False
            categories = []
            
            if vuln_count > 0:
                score = min(vuln_count * 25, 80)
                detected = True
                categories.append('vulnerable-services')
            
            dangerous_ports = set([21, 22, 23, 445, 3389, 6379, 27017, 3306, 1433, 5432]) & set(ports)
            if dangerous_ports:
                score += 20
                detected = True
                categories.append('exposed-services')
            
            if port_count > 15:
                score += 15
                detected = True
                if 'exposed-services' not in categories:
                    categories.append('exposed-services')
            elif port_count > 10:
                score += 10
                detected = True
                if 'exposed-services' not in categories:
                    categories.append('exposed-services')
            
            score = min(score, 100)
            
            return {
                'source': 'Shodan',
                'detected': detected,
                'score': score,
                'categories': categories,
                'malicious': vuln_count,
                'suspicious': 1 if port_count > 10 else 0,
                'harmless': 0 if detected else 1,
                'undetected': 0,
                'details': f"Open Ports: {port_count}, Vulnerabilities: {vuln_count}, OS: {os_info}",
                'ports': ports[:15],
                'dangerous_ports': list(dangerous_ports),
                'hostnames': hostnames,
                'org': org,
                'os': os_info,
                'vulns': list(vulns)[:10]
            }
        else:
            return {'source': 'Shodan', 'error': True, 'detected': False, 'score': 0, 'categories': [], 'malicious': 0, 'suspicious': 0, 'harmless': 0, 'undetected': 0}
    except:
        return {'source': 'Shodan', 'error': True, 'detected': False, 'score': 0, 'categories': [], 'malicious': 0, 'suspicious': 0, 'harmless': 0, 'undetected': 0}


# ============================================
# THREAT CORRELATION ENGINE
# ============================================

def aggregate_threat_data(sources_data):
    """Correlate and normalize multi-source threat intelligence"""
    
    total_score = 0
    total_weight = 0
    all_categories = set()
    detected_count = 0
    
    total_malicious = 0
    total_suspicious = 0
    total_harmless = 0
    total_undetected = 0
    
    source_weights = {
        'VirusTotal': 2.5,
        'Shodan': 2.0
    }
    
    for source in sources_data:
        if not source.get('error'):
            weight = source_weights.get(source['source'], 1.0)
            total_score += source.get('score', 0) * weight
            total_weight += weight
            
            if source.get('detected'):
                detected_count += 1
            
            all_categories.update(source.get('categories', []))
            
            total_malicious += source.get('malicious', 0)
            total_suspicious += source.get('suspicious', 0)
            total_harmless += source.get('harmless', 0)
            total_undetected += source.get('undetected', 0)
    
    aggregated_score = int(total_score / total_weight) if total_weight > 0 else 0
    
    if aggregated_score >= 70:
        threat_level = 'critical'
    elif aggregated_score >= 50:
        threat_level = 'high'
    elif aggregated_score >= 30:
        threat_level = 'medium'
    elif aggregated_score >= 15:
        threat_level = 'low'
    else:
        threat_level = 'safe'
    
    active_sources = len([s for s in sources_data if not s.get('error')])
    
    if detected_count > 0:
        confidence = int((detected_count / active_sources) * 100) if active_sources > 0 else 50
        confidence = max(confidence, 60)
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


def get_threat_attribution_report(ip):
    """Generate comprehensive threat attribution report with AI categorization"""
    
    virustotal_result = get_virustotal_data(ip)
    shodan_result = get_shodan_data(ip)
    ipinfo_data = get_ipinfo_data(ip)
    
    multi_source_data = [virustotal_result, shodan_result]
    
    aggregated = aggregate_threat_data(multi_source_data)
    
    # Build unified threat profile
    threat_profile = {
        'ip': ip,
        'timestamp': datetime.utcnow().isoformat() + 'Z',
        **aggregated,
        'multiSourceData': multi_source_data,
        'geolocation': ipinfo_data,
        'type': 'IPv4',
        'attribution': {
            'isMalicious': aggregated['threatLevel'] in ['critical', 'high', 'medium'],
            'threatCategories': aggregated['categories'],
            'geolocation': f"{ipinfo_data.get('city', 'Unknown')}, {ipinfo_data.get('country', 'Unknown')}",
            'asn': ipinfo_data.get('asn', 'Unknown'),
            'relatedDomains': shodan_result.get('hostnames', []) if not shodan_result.get('error') else []
        }
    }
    
    # ✅ ADD AI THREAT CATEGORIZATION
    ai_categorization = categorize_threat(threat_profile)
    threat_profile['aiCategorization'] = ai_categorization
    
    return threat_profile


# ============================================
# FLASK ROUTES
# ============================================

@app.route('/')
def index():
    return render_template('index.html')


@app.route('/check/<ip>', methods=['GET'])
def check_ip(ip):
    """API endpoint for threat intelligence analysis"""
    result = get_threat_attribution_report(ip)
    return jsonify(result)


@app.route('/api/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({
        'status': 'healthy',
        'service': 'TICE - Threat Intelligence Correlation Engine',
        'version': '2.0.0'
    })


if __name__ == '__main__':
    print("🔥 TICE - Threat Intelligence Correlation Engine v2.0")
    print("=" * 50)
    print("🎨 Enhanced UI with Interactive Map")
    print("🤖 AI-Powered Threat Categorization")
    print("📊 Active Sources: VirusTotal, Shodan, IPInfo")
    print("Server starting on http://127.0.0.1:5000")
    print("=" * 50)
    app.run(debug=True, host='0.0.0.0', port=5000)
