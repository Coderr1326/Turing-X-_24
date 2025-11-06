import os
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# API Configuration
ABUSEIPDB_API_KEY = os.getenv('ABUSEIPDB_API_KEY', '')
VIRUSTOTAL_API_KEY = os.getenv('VIRUSTOTAL_API_KEY', '')
ALIENVAULT_API_KEY = os.getenv('ALIENVAULT_API_KEY', '')

# Database
DATABASE_PATH = os.getenv('DATABASE_PATH', 'data/threat_intel.db')

# Thresholds
MALICIOUS_THRESHOLD = int(os.getenv('MALICIOUS_THRESHOLD', 50))
HIGH_CONFIDENCE_THRESHOLD = int(os.getenv('HIGH_CONFIDENCE_THRESHOLD', 75))

# Category Mapping (Normalization)[source:96]
CATEGORY_MAPPING = {
    # Command & Control
    "c2": "c2_server",
    "c&c": "c2_server",
    "command and control": "c2_server",
    "cnc": "c2_server",
    
    # Botnet
    "bot": "botnet",
    "botnet": "botnet",
    "zombie": "botnet",
    
    # Phishing
    "phish": "phishing",
    "phishing": "phishing",
    "credential theft": "phishing",
    
    # Malware
    "malware": "malware",
    "virus": "malware",
    "trojan": "malware",
    "worm": "malware",
    
    # Ransomware
    "ransomware": "ransomware",
    "crypto-locker": "ransomware",
    
    # Spam
    "spam": "spam",
    "spammer": "spam",
    "email spam": "spam",
    
    # Scanner/Brute Force
    "scanner": "scanner",
    "brute": "scanner",
    "brute force": "scanner",
    "port scan": "scanner",
    "ssh brute": "scanner",
    
    # DDoS
    "ddos": "ddos_source",
    "dos": "ddos_source",
    "amplification": "ddos_source",
    
    # Proxy/VPN
    "proxy": "proxy",
    "vpn": "vpn",
    "tor": "tor_exit",
    "tor exit": "tor_exit",
    
    # Mining
    "mining": "mining",
    "cryptomining": "mining",
    "crypto mining": "mining",
    
    # Exploit
    "exploit": "exploit",
    "exploitation": "exploit",
    "vulnerability scan": "exploit"
}

# Source Reliability (NATO Admiralty Code)[source:38]
SOURCE_RELIABILITY = {
    'AbuseIPDB': 'A',        # Completely reliable
    'VirusTotal': 'A',       # Completely reliable
    'AlienVault OTX': 'B',   # Usually reliable
    'Shodan': 'B',           # Usually reliable
    'IPApi': 'C',            # Fairly reliable
    'Custom': 'D'            # Not usually reliable
}

# Source Weights for Reputation Scoring[source:100]
SOURCE_WEIGHTS = {
    'AbuseIPDB': 1.0,
    'VirusTotal': 1.0,
    'AlienVault OTX': 0.8,
    'Shodan': 0.7,
    'IPApi': 0.5,
    'Custom': 0.3
}

# Threat Level Mapping[source:100]
THREAT_LEVELS = {
    (75, 100): 'critical',   # 75+ = Malicious
    (50, 74): 'high',        # 50-74 = Suspicious
    (25, 49): 'medium',      # 25-49 = Neutral
    (1, 24): 'low',          # 1-24 = Unknown
    (0, 0): 'benign'         # 0 = Clean
}

def get_threat_level(score):
    """Determine threat level from confidence score"""
    for (min_score, max_score), level in THREAT_LEVELS.items():
        if min_score <= score <= max_score:
            return level
    return 'unknown'
