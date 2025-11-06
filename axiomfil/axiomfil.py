import csv
import requests

API_KEY = '75af0f83d0a52d2b06eb839d18d60ef9327e0ab4599c1dc15e3bddead6992608'
BASE_URL = 'https://www.virustotal.com/api/v3/ip_addresses/'

headers = {
    'x-apikey': API_KEY
}

def check_ip_reputation(ip):
    url = BASE_URL + ip
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        data = response.json()
        attributes = data.get('data', {}).get('attributes', {})

        reputation = attributes.get('reputation', 'N/A')
        geolocation = attributes.get('country', 'N/A')
        categories = attributes.get('categories', [])
        resolutions = attributes.get('resolutions', [])
        source_credibility = attributes.get('last_analysis_stats', {})

        return {
            'ip': ip,
            'reputation': reputation,
            'categories': categories,
            'geolocation': geolocation,
            'domain_associations': [res.get('hostname') for res in resolutions],
            'source_credibility': source_credibility
        }
    else:
        print(f"Failed to get data for IP {ip}. Status code: {response.status_code}")
        return {'ip': ip, 'error': f'Status code {response.status_code}'}

def main(csv_file):
    results = []
    with open(csv_file, 'r') as f:
        reader = csv.reader(f)
        for row in reader:
            if row:
                ip = row[0].strip()
                result = check_ip_reputation(ip)
                results.append(result)

    for res in results:
        if 'error' in res:
            print(f"IP: {res['ip']} - Error: {res['error']}")
        else:
            print(f"IP: {res['ip']}")
            print(f"  Reputation score: {res['reputation']}")
            print(f"  Threat categories: {res['categories']}")
            print(f"  Geolocation: {res['geolocation']}")
            print(f"  Domain associations: {res['domain_associations']}")
            print(f"  Source credibility (last analysis stats): {res['source_credibility']}\n")

if __name__ == '__main__':
    csv_path = 'C:\\Users\\preet\\OneDrive\\Pictures\\Documents\\axiom2025\\ips.csv'  # Path to your CSV file with IPs listed one per line
    main(csv_path)