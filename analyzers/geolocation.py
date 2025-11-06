import requests

def get_ip_location(ip_address, api_key):
    url = f"https://geo.ipify.org/api/v2/country,city?apiKey={api_key}&ipAddress={ip_address}"
    response = requests.get(url)
    if response.status_code == 200:
        data = response.json()
        city = data.get('location', {}).get('city', 'N/A')
        region = data.get('location', {}).get('region', 'N/A')
        country = data.get('location', {}).get('country', 'N/A')
        return f"City: {city}, Region: {region}, Country: {country}"
    else:
        return f"Error fetching location, status code: {response.status_code}"

if __name__ == "_main_":
    ip = input("Enter IP address: ")
    api_key = input("Enter your Geo.IPify API key: ")
    location = get_ip_location(ip, api_key)
    print(location)
