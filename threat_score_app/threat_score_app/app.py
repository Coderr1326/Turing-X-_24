from flask import Flask, request, jsonify, render_template
import requests
import base64
from config import ISMALICIOUS_API_KEY, ISMALICIOUS_API_SECRET

app = Flask(__name__)

def get_ismalicious_data(ip):
    """Query isMalicious.com API and return raw response"""
    url = "https://ismalicious.com/api/check/reputation"
    
    credentials = f"{ISMALICIOUS_API_KEY}:{ISMALICIOUS_API_SECRET}"
    encoded_credentials = base64.b64encode(credentials.encode()).decode()
    
    headers = {
        "X-API-KEY": encoded_credentials,
        "Accept": "application/json",
        "Content-Type": "application/json"
    }
    
    params = {"query": ip}
    
    try:
        response = requests.get(url, headers=headers, params=params, timeout=10)
        
        if response.status_code == 200:
            return response.json()
        else:
            return {
                'error': True,
                'status_code': response.status_code,
                'message': response.text
            }
    except Exception as e:
        return {'error': True, 'message': str(e)}

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/check/<ip>', methods=['GET'])
def check_ip(ip):
    result = get_ismalicious_data(ip)
    return jsonify(result)

@app.route('/check', methods=['POST'])
def check_ip_post():
    data = request.get_json()
    ip = data.get('ip')
    
    if not ip:
        return jsonify({'error': 'IP address required'}), 400
    
    result = get_ismalicious_data(ip)
    return jsonify(result)

if __name__ == '__main__':
    app.run(debug=True)
