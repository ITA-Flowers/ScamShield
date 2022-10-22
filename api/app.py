from flask import Flask, jsonify, request

from scam_detector import detector

app = Flask(__name__)

ENDPOINT = '/api/url'
RESPONSE_OK = {"domain" : "\0", "phishing_estimate" : "\0"}
RESPONSE_ERROR = {"error" : "0"}

@app.route(ENDPOINT, methods=['POST'])
def post_url():
    try:
        url = request.json.get('url').strip()

        resp = RESPONSE_OK
        resp["domain"] = url
        resp["phishing_estimate"] = detector.estimate_score(url)
        
        return jsonify(resp), 200
    
    except Exception as why:
        return jsonify(RESPONSE_ERROR), 400
