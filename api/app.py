from flask import Flask, jsonify, request

from scam_detector import detector
from scam_detector.logs import (_on_request, _on_response)

app = Flask(__name__)

ENDPOINT = '/api/url'
RESPONSE_OK = {"domain" : "\0", "phishing_estimate" : "\0"}
RESPONSE_ERROR = {"error" : "0"}

@app.route(ENDPOINT, methods=['POST'])
def post_url():
    
    _on_request(request.json)
    
    try:
        url = request.json.get('url').strip()

        resp = RESPONSE_OK
        resp["domain"] = url
        resp["phishing_estimate"] = detector.estimate_score(url)
        status_code = 200
    
    except Exception as why:
        resp = RESPONSE_ERROR
        status_code = 400
    finally:
        _on_response(resp)
        response = jsonify(resp)
        return response, status_code

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080)