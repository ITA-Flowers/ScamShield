import requests
import ssl, socket

from config import SCAM_ADVISER_API_KEY
from logs import (_on_debug, _on_result, _on_error)
import js_analyzer

# -- Check if secured
def scan_protocol(protocol : str):
    _on_debug('SCAN: Protocol')
    result = int()
    
    if protocol == 'http':
        result = 5
    elif protocol == 'https':
        result = 0
    else:
        result = 10
        
    _on_result(f'\tRESULT: {result}')
    return result

# -- Scam Adviser API call
def scan_scam_adviser(url : str):
    _on_debug('SCAN: Scam Adviser')
    result = int()
    api_key = SCAM_ADVISER_API_KEY
    
    try:
        if api_key is None:
            raise ValueError('Scam Adviser API Key is not defined')
        endpoint = "https://api.scamadviser.cloud/v2/trust/single?apikey=" + api_key + "&domain=" + url
    
        response = requests.request("GET", endpoint)

        if response.ok:
            score = int(response.json().get('score'))
            result = 100 - score
        else:
            result = 0
            
        _on_result(f'\tRESULT: {result}')
        return result
    
    except Exception as why:
        _on_error(why)
        _on_result(f'\tRESULT: {result}')
        return 0
 
# -- Check SSL Cert
def scan_ssl(domain : str):
    
    _on_debug('SCAN: SSL')
    
    result = int()
    
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=domain) as s:
            s.connect((domain, 443))
            cert = s.getpeercert()

        subject = dict(x[0] for x in cert['subject'])
        issuer = dict(x[0] for x in cert['issuer'])
        
        issued_to = subject['commonName']
        issued_by = issuer['commonName']
        
        # TODO: Analyze [issued_to] and [issued_by]
        result = 0
        # ...
        
        _on_result(f'\tRESULT: {result}')
        return result
        
    except Exception as why:
        _on_error(why)
        _on_result(f'\tRESULT: {0}')
        return 0

# -- Analyze JavaScript Code
def scan_js(url : str):
    _on_debug('SCAN: JS')
    result = int()
    
    result = js_analyzer.analyze(url)
    
    _on_result(f'\tRESULT: {result}')
    return result