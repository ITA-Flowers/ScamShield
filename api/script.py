import scam_detector.detector as detector
from scam_detector.logs import _on_error
from scam_detector.config import bcolors

url_twojamode = "http://twojamoda.site/"
url_novii = "https://novvi.pl/"

RESPONSE_OK = {"domain" : "\0", "phishing_estimate" : "\0"}
RESPONSE_ERROR = {"error" : "0"}

def check(url : str):
    try:                
        resp = RESPONSE_OK
        resp["domain"] = url
        resp["phishing_estimate"] = detector.estimate_score(url)
        
        print('\n' + 50 * '-', end='\n\n')
        
        return resp
    
    except ValueError as why:
        _on_error(why)
        resp = RESPONSE_ERROR
        return None
        
def main():
    results = ['0', '0']
    errors = ['error', 'error', 'error']
    
    with open('test_domains.txt') as f:
        domains = f.readlines()
        
    for domain in domains:
        url = domain[:-1]
        input(f'Next [{url}]')
        response = check(url)
        if response is not None:
            result = f'{response["phishing_estimate"]} : {response["domain"]}'
            results.append(f'{result}\n')
            print(f'{bcolors.GREEN}RESULT: {result}{bcolors.ENDC}')
        else:
            errors.append(f'ERROR : {url}\n')
            print(f'{bcolors.RED}RESULT: {response["phishing_estimate"]} : {response["domain"]}{bcolors.ENDC}')
            

    with open('results.txt', 'w') as f:
        f.writelines(results)
        
    with open('errors.txt', 'w') as f:
        f.writelines(errors)

if __name__ == '__main__':
    main()