import re
import urllib.request

import scam_detector.scans as scans
from scam_detector.logs import _on_error


def _recognize_url(url : str):
    address =   {   
                    'protocol' : None, 
                    'domain' : None, 
                    'theme' : None, 
                    'tail' : None, 
                    'isWWW' : False
                }

    result = re.match(r"^(?P<protocol>.*?):/*(www\.)*(?P<domain>.*?)/", url)
    if result:
        
        address['protocol'] = result.group('protocol')
        address['domain'] = result.group('domain')
        
        if not ((address['protocol'].__eq__('http')) or (address['protocol'].__eq__('https'))):
            ind = url.index(address['domain'])
            address['domain'] = url[ind::]
            return address
            
        address['isWWW'] = True
        theme_ind = url.index(address['domain']) + len(address['domain'])
        theme_url = url[theme_ind::]
        
        if len(theme_url) > 1:
            if '?' in theme_url:
                address['theme'] = theme_url[:theme_url.index('?')]
                address['tail'] = theme_url[theme_url.index('?')+1::]
            else:
                address['theme'] = theme_url
    else:
        raise ValueError('REGEX Error')
    
    return address        
    

def estimate_score(url : str):
    # -- Trust Score (0 - 100) : 0-legit, 100-scam
    score = int()

    try:
        address = _recognize_url(url)
    except ValueError as why:
        raise why
    
    print('ADDRESS:')
    print(f'\tPROTOCOL: {address["protocol"]}')
    print(f'\tDOMAIN:   {address["domain"]}')
    print(f'\tTHEME:    {address["theme"]}')
    print(f'\tTAIL:     {address["tail"]}')
    print(f'\tisWWW:    {address["isWWW"]}')
    print(50 * '-' + '\n')
    
    if address['isWWW']:
        try:
            html_dom = urllib.request.urlopen(url).read()
        except Exception as why:
            html_dom = None
            _on_error(why)
            
        score += scans.scan_protocol(address['protocol'])
        score += scans.scan_page_age(url)
        score += scans.scan_ssl(address['domain'])
        if html_dom:
            score += scans.scan_js(html_dom)
            score += scans.scan_html_compare(html_dom, address['domain'])
            
        score += scans.scan_shops_service(url)
            
    if score > 100:
        score = 100
    return str(score)
