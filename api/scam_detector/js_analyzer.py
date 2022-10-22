from bs4 import BeautifulSoup
import urllib.request
import urllib.error
import re

from scam_detector.logs import _on_error
from scam_detector.config import bcolors


def _get_scripts(html_dom):
    soup = BeautifulSoup(html_dom, 'html.parser')
        
    scripts_elements = soup.find_all('script')
    
    scripts_texts = []
    sources = []
    
    for element in scripts_elements:
        try:
            src = element["src"]
            sources.append(src)
        except KeyError as why:
            scripts_texts.append(element.text)
    
    downloaded = 0
    if len(sources) > 0:
        for source in sources:
            m = re.match(r"^http.*", source)
            if not m:
                source = 'http:' + source
            try:
                scripts_texts.append(urllib.request.urlopen(source).read().decode('utf-8'))
                downloaded += 1
            except urllib.error.URLError:
                print(f'\t{bcolors.RED}Cannot download script: {source}{bcolors.ENDC}')
        
    print(f'\tDETECTED SCRIPTS:       {len(scripts_elements)}')
    print(f'\tSOURCED SCRIPTS:        {len(sources)}')
    print(f'\tDOWNLOADED SCRIPTS:     {downloaded}')
    print(f'\tCOLLECTED SCRIPTS:      {len(scripts_texts)}')
    
    return scripts_texts, len(scripts_elements)


def _analyze_script(script : str):
    regex_1 = r"unescape"
    m1 = re.findall(regex_1, script)
    return len(m1)


def analyze(html_dom):
    result = int(0)
    
    scripts, detected_scripts_amount = _get_scripts(html_dom)
    
    matches = 0
    for script in scripts:
        matches += _analyze_script(script)
    
    print(f'\tSUSPICIOUS METHODS:\t{matches}')
    
    if matches > (detected_scripts_amount / 3):
        result = 15
    else:
        result = 0
        
    return result