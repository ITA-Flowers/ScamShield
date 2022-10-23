from bs4 import BeautifulSoup
import urllib.request
import bcrypt
import re


def _text_download(url : str):
    html = urllib.request.urlopen(url).read()
    soup = BeautifulSoup(html, features="html.parser")

    for script in soup(["script"]):
        script.extract()

    text = soup.get_text()
    lines = (line.strip() for line in text.splitlines())
    chunks = (phrase.strip() for line in lines for phrase in line.split("  "))
    text = '\n'.join(chunk for chunk in chunks if chunk)
    return text

def _get_offer_id(text, first, last):
    try:
        start = text.index(first) + len(first)
        end = text.index(last, start)
        return text[start:end]
    except ValueError:
        return ""


def _service_allegro(url : str): 
    product_code = str(url[-11:])
    final_link = "https://allegro.pl/oferta/" + product_code
    
    to_check_safe_bytes = urllib.request.urlopen(final_link).read()    
    to_check_insure_bytes = urllib.request.urlopen(url).read()

    salt = bcrypt.gensalt()
    hash_safe = bcrypt.hashpw(to_check_safe_bytes, salt)
    hash_insure = bcrypt.hashpw(to_check_insure_bytes,salt)
    
    if hash_insure.__eq__(hash_safe):
        print(f'\tOFFER [{product_code}] EXISTS')
        return True
    else:
        print(f'\tOFFER [{product_code}] DOES NOT EXISTS')
        return False

def _service_olx(url : str):
    page_text = _text_download(url)
    offer_id=_get_offer_id(page_text, "ID:", "ZgłośRozmowy").strip()

    real_olx = "https://www.olx.pl/d/oferty/q-" + offer_id

    real_olx_content = _text_download(real_olx)

    real_offer_if = int(_get_offer_id(real_olx_content,"Znaleźliśmy", "ogłoszenie").strip())

    if real_offer_if:
        print(f'\tOFFER [{offer_id}] EXISTS')
        return True
    else:
        print(f'\tOFFER [{offer_id}] DOES NOT EXISTS')
        return False

def _service_vinted(url : str):
    html_dom_text = urllib.request.urlopen(url).read().decode('utf-8')

    to_check = _get_offer_id(html_dom_text, "URL:", " </li>")

    regex="www.vinted.pl/"
    match = re.find(regex, to_check)
    
    if match:
        print('\tOFFER IS VALID')
        return True
    else:
        print('\tOFFER IS NOT VALID')
        return False

def _service_ebay(url : str):
    try:
        offer_id = _get_offer_id(_text_download(url), "Nr przedmiotu eBay:", "Ostatnia aktualizacja").strip()
        real_Ebay = "https://www.ebay.pl/itm/" + offer_id

        to_compare_real = _text_download(real_Ebay)
        to_compare_potencial_fake = _text_download(url)
        if to_compare_real.__eq__(to_compare_potencial_fake):
            print(f'\tOFFER [{offer_id}] EXISTS')
            return True
        else:
            print(f'\tOFFER [{offer_id}] DOES NOT EXISTS!')
            return False
    except ValueError as why:
        raise why


def check_offer(url : str, index : int):
    try:
        if index == 0:
            return _service_allegro(url)
        elif index == 1:
            return _service_olx(url)
        elif index == 2:
            return _service_vinted(url)
        elif index == 3:
            return _service_ebay(url)
    except Exception as why:
        raise why

SERVICES_REGEX =    [ 
                        'allegro.pl/oferta/',
                        'olx.pl/d/oferta/',
                        'vinted.pl/',
                        'ebay.pl/itm/'      
                    ]