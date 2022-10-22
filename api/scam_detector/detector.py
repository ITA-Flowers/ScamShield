from random import random
import urllib.request
from bs4 import BeautifulSoup

def get_html_dom(url : str):
    return urllib.request.urlopen(url).read()


def estimate_score(url : str):
    score = 0 # range(0, 100); where (0 -> valid) and (100 -> scam)
    
    content = get_html_dom(url)
    # print(content)
    # print(50 * '-')
    
    soup = BeautifulSoup(content, 'html.parser')
    
    tags_a = soup.find_all('a')
    for tag in tags_a:
        print(30 * '-')
        print(tag)
        
    print(60 * '-', end='\n\n')
    
    score = int(round((random() * 100), 0))
    
    return str(score)