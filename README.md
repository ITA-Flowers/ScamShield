# ScamShield

<img src="https://raw.githubusercontent.com/ITA-Flowers/ScamShield/master/browser_extension/images/banner_b_f.png">

___

# Install
pip upgrade

    python -m pip install --upgrade pip

download github repo

    git clone https://github.com/ITA-Flowers/ScamShield.git

Change dir to api workdir

    cd ./ScamShield/api 

install virtual enviroment python module

    python -m pip install virtualenv

create virtual enviroment for API

    python -m venv ./.venv

activate venv

    ./.venv/Scripts/activate

install required modules
    
    python -m pip install -r ./requirements

run API
    
    flask run

default server host and port:

**HOST**: *0.0.0.0*

**PORT**: *8080*

**OPTIONAL** you could set server host address and port ``` by:
    
    flask run --host '0.0.0.0' --port 8080

**ALTERNATIVE** run API

    python ./app.py

___

# Endpoint

### **Adres** 
```
/api/url
```

### **Request Body**
``` json
{
    "url" : "https://www.example.com/"
}

```

### **Response OK**
``` json
{
    "domain" : "https://www.example.com/",
    "phishing_estimate" : "7"
}

```

### **Response Bad Request**
``` json
{
    "error" : "0"
}

```

___

# Algorytmy skanowania

## Protokół
W przypadku używania http istnieje zwiększone ryzyko, zatem zwiększamy punktacje phishingową.

## Wiek strony

Sprawdzamy wiek strony, w celu wyłapania młodych stron. Istnieje duże ryzyko, że są stronami phishingowymi.

## SSL

SSL strony jest pobierany i porównywany z rankingiem SSL z których pochodzi najwięcej stron phishingowych.

SSL jest również sprawdzane z blacklist’ą przydzielonych certyfikatów.

## JavaScript

Żadna uczciwa strona nie szyfruje swoich URL. Zatem w poszukiwaniu stron oszustów wyszukujemy w kodzie javascript stron podejrzanych, użyć przestarzałych metod szyfrowania np. unescaped().

## Porównanie HTML

Pobieramy ze strony jej tytuł, algorytm przy jego pomocy wyszukuje stronę html którą uznaje za oryginalną. Następnie szyfrujemy zawartości stron i porównujemy oba wyniki. W sytuacji w której nie ma tytułu, od razu strona trafia do zwiększonego ryzyka, ponieważ przeglądarki wykorzystują tytuły do pozycjonowania stron.

## Serwisy sklepowe

Portale aukcyjne są sprawdzane pod kątem numerów ogłoszeń dzięki czemu możemy się dowiedzieć czy akcje są fałszywe.

___

# Testowanie

## [Zestaw testowy](https://github.com/ITA-Flowers/ScamShield/blob/master/api/test_domains.txt)

## [Skrypt](https://github.com/ITA-Flowers/ScamShield/blob/master/api/script.py)

## [Wyniki](https://github.com/ITA-Flowers/ScamShield/blob/master/api/results.txt)

## [Błędy](https://github.com/ITA-Flowers/ScamShield/blob/master/api/errors.txt)