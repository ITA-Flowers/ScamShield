from scam_detector.config import bcolors

# -- Error log
def _on_error(error):
    print(f'{bcolors.RED}ERROR: {error}{bcolors.ENDC}')

# -- Debug log
def _on_debug(msg):
    print(f'{bcolors.BLUE}{msg}{bcolors.ENDC}')

# -- Result log
def _on_result(result):
    print(f'{bcolors.YELLOW}{result}{bcolors.ENDC}')

# -- Request log    
def _on_request(request):
    print(f'{bcolors.PURPLE}REQUEST:')
    for section in request:
        print(f'{section} : {request[section]}')
    print(bcolors.ENDC)

# -- Response log
def _on_response(response):
    print(f'{bcolors.CYAN}RESPONSE:')
    for section in response:
        print(f'{section} : {response[section]}')
    print(bcolors.ENDC)