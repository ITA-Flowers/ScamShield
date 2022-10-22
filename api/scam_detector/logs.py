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