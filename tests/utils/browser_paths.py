import sys
import os

from . import BrowserName, logger

def get_username():
    try:
        return os.getlogin()
    except OSError:
        return os.environ.get('USERNAME') or os.environ.get('USER') or ''

BIN_LOCATIONS = {
    BrowserName.CHROME: {
        'linux': ['/usr/bin/google-chrome-stable'],
        'windows': [
            r'C:\Program Files (x86)\Google\Chrome\Application\chrome.exe',
            r'C:\Program Files\Google\Chrome\Application\chrome.exe'
        ],
        'macos': ['/Applications/Google Chrome.app/Contents/MacOS/Google Chrome'] # Not tested
    },
    BrowserName.CHROMIUM: {
        'linux': ['/usr/bin/chromium', '/usr/bin/chromium-browser'],
        'windows': [
            r'C:\Program Files (x86)\Chromium\Application\chrome.exe',
            r'C:\Program Files\Chromium\Application\chrome.exe'
        ],
        'macos': ['/Applications/Chromium.app/Contents/MacOS/Chromium'] # Not tested
    },
    BrowserName.BRAVE: {
        'linux': ['/usr/bin/brave', '/usr/bin/brave-browser'],
        'windows': [
            r'C:\Program Files (x86)\BraveSoftware\Brave-Browser\Application\brave.exe',
            r'C:\Program Files\BraveSoftware\Brave-Browser\Application\brave.exe',
            fr'C:\Users\{get_username()}\AppData\Local\BraveSoftware\Brave-Browser\Application\brave.exe'
        ],
        'macos': ['/Applications/Brave Browser.app/Contents/MacOS/Brave Browser'] # Not tested
    },
    BrowserName.EDGE: {
        'linux': ['/usr/bin/microsoft-edge-stable'],
        'windows': [
            r'C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe',
            r'C:\Program Files\Microsoft\Edge\Application\msedge.exe'
        ],
        'macos': ['/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge'] # Not tested
    },
    BrowserName.FIREFOX: {
        'linux': ['/usr/bin/firefox'],
        'windows': [
            r'C:\Program Files (x86)\Mozilla Firefox\firefox.exe',
            r'C:\Program Files\Mozilla Firefox\firefox.exe'
        ],
        'macos': ['/Applications/Firefox.app/Contents/MacOS/firefox'] # Not tested
    },
    BrowserName.OPERA: {
        'linux': ['/usr/bin/opera'],
        'windows': [
            r'C:\Program Files (x86)\Opera\opera.exe',
            r'C:\Program Files\Opera\opera.exe',
            fr'C:\Users\{get_username()}\AppData\Local\Programs\Opera\opera.exe'
        ],
        'macos': ['/Applications/Opera.app/Contents/MacOS/Opera'] # Not tested
    },
    BrowserName.OPERA_GX: {
        'linux': [],
        'windows': [
            r'C:\Program Files (x86)\Opera GX\opera.exe',
            r'C:\Program Files\Opera GX\opera.exe',
            fr'C:\Users\{get_username()}\AppData\Local\Programs\Opera GX\opera.exe'
        ],
        'macos': ['/Applications/Opera GX.app/Contents/MacOS/Opera GX'] # Not tested
    },
    BrowserName.VIVALDI: {
        'linux': ['/usr/bin/vivaldi-stable'],
        'windows': [
            r'C:\Program Files (x86)\Vivaldi\Application\vivaldi.exe',
            r'C:\Program Files\Vivaldi\Application\vivaldi.exe',
            fr'C:\Users\{get_username()}\AppData\Local\Vivaldi\Application\vivaldi.exe'
        ],
        'macos': ['/Applications/Vivaldi.app/Contents/MacOS/Vivaldi'] # Not tested
    }
}

class BinaryLocation:
    def __init__(self, raise_not_found=False):
        self.__raise_not_found = raise_not_found
        if sys.platform == 'darwin':
            self.__os = 'macos'
        elif sys.platform.startswith('linux') or 'bsd' in sys.platform.lower():
            self.__os = 'linux'
        elif sys.platform == "win32":
            self.__os = 'windows'
        else:
            raise ValueError('unsupported os')
    
    def get(self, browser:str) -> str:
        for i in BIN_LOCATIONS[browser][self.__os]:
            if os.path.exists(i):
                logger.info(f'found {browser} binary at: {i}')
                return i
        if self.__raise_not_found:
            raise FileNotFoundError('browser not found')
        logger.warning(f'could not find {browser} binary')
