import sys
import os

from . import BrowserName

LOCATIONS = {
    BrowserName.CHROME: {
        'linux': ['/usr/bin/google-chrome-stable'],
        'windows': ['C:\\Program Files (x86)\\Google\\Chrome\\Application\\chrome.exe'], # Not tested
        'macos': ['/Applications/Google Chrome.app/Contents/MacOS/Google Chrome'] # Not tested
    },
    BrowserName.CHROMIUM: {
        'linux': ['/usr/bin/chromium', '/usr/bin/chromium-browser'],
        'windows': ['C:\\Program Files (x86)\\Chromium\\Application\\chrome.exe'], # Not tested
        'macos': ['/Applications/Chromium.app/Contents/MacOS/Chromium'] # Not tested
    },
    BrowserName.BRAVE: {
        'linux': ['/usr/bin/brave', '/usr/bin/brave-browser'],
        'windows': ['C:\\Program Files (x86)\\BraveSoftware\\Brave-Browser\\Application\\brave.exe'], # Not tested
        'macos': ['/Applications/Brave Browser.app/Contents/MacOS/Brave Browser'] # Not tested
    },
    BrowserName.EDGE: {
        'linux': ['/usr/bin/microsoft-edge-stable'],
        'windows': ['C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe'], # Not tested
        'macos': ['/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge'] # Not tested
    },
    BrowserName.FIREFOX: {
        'linux': ['/usr/bin/firefox'],
        'windows': ['C:\\Program Files\\Mozilla Firefox\\firefox.exe'], # Not tested
        'macos': ['/Applications/Firefox.app/Contents/MacOS/firefox'] # Not tested
    },
    BrowserName.OPERA: {
        'linux': ['/usr/bin/opera'],
        'windows': ['C:\\Program Files\\Opera\\launcher.exe'], # Not tested
        'macos': ['/Applications/Opera.app/Contents/MacOS/Opera'] # Not tested
    },
    BrowserName.VIVALDI: {
        'linux': ['/usr/bin/vivaldi-stable'],
        'windows': ['C:\\Program Files (x86)\\Vivaldi\\Application\\vivaldi.exe'], # Not tested
        'macos': ['/Applications/Vivaldi.app/Contents/MacOS/Vivaldi'] # Not tested
    }
}

class BinaryLocation:
    def __init__(self):
        if sys.platform == 'darwin':
            self.__os = 'macos'
        elif sys.platform.startswith('linux') or 'bsd' in sys.platform.lower():
            self.__os = 'linux'
        elif sys.platform == "win32":
            self.__os = 'windows'
        else:
            raise ValueError('unsupported os')
    
    def get(self, browser:str) -> str:
        for i in LOCATIONS[browser][self.__os]:
            if os.path.exists(i):
                return i
