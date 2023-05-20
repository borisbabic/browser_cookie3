import requests

from .user_agent import UAGetter

CHROME_DRIVER_INFO_JSON_URL = 'https://pypi.org/pypi/chromedriver-py/json'

class ChromeDriverVersion:
    def __init__(self, ua_string:str) -> None:
        self.__ua_string = ua_string

    def __get_chrome_major_version(self) -> str:
        try:
            return self.__ua_string.split('Chrome/')[1].split('.')[0]
        except:
            raise ValueError('Not a Chrome user agent string')
    
    def __get_matching_chrome_driver_version(self) -> str:
        releases = requests.get(CHROME_DRIVER_INFO_JSON_URL).json()['releases']
        major_version = self.__get_chrome_major_version()
        major_version_matches = []
        for k in releases.keys():
            if k.startswith(major_version):
                major_version_matches.append(k)
        return max(major_version_matches)

    def get(self):
        return self.__get_matching_chrome_driver_version()

def get_driver_version_from_chromium_based_binary(binary_location:str) -> str:
    return ChromeDriverVersion(UAGetter(binary_location, UAGetter.HEADLESS_NEW).get()).get()
