import re
import sys

import requests

from . import logger
from .user_agent import UAGetter

CHROME_DRIVER_INFO_JSON_URL = 'https://pypi.org/pypi/chromedriver-py/json'
VIVALDI_WEBSITE = 'https://vivaldi.com'


class ChromeDriverVersion:
    def __init__(self, ua_string: str) -> None:
        self.__ua_string = ua_string

    def __get_chrome_major_version(self) -> str:
        try:
            return self.__ua_string.split('Chrome/')[1].split('.')[0]
        except Exception:
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


def get_driver_version_from_chromium_based_binary(binary_location: str) -> str:
    logger.info(
        f'Getting driver version from Chromium based binary: {binary_location}')
    return ChromeDriverVersion(UAGetter(binary_location, UAGetter.HEADLESS_NEW).get()).get()


def get_vivaldi_driver_version_from_web() -> str:
    logger.info('Getting Vivaldi version from web')
    res = requests.get(f'{VIVALDI_WEBSITE}/download/')
    found = re.findall(r'Vivaldi\s(\d+.\d+)<', res.text)
    if len(found) != 1:
        return None

    res = requests.get(
        f'{VIVALDI_WEBSITE}/changelog-vivaldi-browser-{found[0]}/')
    chromium_major = re.findall(r'\[Chromium\][^\d]+(\d+)', res.text)
    if len(chromium_major) != 1:
        return None
    return ChromeDriverVersion(f'Chrome/{chromium_major[0]}').get()


def get_vivaldi_driver_version(binary_location, is_github_actions) -> str:
    if sys.platform == 'win32' and is_github_actions:
        return get_vivaldi_driver_version_from_web()
    return get_driver_version_from_chromium_based_binary(binary_location)
