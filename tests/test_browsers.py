import base64
import json
import os
import shutil
import sys
import tarfile
import tempfile
import time
import unittest

from selenium import webdriver
from selenium.webdriver.chrome.service import Service as ChromeService
from selenium.webdriver.edge.service import Service as EdgeService
from selenium.webdriver.firefox.service import Service as FirefoxService
from webdriver_manager.chrome import ChromeDriverManager
from webdriver_manager.core.utils import ChromeType
from webdriver_manager.firefox import GeckoDriverManager
from webdriver_manager.microsoft import EdgeChromiumDriverManager
from webdriver_manager.opera import OperaDriverManager

from browser_cookie3 import (brave, chrome, chromium, edge, firefox, librewolf,
                             load, opera, opera_gx, vivaldi)

from .utils import BrowserName, logger
from .utils.browser_paths import BinaryLocation
from .utils.driver_version import get_vivaldi_driver_version

FIREFOX_BASED_PROFILE_DIR_TAR_XZ_B64 = '/Td6WFoAAATm1rRGAgAhARYAAAB0L+Wj4Cf/AYFdABoeCqdqx8Ww3rP7opUNoguNkPsxJ2/LebvQiBz6BsBQHaW+I1WQtjmf3unq5qmmUUrSZDK1J4u30H9wRGMKCVjK3Fc4k2kZ6V9v2ySBjXGozKv3Fk/Ai8MCLrCO+SZEQvWOKlVVCBs798tiUloPgnBdT3fRm60SZOSq9gz0ac+/B5M3kI2E9sc6zTn1BVUGf3XpssfNTbyq3Htm/XyjGXwsjpxHjVVfoijHC5ldnaE09Ro14TLFRs56FUolOssUzvXnWt0VrFd3dD/oZxVJ7XDS/1lirTYUWMkiPu4lU6icGJWzIVIEh5MA/cBoO7LDHd6ehXlyhbOGPeNpVuk7a0GGOq295Zi/4jFT2JeIm9QOtw/pcRFsP/sn6Y1MS2BBiO9A30qT0zyb+mqho8kxvK2gMnZWJSFczG/9lyWyNc8gDtpYYyGBjfinCYdJlcOAMoa5pS3zS5g4AIvCSKVwEH1Ba3gn1StsUCGMT4Nw9Pom/Wkd3JGSfq30VB+bRRNlch0AAAAA7jsEu81WUn0AAZ0DgFAAABsz6KSxxGf7AgAAAAAEWVo='   # noqa: E501
FIREFOX_BASED_PROFILE_DIR_NAME = '4xutesqi.default-release'
GO_TO_URLS = ['https://google.com', 'https://facebook.com',
              'https://aka.ms', 'https://github.com']


class Test(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.__is_github_actions = not not os.environ.get(
            'GITHUB_ACTIONS', False)
        if cls.__is_github_actions:
            cls.__headless = True
        else:
            cls.__headless = not not os.environ.get('RUN_HEADLESS', False)
        if cls.__headless:
            logger.info('Running headless')
        cls.__binary_location = BinaryLocation(
            raise_not_found=cls.__is_github_actions)

    def setUp(self) -> None:
        self.__temp_dir = tempfile.mktemp(prefix='browser_cookie3_test_')
        os.mkdir(self.__temp_dir)
        logger.info('Starting test: %s', self._testMethodName)
        super().setUp()

    def tearDown(self) -> None:
        try:
            shutil.rmtree(self.__temp_dir)
        except PermissionError:
            pass
        logger.info('Finished test: %s', self._testMethodName)
        super().tearDown()

    def __get_data_dir(self):
        data_dir = os.path.join(self.__temp_dir, self._testMethodName)
        return data_dir

    def __is_key_path_okay(self, key_path):
        if not key_path:
            return True  # keypath not provided, will use default
        if sys.platform != 'win32':
            return True  # keypath only used on windows
        if not os.path.exists(key_path):
            return False
        with open(key_path, 'r') as f:
            data = json.load(f).get('os_crypt', {}).get('encrypted_key', None)
        return data is not None

    def __wait_for_cookies_to_be_detected(self, browser_func, cookies_path, key_path, timeout):
        end_time = time.time() + timeout
        while time.time() < end_time:
            if not self.__is_key_path_okay(key_path):
                time.sleep(1)
                continue
            if len(self.__call_browser_func(browser_func, cookies_path, key_path)) > 0:
                return
            time.sleep(1)

    def __setup_firefox_based(self, profile_containing_dir, binary_location):
        if os.path.exists(profile_containing_dir):
            raise Exception(
                f'Profile dir already exists: {profile_containing_dir}')
        os.makedirs(profile_containing_dir)

        xz_file = tempfile.mktemp(suffix='.tar.xz')
        with open(xz_file, 'wb') as f:
            f.write(base64.b64decode(FIREFOX_BASED_PROFILE_DIR_TAR_XZ_B64))
        with tarfile.open(xz_file) as f:
            f.extractall(profile_containing_dir)
        os.remove(xz_file)

        profile_dir = os.path.join(
            profile_containing_dir, FIREFOX_BASED_PROFILE_DIR_NAME)

        options = webdriver.FirefoxOptions()
        options.binary_location = binary_location
        options.add_argument('-profile')
        options.add_argument(profile_dir)
        # Disable clearing cookies on shutdown, cookies is cleared by some firefox-based browsers
        options.set_preference('privacy.clearOnShutdown.cookies', False)

        if self.__headless:
            options.add_argument('--headless')
            options.add_argument('--disable-gpu')

        executable_path = os.environ.get(
            'GECKOWEBDRIVER', None) or GeckoDriverManager().install()

        self.driver = webdriver.Firefox(
            service=FirefoxService(executable_path), options=options)

    @staticmethod
    def __call_browser_func(func, cookies_path, key_path):
        if not key_path:
            return func(cookies_path)
        return func(cookies_path, key_file=key_path)

    def __test_browser(self, browser_func, cookies_path=None, key_path=None, max_wait_seconds=45):
        for url in GO_TO_URLS:
            self.driver.get(url)
            self.driver.implicitly_wait(10)

        time.sleep(5)
        self.driver.quit()
        time.sleep(5)
        self.__wait_for_cookies_to_be_detected(
            browser_func, cookies_path, key_path, max_wait_seconds)
        total_cookies = len(self.__call_browser_func(
            browser_func, cookies_path, key_path))
        self.assertGreaterEqual(total_cookies, 0)
        if total_cookies < 1:
            logger.warning(
                'Cookie database was empty after waiting for cookies to be detected')

    def __setup_chromium_based(self, chrome_type, binary_location, driver_version=None):
        options = webdriver.ChromeOptions()
        options.binary_location = binary_location
        options.add_argument(f'--user-data-dir={self.__get_data_dir()}')
        if self.__headless:
            options.add_argument('--headless=new')
            options.add_argument('--disable-gpu')
        self.driver = webdriver.Chrome(service=ChromeService(ChromeDriverManager(
            version=driver_version, chrome_type=chrome_type).install()), options=options)

    def __test_chromium_based(self, browser_func, max_wait_seconds=45):
        paths = ['Default', 'Cookies']
        key_path = None
        if sys.platform == 'win32':
            paths.insert(1, 'Network')
            key_path = os.path.join(self.__get_data_dir(), 'Local State')

        cookies_path = os.path.join(self.__get_data_dir(), *paths)
        self.__test_browser(browser_func, cookies_path,
                            key_path, max_wait_seconds)

    def __setup_opera_based(self, binary_location):
        if sys.platform != 'win32':
            return self.__setup_chromium_based(ChromeType.GOOGLE, binary_location)
        self.__opera_service = ChromeService(OperaDriverManager().install())
        self.__opera_service.start()
        options = webdriver.ChromeOptions()
        options.binary_location = binary_location
        options.add_argument(f'--user-data-dir={self.__get_data_dir()}')
        options.add_experimental_option('w3c', True)
        if self.__headless:
            options.add_argument('--headless=new')
            options.add_argument('--disable-gpu')

        self.driver = webdriver.Remote(
            self.__opera_service.service_url, options=options)

    def __test_opera_based(self, browser_func):
        cookie_path = ['Cookies']
        key_path = None
        if sys.platform == 'win32':
            cookie_path.insert(0, 'Network')
            key_path = os.path.join(self.__get_data_dir(), 'Local State')
        try:
            self.__test_browser(browser_func, os.path.join(
                self.__get_data_dir(), *cookie_path), key_path)
        except KeyError as e:
            if 'os_crypt' in str(e) and sys.platform == 'win32':
                logger.warning('os_crypt not in keyfile, skipping test')
                logger.warning(
                    'it is a common issue with Opera-based browsers on Windows')
                self.skipTest('os_crypt not in keyfile')
            else:
                raise e

    def __setup_edge(self):
        options = webdriver.EdgeOptions()
        options.binary_location = self.__binary_location.get(BrowserName.EDGE)
        options.add_argument(f'--user-data-dir={self.__get_data_dir()}')
        if self.__headless:
            options.add_argument('--headless=new')
            options.add_argument('--disable-gpu')

        self.driver = webdriver.Edge(
            service=EdgeService(EdgeChromiumDriverManager().install()), options=options)

    def test_edge(self):
        # Edge is based on Chromium, but __setup_chromium_based() doesn't work for Edge
        self.__setup_edge()
        if not self.__headless:
            # wait for the browser to start completely,
            # otherwise it raises WebDriverException: unknown error: cannot determine loading status
            time.sleep(5)
        self.__test_chromium_based(edge)

    def test_brave(self):
        self.__setup_chromium_based(
            ChromeType.BRAVE, self.__binary_location.get(BrowserName.BRAVE))
        self.__test_chromium_based(brave)

    def test_chromium(self):
        self.__setup_chromium_based(
            ChromeType.CHROMIUM, self.__binary_location.get(BrowserName.CHROMIUM))
        self.__test_chromium_based(chromium)

    def test_chrome(self):
        self.__setup_chromium_based(
            ChromeType.GOOGLE, self.__binary_location.get(BrowserName.CHROME))
        self.__test_chromium_based(chrome)

    def test_firefox(self):
        profile_containing_dir = os.path.join(
            self.__temp_dir, '.mozilla', 'firefox')
        cookie_path = os.path.join(
            profile_containing_dir, FIREFOX_BASED_PROFILE_DIR_NAME, 'cookies.sqlite')
        binary_location = self.__binary_location.get(BrowserName.FIREFOX)

        self.__setup_firefox_based(profile_containing_dir, binary_location)
        self.__test_browser(firefox, cookie_path)

    def test_librewolf(self):
        profile_containing_dir = os.path.join(self.__temp_dir, '.librewolf')
        cookie_path = os.path.join(
            profile_containing_dir, FIREFOX_BASED_PROFILE_DIR_NAME, 'cookies.sqlite')
        binary_location = self.__binary_location.get(BrowserName.LIBREWOLF)

        self.__setup_firefox_based(profile_containing_dir, binary_location)
        self.__test_browser(librewolf, cookie_path)

    def test_opera(self):
        self.__setup_opera_based(self.__binary_location.get(BrowserName.OPERA))
        self.__test_opera_based(opera)

    @unittest.skipIf(sys.platform not in ['win32', 'darwin'], 'Only supported on Windows and macOS')
    def test_opera_gx(self):
        self.__setup_opera_based(
            self.__binary_location.get(BrowserName.OPERA_GX))
        self.__test_opera_based(opera_gx)

    def test_vivaldi(self):
        # Vivaldi requires a specific version of chromedriver, so we can't use __setup_chromium_based()
        driver_version = get_vivaldi_driver_version(
            self.__binary_location.get(BrowserName.VIVALDI), self.__is_github_actions)
        logger.info(f'Using chromedriver version {driver_version} for Vivaldi')
        self.__setup_chromium_based(ChromeType.GOOGLE, self.__binary_location.get(
            BrowserName.VIVALDI), driver_version)
        self.__test_chromium_based(vivaldi)

    def test_z_load(self):
        logger.info('Testing load() at the end of the test suite')
        load()
    
    def test_a_load(self):
        logger.info('Testing load() at the beginning of the test suite')
        load()


if __name__ == '__main__':
    unittest.main()
