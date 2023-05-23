import base64
import sys
import unittest
import os
import shutil
import tempfile
import tarfile
import time
import json

from selenium import webdriver
from selenium.webdriver.chrome.service import Service as ChromeService
from selenium.webdriver.edge.service import Service as EdgeService
from selenium.webdriver.firefox.service import Service as FirefoxService

from webdriver_manager.chrome import ChromeDriverManager
from webdriver_manager.firefox import GeckoDriverManager
from webdriver_manager.microsoft import EdgeChromiumDriverManager
from webdriver_manager.opera import OperaDriverManager
from webdriver_manager.core.utils import ChromeType

from .utils.driver_version import get_vivaldi_driver_version
from .utils.browser_paths import BinaryLocation
from .utils import BrowserName, logger

from browser_cookie3 import chrome, chromium, opera, brave, edge, vivaldi, firefox, opera_gx, load

FIREFOX_PROFILE_DIR_TAR_XZ_B64 = '/Td6WFoAAATm1rRGAgAhARYAAAB0L+Wj4Cf/Ab9dADKeCtBB2uo3WZXNf0LmOYhU+/uDA4UuA4WFok+rSGo77xLonlTJRZVUflBOJqwKkKSdaAqhwGEKuBBQPUhhAnLAtEoZDYIZr/+NtA7qmJUYLdsVeR6Wl7WxZbXKiZGGvRIikC0hq43rbn1Yqg9Np1jaN2SAN9nJ+dbdaiRN41M1dNay8kvuJQN82yhVO60WIPevkpqDyk9e6znR/txuyHxu/+CbWOpjVKK0Za4lt3Q4lSoqMjQsyOotQb+PG2xm8gUMIe+oz+95CoHCPsjkgPQwsE9nZ6Va1k1Ao5kgxs7BM5Zc1gJaAeITfxmzI8Z9jmimHExXDoIayhbg+IaENPO40nuioZvaPnRYKU2giDaqKbeMbfgru1OAQqGHJjtHtluCO6g9BddV6w3w2eseL2L/5ftFlv84//BRoqSe60dlPPf6k9FunUY7nE1DrErvms34C8C5ijJy/w6HyQszlbUrUGhcPzlqcWSbx/qVcdynh0RazPq7bnOcSpdRTOKWDNDCo1YWARi5kzCVYhB3nPpFj35fuIWHWfg4JBz6h69RHe7H06SVat4foed/oKNmocM5tuAtFyzqIumE2BbAAAAAYT2+VFTQ6AsAAdsDgFAAAGra6X2xxGf7AgAAAAAEWVo='
FIREFOX_PROFILE_DIR_NAME = '4xutesqi.default-release'
GO_TO_URLS = ['https://google.com', 'https://facebook.com', 'https://aka.ms', 'https://github.com']


class Test(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.__is_github_actions = not not os.environ.get('GITHUB_ACTIONS', False)
        if cls.__is_github_actions:
            cls.__headless = True
        else:
            cls.__headless = not not os.environ.get('RUN_HEADLESS', False)
        if cls.__headless:
            logger.info('Running headless')
        cls.__binary_location = BinaryLocation(raise_not_found=cls.__is_github_actions)
        
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
            return True # keypath not provided, will use default
        if sys.platform != 'win32':
            return True # keypath only used on windows
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

    def __setup_firefox(self):
        mozilla_dir = os.path.join(self.__temp_dir, '.mozilla')
        if os.path.exists(mozilla_dir):
            raise Exception(f'{mozilla_dir} already exists')
        os.mkdir(mozilla_dir)

        xz_file = tempfile.mktemp(suffix='.tar.xz')
        with open(xz_file, 'wb') as f:
            f.write(base64.b64decode(FIREFOX_PROFILE_DIR_TAR_XZ_B64))
        with tarfile.open(xz_file) as f:
            f.extractall(mozilla_dir)
        os.remove(xz_file)
        
        profile_dir = os.path.join(mozilla_dir, 'firefox', FIREFOX_PROFILE_DIR_NAME)

        options = webdriver.FirefoxOptions()
        options.binary_location = self.__binary_location.get(BrowserName.FIREFOX)
        options.add_argument('-profile')
        options.add_argument(profile_dir)
        if self.__headless:
            options.add_argument('--headless')
            options.add_argument('--disable-gpu')
        
        self.driver = webdriver.Firefox(service=FirefoxService(GeckoDriverManager().install()), options=options)
    
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
        self.__wait_for_cookies_to_be_detected(browser_func, cookies_path, key_path, max_wait_seconds)
        total_cookies = len(self.__call_browser_func(browser_func, cookies_path, key_path))
        self.assertGreaterEqual(total_cookies, 0)
        if total_cookies < 1:
            logger.warning('Cookie database was empty after waiting for cookies to be detected')
    
    def __setup_chromium_based(self, chrome_type, binary_location, driver_version=None):
        options = webdriver.ChromeOptions()
        options.binary_location = binary_location
        options.add_argument(f'--user-data-dir={self.__get_data_dir()}')
        if self.__headless:
            options.add_argument('--headless=new')
            options.add_argument('--disable-gpu')
        self.driver = webdriver.Chrome(service=ChromeService(ChromeDriverManager(version=driver_version,chrome_type=chrome_type).install()), options=options)

    def __test_chromium_based(self, browser_func, max_wait_seconds=45):
        paths = ['Default', 'Cookies']
        key_path = None
        if sys.platform == 'win32':
            paths.insert(1, 'Network')
            key_path = os.path.join(self.__get_data_dir(), 'Local State')

        cookies_path = os.path.join(self.__get_data_dir(), *paths)
        self.__test_browser(browser_func, cookies_path, key_path, max_wait_seconds)
    
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
        
        self.driver = webdriver.Remote(self.__opera_service.service_url, options=options)
    
    def __test_opera_based(self, browser_func):
        cookie_path = ['Cookies']
        key_path = None
        if sys.platform == 'win32':
            cookie_path.insert(0, 'Network')
            key_path = os.path.join(self.__get_data_dir(), 'Local State')
        self.__test_browser(browser_func, os.path.join(self.__get_data_dir(), *cookie_path), key_path)
        

    def __setup_edge(self):
        options = webdriver.EdgeOptions()
        options.binary_location = self.__binary_location.get(BrowserName.EDGE)
        options.add_argument(f'--user-data-dir={self.__get_data_dir()}')
        if self.__headless:
            options.add_argument('--headless=new')
            options.add_argument('--disable-gpu')
        self.driver = webdriver.Edge(service=EdgeService(EdgeChromiumDriverManager().install()), options=options)

    def test_edge(self):
        self.__setup_edge() # Edge is based on Chromium, but __setup_chromium_based() doesn't work for Edge
        if not self.__headless:
            time.sleep(5) # wait for the browser to start completely, otherwise it raises WebDriverException: unknown error: cannot determine loading status
        self.__test_chromium_based(edge)

    def test_brave(self):
        self.__setup_chromium_based(ChromeType.BRAVE, self.__binary_location.get(BrowserName.BRAVE))
        self.__test_chromium_based(brave)

    def test_chromium(self):
        self.__setup_chromium_based(ChromeType.CHROMIUM, self.__binary_location.get(BrowserName.CHROMIUM))
        self.__test_chromium_based(chromium)
    
    def test_chrome(self):
        self.__setup_chromium_based(ChromeType.GOOGLE, self.__binary_location.get(BrowserName.CHROME))
        self.__test_chromium_based(chrome)
    
    def test_firefox(self):
        self.__setup_firefox()
        cookie_path = os.path.join(self.__temp_dir, '.mozilla', 'firefox', FIREFOX_PROFILE_DIR_NAME, 'cookies.sqlite')
        self.__test_browser(firefox, cookie_path)
    
    def test_opera(self):
        self.__setup_opera_based(self.__binary_location.get(BrowserName.OPERA))
        self.__test_opera_based(opera)
    
    @unittest.skipIf(sys.platform not in ['win32', 'darwin'], 'Only supported on Windows and macOS')
    def test_opera_gx(self):
        self.__setup_opera_based(self.__binary_location.get(BrowserName.OPERA_GX))
        self.__test_opera_based(opera_gx)
    
    def test_vivaldi(self):
        ## Vivaldi requires a specific version of chromedriver, so we can't use __setup_chromium_based()
        driver_version = get_vivaldi_driver_version(self.__binary_location.get(BrowserName.VIVALDI), self.__is_github_actions)
        logger.info(f'Using chromedriver version {driver_version} for Vivaldi')
        self.__setup_chromium_based(ChromeType.GOOGLE, self.__binary_location.get(BrowserName.VIVALDI), driver_version)
        self.__test_chromium_based(vivaldi)
    
    def test_z_load(self):
        load()

if __name__ == '__main__':
    unittest.main()
