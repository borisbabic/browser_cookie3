import base64
import unittest
import os
import shutil
import tempfile
import tarfile
import time

from selenium import webdriver
from selenium.webdriver.chrome.service import Service as ChromeService
from selenium.webdriver.edge.service import Service as EdgeService
from selenium.webdriver.firefox.service import Service as FirefoxService

from webdriver_manager.chrome import ChromeDriverManager
from webdriver_manager.firefox import GeckoDriverManager
from webdriver_manager.microsoft import EdgeChromiumDriverManager
from webdriver_manager.core.utils import ChromeType

from urllib3.exceptions import MaxRetryError, NewConnectionError

from .utils.driver_version import get_driver_version_from_chromium_based_binary
from .utils.browser_bin_location import BinaryLocation
from .utils import BrowserName

from __init__ import chrome, chromium, opera, brave, edge, vivaldi, firefox

FIREFOX_PROFILE_DIR_TAR_XZ_B64 = '/Td6WFoAAATm1rRGAgAhARYAAAB0L+Wj4Cf/Ab9dADKeCtBB2uo3WZXNf0LmOYhU+/uDA4UuA4WFok+rSGo77xLonlTJRZVUflBOJqwKkKSdaAqhwGEKuBBQPUhhAnLAtEoZDYIZr/+NtA7qmJUYLdsVeR6Wl7WxZbXKiZGGvRIikC0hq43rbn1Yqg9Np1jaN2SAN9nJ+dbdaiRN41M1dNay8kvuJQN82yhVO60WIPevkpqDyk9e6znR/txuyHxu/+CbWOpjVKK0Za4lt3Q4lSoqMjQsyOotQb+PG2xm8gUMIe+oz+95CoHCPsjkgPQwsE9nZ6Va1k1Ao5kgxs7BM5Zc1gJaAeITfxmzI8Z9jmimHExXDoIayhbg+IaENPO40nuioZvaPnRYKU2giDaqKbeMbfgru1OAQqGHJjtHtluCO6g9BddV6w3w2eseL2L/5ftFlv84//BRoqSe60dlPPf6k9FunUY7nE1DrErvms34C8C5ijJy/w6HyQszlbUrUGhcPzlqcWSbx/qVcdynh0RazPq7bnOcSpdRTOKWDNDCo1YWARi5kzCVYhB3nPpFj35fuIWHWfg4JBz6h69RHe7H06SVat4foed/oKNmocM5tuAtFyzqIumE2BbAAAAAYT2+VFTQ6AsAAdsDgFAAAGra6X2xxGf7AgAAAAAEWVo='
FIREFOX_PROFILE_DIR_NAME = '4xutesqi.default-release'
GO_TO_URLS = ['https://google.com', 'https://facebook.com', 'https://aka.ms']


class Test(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.__temp_dir = tempfile.mktemp(prefix='browser_cookie3_test_')
        cls.__is_github_actions = not not os.environ.get('GITHUB_ACTIONS', False)
        if cls.__is_github_actions:
            cls.__headless = True
        else:
            cls.__headless = not not os.environ.get('RUN_HEADLESS', False)
        if cls.__headless:
            print('Running headless')
        cls.__binary_location = BinaryLocation(raise_not_found=cls.__is_github_actions)

    def setUp(self) -> None:
        os.mkdir(self.__temp_dir)
        super().setUp()
    
    def tearDown(self) -> None:
        shutil.rmtree(self.__temp_dir)
        super().tearDown()

    def __get_data_dir(self):
        data_dir = os.path.join(self.__temp_dir, self._testMethodName)
        return data_dir

    def __wait_for_cookies_to_be_deleted(self, browser_func, cookies_path, timeout):
        end_time = time.time() + timeout
        while time.time() < end_time:
            if len(browser_func(cookies_path)) > 0:
                return
            time.sleep(0.5)

    def __setup_firefox(self):
        mozilla_dir = os.path.expanduser('~/.mozilla')
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
    
    def __test_browser(self, browser_func, cookies_path=None, max_wait_seconds=15):
        for url in GO_TO_URLS:
            self.driver.get(url)
            self.driver.implicitly_wait(10)
        
        self.assertGreaterEqual(len(browser_func(cookies_path)), 0)
        self.driver.quit()
        self.__wait_for_cookies_to_be_deleted(browser_func, cookies_path, max_wait_seconds)
        self.assertGreater(len(browser_func(cookies_path)), 0)

    def __setup_chromium_based(self, chrome_type, binary_location, driver_version=None):
        options = webdriver.ChromeOptions()
        options.binary_location = binary_location
        options.add_argument(f'--user-data-dir={self.__get_data_dir()}')
        if self.__headless:
            options.add_argument('--headless=new')
            options.add_argument('--disable-gpu')
        self.driver = webdriver.Chrome(service=ChromeService(ChromeDriverManager(version=driver_version,chrome_type=chrome_type).install()), options=options)

    def __test_chromium_based(self, browser_func, wait_seconds=15):
        cookies_path = os.path.join(self.__get_data_dir(), 'Default', 'Cookies')
        self.__test_browser(browser_func, cookies_path, wait_seconds)
       
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
        self.__test_browser(firefox)
    
    def test_opera(self):
        self.__setup_chromium_based(ChromeType.GOOGLE, self.__binary_location.get(BrowserName.OPERA))
        self.__test_browser(opera, os.path.join(self.__get_data_dir(), 'Cookies'))
    
    def test_vivaldi(self):
        driver_version = get_driver_version_from_chromium_based_binary('/usr/bin/vivaldi-stable')
        self.__setup_chromium_based(ChromeType.GOOGLE, self.__binary_location.get(BrowserName.VIVALDI), driver_version)
        self.__test_chromium_based(vivaldi, wait_seconds=45)


if __name__ == '__main__':
    unittest.main()
