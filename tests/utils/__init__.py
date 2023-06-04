import logging


class BrowserName:
    CHROME = 'chrome'
    CHROMIUM = 'chromium'
    OPERA = 'opera'
    OPERA_GX = 'opera_gx'
    BRAVE = 'brave'
    EDGE = 'edge'
    VIVALDI = 'vivaldi'
    FIREFOX = 'firefox'
    LIBREWOLF = 'librewolf'


logger = logging.getLogger('browser_cookie3_test')
logger.setLevel(logging.INFO)
console_handler = logging.StreamHandler()
formatter = logging.Formatter('%(levelname)s - %(message)s')
console_handler.setFormatter(formatter)
logger.addHandler(console_handler)
