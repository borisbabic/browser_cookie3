from http.server import BaseHTTPRequestHandler, HTTPServer
import subprocess
import tempfile

DEFAULT_TIMEOUT = 30 # sec
_ua_list = []

class HTTPRequestHandler(BaseHTTPRequestHandler):    
    def log_request(self, *args):
        pass # No need to log
    
    def __handle_get_request(self):
        ua = self.headers.get('User-Agent')
        if ua:
            _ua_list.append(ua)
        self.send_response(200)
        self.send_header('Content-Type', 'text/plain')
        self.end_headers()

        self.wfile.write(b'OK')

    def do_GET(self):
        self.__handle_get_request()

class UAGetter:
    HEADLESS_NEW = 'new'
    HEADLESS_OLD = 'old'
    HEADLESS_DEFAULT = ''

    def __init__(self, binary_path, headless_mode=HEADLESS_DEFAULT, timeout=DEFAULT_TIMEOUT):
        self.__set_server()
        self.__temp_dir = tempfile.mkdtemp(prefix='browser_ua_')
        headless = f'--headless={headless_mode}' if headless_mode else '--headless'
        self.__args = [binary_path, headless, '--disable-gpu', f'--user-data-dir={self.__temp_dir}']
        self.server.timeout = timeout    
    
    def __set_server(self):
        port = 55121
        while True:
            try:
                server = HTTPServer(('127.0.0.1', port), HTTPRequestHandler)
                break
            except:
                port+=1
        self.server = server
    
    def get(self):
        self.__args.append(f'http://127.0.0.1:{self.server.server_port}')
        process = subprocess.Popen(self.__args, stderr=subprocess.DEVNULL, stdout=subprocess.DEVNULL)
        self.server.handle_request()
        self.server.server_close()

        process.kill()
        process.wait()
        
        return _ua_list[0] if _ua_list else None
