from distutils.core import setup

setup(
    name='browser-cookie', 
    version='0.4',
    packages=['browser_cookie'],
    package_dir={'browser_cookie' : '.'}, # look for package contents in current directory
    author='Boris Babic',
    author_email='boris.ivan.babic@gmail.com',
    description='Loads cookies from your browser into a cookiejar object so can download with urllib and other libraries the same content you see in the web browser.',
    url='https://github.com/borisbabic/browser_cookie3',
    install_requires=['pycrypto', 'keyring'],
    license='lgpl'
)
