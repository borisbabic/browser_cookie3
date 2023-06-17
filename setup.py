from setuptools import setup

setup(
    name='browser-cookie3',
    version='0.19.1',
    packages=['browser_cookie3'],
    # look for package contents in current directory
    package_dir={'browser_cookie3': 'browser_cookie3'},
    author='Boris Babic',
    author_email='boris.ivan.babic@gmail.com',
    description='Loads cookies from your browser into a cookiejar object so can download with urllib and other libraries the same content you see in the web browser.',     # noqa: E501
    url='https://github.com/borisbabic/browser_cookie3',
    install_requires=[
        'lz4',
        'pycryptodomex',
        'dbus-python; python_version < "3.7" and ("bsd" in sys_platform or sys_platform == "linux")',
        'jeepney; python_version >= "3.7" and ("bsd" in sys_platform or sys_platform == "linux")'
    ],
    license='lgpl'
)
