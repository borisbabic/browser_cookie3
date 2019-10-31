from distutils.core import setup

setup(
    name='browser-cookie3',
    version='0.7.6',
    packages=['browser_cookie3'],
    package_dir={'browser_cookie3' : '.'}, # look for package contents in current directory
    author='Boris Babic',
    author_email='boris.ivan.babic@gmail.com',
    description='Loads cookies from your browser into a cookiejar object so can download with urllib and other libraries the same content you see in the web browser.',
    url='https://github.com/borisbabic/browser_cookie3',
    install_requires=['pyaes','pbkdf2','keyring','lz4','configparser'],
    license='lgpl',
    classifiers=[
        "Programming Language :: Python :: 3",
        'License :: OSI Approved :: GNU Lesser General Public License v3 or later (LGPLv3+)',
        "Operating System :: OS Independent",
    ]
)
