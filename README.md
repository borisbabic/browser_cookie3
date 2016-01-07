This is a python3 fork of [Richard Penman's Browser Cookie](https://bitbucket.org/richardpenman/browsercookie)

# Browser Cookie #

* ***What does it do?*** Loads cookies used by your web browser into a cookiejar object.
* ***Why is it useful?*** This means you can use python to download and get the same content you see in the web browser without needing to login.
* ***Which browsers are supported?*** Currently Chrome and Firefox.
* ***How are the cookies stored?*** In a sqlite database in your home directory.

## Install ##
```
#!bash

    pip3 install browser-cookie3

```


## Usage ##

Here is a *dangerous* hack to extract the title from a webpage:
```
#!python
>>> import re
>>> get_title = lambda html: re.findall('<title>(.*?)</title>', html, flags=re.DOTALL)[0].strip()
```

And here is the webpage title when downloaded normally:
```
#!python
>>> import urllib2
>>> url = 'https://bitbucket.org/'
>>> public_html = urllib2.urlopen(url).read()
>>> get_title(public_html)
'Git and Mercurial code management for teams'
```

Now let's try with browser_cookie3 - make sure you are logged into Bitbucket in Firefox before trying this example:
```
#!python

>>> import browser_cookie3
>>> cj = browser_cookie3.firefox()
>>> opener = urllib2.build_opener(urllib2.HTTPCookieProcessor(cj))
>>> login_html = opener.open(url).read()
>>> get_title(login_html)
'richardpenman / home &mdash; Bitbucket'
```

You should see your own username here, meaning the module successfully loaded the cookies from Firefox.

Here is an alternative example with [requests](http://docs.python-requests.org/en/latest/), this time loading the Chrome cookies. Again make sure you are logged into Bitbucket in Chrome before running this:
```
#!python

>>> import browser_cookie3
>>> import requests
>>> cj = browser_cookie3.chrome()
>>> r = requests.get(url, cookies=cj)
>>> get_title(r.content)
'richardpenman / home &mdash; Bitbucket'
```

Alternatively if you don't know/care which browser has the cookies you want then all available browser cookies can be loaded:
```
#!python

>>> import browser_cookie3
>>> import requests
>>> cj = browser_cookie3.load()
>>> r = requests.get(url, cookies=cj)
>>> get_title(r.content)
'richardpenman / home &mdash; Bitbucket'
```

Alternatively if you are only interested in cookies from a specific domain, you can specify a domain filter.
```
#!python

>>> import browser_cookie3
>>> import requests
>>> cj = browser_cookie3.chrome('www.bitbucket.com')
>>> r = requests.get(url, cookies=cj)
>>> get_title(r.content)
'richardpenman / home &mdash; Bitbucket'
```

## Contribute ##
So far the following platforms are supported:

* **Chrome:** Linux, OSX, Windows
* **Firefox:** Linux, OSX, Windows

## Testing Dates  ##

OS      | Chrome | Firefox |
:------ | :----: | :-----: |
Mac     | 1/6/16 | 1/6/16  |
Linux   | 1/6/16 | 1/6/16  |
Windows | 1/6/16 | n/a     |

However I only tested on a single version of each browser and so am not sure if the cookie sqlite format changes location or format in earlier/later versions. If you experience a problem please [open an issue](https://github.com/borisbabic/browser_cookie3/issues/new) which includes details of the browser version and operating system. Also patches to support other browsers are very welcome, particularly for Chrome and Internet Explorer on Windows.

## Acknowledgements ##
Special thanks to Nathan Henrie for his example of [how to decode the Chrome cookies](http://n8henrie.com/2013/11/use-chromes-cookies-for-easier-downloading-with-python-requests/).
