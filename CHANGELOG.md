### 0.16.0
- [MODULE] Added new browser support: Safari
### 0.15.0
- [MODULE] Added new browser support: Vivaldi
- [Chromium based] Fix profile path channge for macOS Monterey
### 0.14.3
- [Chromium based] Fix for mixture of `v10` and `v11` cookies on linux
### 0.14.2
- [Chromium based] Added support for KDE Wallet
### 0.14.1
- [Chromium based] Added Chromium v96 cookie paths
- [MODULE] Replaced deprecated `distutils` with `setuptools`
### 0.14.0
- [MODULE] Set HTTPOnly flag for cookies
- [MODULE] Remove vestigial json-or-simplejson import
- [DOCS] Update list of supported browsers, fix typos in comments
- [Chromium based] Unbork Chromium-based cookies’ expiration timestamps
- [FIREFOX] Unbork Firefox session cookies’ expiration timestamps
- [FIREFOX] Fix decode error of `profiles.ini`
### 0.13.0
- [BRAVE] Add brave support
- [CHROME] Fix expires handling
- [CHROME] Fix double quoted sqlite strings
### 0.11.4
- [CHROME] Support Chromium v80
- [CHROME] Better error when missing cookie file
### 0.11.3
- [FIREFOX] Add only cookies from the specified domain
### 0.11.2
- [EDGE|Chromium based] Support setting the key file 
### 0.11.1
- [GNOME|ARCH] Improve libsecret detection
### 0.11.0
- [CHROME] Support libsecret
### 0.10.2
- [CHROME] Fix default chromium path on linux
### 0.10.1
- [CHROME] Fix decryption on windows
- [CHROME] Fix windows timestamp OSError issue
### 0.10.0
- [FIREFOX] Fix cookie lookup
- [FIREFOX] Improve profiles.ini handling: different profile.ini locations, absolute instead of relative paths
### 0.9.1
- [CHROME] Fix expires exceeding python's datetime limit #35
### 0.9.0
- [FIREFOX] Add support for checking the default profile in `profiles.ini` #34
- [CHROME] Fix chrome timestamps format #27
