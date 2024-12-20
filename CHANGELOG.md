### 0.21.0
- [MODULE] Fix lynx issue
### 0.20.0
- [CLI] Add browser-cookie cli
- [MODULE] Added new browser support: Lynx, W3m, and Arc
- [MODULE] Avoid ResourceWarning
- [Win32] Support shadowcopy if we can't get cookies the normal way
### 0.19.2
- [Chromium based] Handle latest sqlite schema
### 0.19.1
- [Firefox based] Fix an error when `load()` fails if librewolf or firefox is not installed
### 0.19.0
- [MODULE] Added new browser support: LibreWolf
- [MODULE] Added `immutable` mode for opening cookies database
- [Chromium based] Added paths for flatpak installations
### 0.18.2
- [MODULE] Added tests
### 0.18.1
- [FIREFOX] Fixed Firefox database read error on linux and macOS
- [MODULE] Fixed read for empty password encrypted cookies on Chromium based browsers
### 0.18.0
- [MODULE] Removed legacy imports and code improvements
### 0.17.1
- [MODULE] Fixed when no password storage is provided by any service on linux
- [MODULE] Fixed dbus related error on linux
- [MODULE] Look for Firefox cookies in Snap folder first on linux due Ubuntu changes
### 0.17.0
- [MODULE] Added new browser support: Opera GX
- [MODULE] Added developer channels for Chromium based browsers
- [MODULE] Added profile other than `Default` for Chromium based browsers
- [MODULE] Marked internal functions with `_` prefix
- [MODULE] Removed `keyring` and `SecretStorage` dependency
### 0.16.5
- [MODULE] Fixed a bug where the `browser-cookie3.load()` fails on linux and Windows
### 0.16.4
- [SAFARI] A new location for the `Cookies.binarycookies` file
- [SAFARI] Fix for Cookie format change
### 0.16.3
- [MODULE] Replaced `pycryptodome` with `pycryptodomex`
- [MODULE] Removed `pbkdf2` and `pyaes` dependency
### 0.16.2
- [MODULE] Added bsd support
### 0.16.1
- [MODULE] Fix resource warning about unclosed file
- [FIREFOX] Added firefox snap directory
### 0.16.0
- [MODULE] Added new browser support: Safari
### 0.15.0
- [MODULE] Added new browser support: Vivaldi
- [Chromium based] Fix profile path change for macOS Monterey
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
