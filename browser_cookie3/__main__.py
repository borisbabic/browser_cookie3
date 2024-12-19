# -*- coding: utf-8 -*-

import argparse
import browser_cookie3
import json


def parse_args(args=None):
    p = argparse.ArgumentParser(
        description='Extract browser cookies using browser_cookie3.',
        epilog='Exit status is 0 if cookie was found, 1 if not found, and 2 if errors occurred',
    )
    p.add_argument('-j', '--json', action='store_true',
                   help="Output JSON with all cookie details, rather than just the cookie's value")
    p.add_argument('domain')
    p.add_argument('name')

    g = p.add_argument_group('Browser selection')
    x = g.add_mutually_exclusive_group()
    x.add_argument('-a', '--all', dest='browser', action='store_const', const=None, default=None,
                   help="Try to load cookies from all supported browsers")
    for browser in browser_cookie3.all_browsers:
        x.add_argument('--' + browser.__name__, dest='browser', action='store_const', const=browser,
                       help="Load cookies from {} browser".format(browser.__name__.title()))
    g.add_argument('-f', '--cookie-file',
                   help="Use specific cookie file (default is to autodetect).")
    g.add_argument('-k', '--key-file',
                   help="Use specific key file (default is to autodetect).")

    args = p.parse_args(args)

    if not args.browser and (args.cookie_file or args.key_file):
        p.error("Must specify a specific browser with --cookie-file or --key-file arguments")

    return p, args


def main(args=None):
    p, args = parse_args(args)

    try:
        if args.browser:
            cj = args.browser(cookie_file=args.cookie_file, key_file=args.key_file)
        else:
            cj = browser_cookie3.load()
    except browser_cookie3.BrowserCookieError as e:
        p.error(e.args[0])

    for cookie in cj:
        if cookie.domain in (args.domain, '.' + args.domain) and cookie.name == args.name:
            if not args.json:
                print(cookie.value)
            else:
                print(json.dumps({k: v for k, v in vars(cookie).items()
                                  if v is not None and (k, v) != ('_rest', {})}))
            break
    else:
        raise SystemExit(1)


if __name__ == '__main__':
    main()
