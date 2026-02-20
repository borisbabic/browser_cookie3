"""Tests for the BROWSERS dict and the browsers= parameter on load().

These tests do not require any browser to be installed or any fixture cookie
files. They mock the individual browser loader functions so the only thing
under test is the new API surface introduced by this PR.
"""

import http.cookiejar
import unittest
from unittest.mock import MagicMock, call, patch

import browser_cookie3


def _make_cookie(name, value, domain="example.com"):
    """Create a minimal http.cookiejar.Cookie for testing."""
    return http.cookiejar.Cookie(
        version=0, name=name, value=value,
        port=None, port_specified=False,
        domain=domain, domain_specified=True, domain_initial_dot=False,
        path="/", path_specified=True,
        secure=False, expires=None, discard=True,
        comment=None, comment_url=None, rest={},
    )


class TestBROWSERS(unittest.TestCase):

    def test_is_dict(self):
        self.assertIsInstance(browser_cookie3.BROWSERS, dict)

    def test_keys_are_strings(self):
        for key in browser_cookie3.BROWSERS:
            self.assertIsInstance(key, str, f"Key {key!r} is not a str")

    def test_values_are_callable(self):
        for name, fn in browser_cookie3.BROWSERS.items():
            self.assertTrue(callable(fn), f"BROWSERS[{name!r}] is not callable")

    def test_matches_all_browsers(self):
        """BROWSERS must contain exactly the same functions as all_browsers, in order."""
        self.assertEqual(
            list(browser_cookie3.BROWSERS.values()),
            browser_cookie3.all_browsers,
        )

    def test_keys_match_function_names(self):
        for name, fn in browser_cookie3.BROWSERS.items():
            self.assertEqual(name, fn.__name__)

    def test_known_browsers_present(self):
        for name in ("chrome", "firefox", "safari", "edge", "brave",
                     "chromium", "opera", "vivaldi", "librewolf"):
            self.assertIn(name, browser_cookie3.BROWSERS, f"{name!r} missing from BROWSERS")

    def test_in_dunder_all(self):
        self.assertIn("BROWSERS", browser_cookie3.__all__)

    def test_no_non_browser_callables(self):
        """Helpers like open_dbus_connection and unpad must not appear."""
        for name in browser_cookie3.BROWSERS:
            self.assertNotIn(name, ("load", "create_cookie", "open_dbus_connection", "unpad"),
                             f"Non-browser callable {name!r} leaked into BROWSERS")


class TestLoadBrowsersParam(unittest.TestCase):

    def _mock_loader(self, cookies):
        """Return a mock browser loader that yields the given cookies."""
        mock = MagicMock()
        mock.return_value = iter(cookies)
        return mock

    def test_default_uses_all_browsers(self):
        """load() with no browsers= arg calls every loader in all_browsers."""
        mocks = [self._mock_loader([]) for _ in browser_cookie3.all_browsers]
        with patch.object(browser_cookie3, 'all_browsers', mocks):
            browser_cookie3.load()
        for mock in mocks:
            mock.assert_called_once()

    def test_subset_by_name(self):
        """load(browsers=['firefox', 'chrome']) calls only those two loaders."""
        ff_cookie = _make_cookie("ff_session", "abc")
        ch_cookie = _make_cookie("ch_session", "xyz")
        mock_ff = self._mock_loader([ff_cookie])
        mock_ch = self._mock_loader([ch_cookie])

        with patch.dict(browser_cookie3.BROWSERS, {"firefox": mock_ff, "chrome": mock_ch}):
            cj = browser_cookie3.load(browsers=["firefox", "chrome"])

        mock_ff.assert_called_once()
        mock_ch.assert_called_once()
        cookies = list(cj)
        self.assertEqual(len(cookies), 2)
        names = {c.name for c in cookies}
        self.assertIn("ff_session", names)
        self.assertIn("ch_session", names)

    def test_subset_by_callable(self):
        """load(browsers=[browser_cookie3.firefox]) accepts callables directly."""
        cookie = _make_cookie("tok", "secret")
        mock_ff = self._mock_loader([cookie])

        with patch.dict(browser_cookie3.BROWSERS, {"firefox": mock_ff}):
            # Pass the mock as a callable, not by name
            cj = browser_cookie3.load(browsers=[mock_ff])

        mock_ff.assert_called_once()
        self.assertEqual(len(list(cj)), 1)

    def test_mixed_names_and_callables(self):
        """load() accepts a mix of name strings and callables."""
        c1 = _make_cookie("c1", "v1")
        c2 = _make_cookie("c2", "v2")
        mock_ff = self._mock_loader([c1])
        mock_ch = self._mock_loader([c2])

        with patch.dict(browser_cookie3.BROWSERS, {"firefox": mock_ff, "chrome": mock_ch}):
            cj = browser_cookie3.load(browsers=["firefox", mock_ch])

        mock_ff.assert_called_once()
        mock_ch.assert_called_once()
        self.assertEqual(len(list(cj)), 2)

    def test_empty_browsers_returns_empty_jar(self):
        """load(browsers=[]) returns an empty CookieJar, not all browsers."""
        # Ensure no loader in all_browsers gets called
        mocks = [self._mock_loader([]) for _ in browser_cookie3.all_browsers]
        with patch.object(browser_cookie3, 'all_browsers', mocks):
            cj = browser_cookie3.load(browsers=[])
        for mock in mocks:
            mock.assert_not_called()
        self.assertEqual(len(list(cj)), 0)

    def test_domain_name_forwarded(self):
        """domain_name= is forwarded to each loader."""
        mock_ff = self._mock_loader([])
        with patch.dict(browser_cookie3.BROWSERS, {"firefox": mock_ff}):
            browser_cookie3.load(domain_name="example.com", browsers=["firefox"])
        mock_ff.assert_called_once_with(domain_name="example.com")

    def test_browser_cookie_error_is_swallowed(self):
        """A BrowserCookieError from one loader does not abort the others."""
        cookie = _make_cookie("surviving", "yes")
        failing_loader = MagicMock(side_effect=browser_cookie3.BrowserCookieError("not found"))
        ok_loader = self._mock_loader([cookie])

        with patch.dict(browser_cookie3.BROWSERS, {"chrome": failing_loader, "firefox": ok_loader}):
            cj = browser_cookie3.load(browsers=["chrome", "firefox"])

        cookies = list(cj)
        self.assertEqual(len(cookies), 1)
        self.assertEqual(cookies[0].name, "surviving")

    def test_unknown_browser_name_raises_key_error(self):
        """Passing an unknown string raises KeyError immediately."""
        with self.assertRaises(KeyError):
            browser_cookie3.load(browsers=["netscape"])

    def test_returns_cookiejar(self):
        """load() always returns an http.cookiejar.CookieJar."""
        cj = browser_cookie3.load(browsers=[])
        self.assertIsInstance(cj, http.cookiejar.CookieJar)

    def test_none_is_identical_to_omitting_param(self):
        """Explicitly passing browsers=None behaves the same as not passing it."""
        mocks = [self._mock_loader([]) for _ in browser_cookie3.all_browsers]
        with patch.object(browser_cookie3, 'all_browsers', mocks):
            browser_cookie3.load(browsers=None)
        for mock in mocks:
            mock.assert_called_once()


if __name__ == "__main__":
    unittest.main()
