from tests.python.util import Test

from minigrid.options import get_cookie_secret, cookie_secret_path


class TestCookieSecret(Test):
    def test_secret_exists(self):
        with open(cookie_secret_path, 'wb') as new_file:
            new_file.write('cookie'.encode())
        self.assertEqual(get_cookie_secret(), 'cookie'.encode())

    def test_secret_does_not_exist(self):
        cookie_secret = get_cookie_secret()
        with open(cookie_secret_path, 'rb') as new_file:
            new_cookie = new_file.read()
        self.assertEqual(cookie_secret, new_cookie)
