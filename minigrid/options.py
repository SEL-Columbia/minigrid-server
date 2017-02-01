"""All of the application-level options."""
from functools import partial
import os
import secrets

from tornado.options import define, options, parse_command_line

__all__ = ('options', 'parse_command_line', 'application_settings')

path = partial(os.path.join, os.path.dirname(__file__))
path.__doc__ = 'Full path relative to the directory of this file.'


cookie_secret_path = path('../COOKIE_SECRET')


def get_cookie_secret():
    """Return the secret key used for session cookies."""
    try:
        with open(cookie_secret_path, 'rb') as cookie_file:
            cookie_secret = cookie_file.read()
    except FileNotFoundError:
        with open(cookie_secret_path, 'wb') as new_cookie_file:
            cookie_secret = secrets.token_bytes(24)
            new_cookie_file.write(cookie_secret)
    return cookie_secret


define(
    'application_debug', default=False,
    help='Dangerous option that shows debug information for any error.'
)
define(
    'minigrid_website_url', default='http://localhost:8888',
    help='The URL of this instance of the minigrid server.'
)
define('minigrid_https', default=True)
define('minigrid_port', default='8888')
define('db_host', default='localhost')
define('db_port', default=5432)
define('db_database', default='minigrid')
define('db_schema', default='minigrid')
define('db_user', default='postgres')
define('db_password', default='password')
define('redis_url', default='redis://localhost:6379/0')


def application_settings():
    """Get only the Application settings from the options."""
    return {
        'static_path': path('static'),
        'template_path': path('templates'),
        'cookie_secret': get_cookie_secret(),
        'xsrf_cookies': True,
        'login_url': '/',
        'debug': options.application_debug,
    }
