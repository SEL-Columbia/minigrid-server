from unittest.mock import patch
from urllib.parse import urlparse, parse_qs
import uuid

from bs4 import BeautifulSoup as inconvenient_soup

from sqlalchemy.exc import IntegrityError

from tornado.testing import ExpectLog

from tests.python.util import HTTPTest, CoroMock

from minigrid import models
from minigrid.portier import redis_kv
from server import Application


def BeautifulSoup(page):
    return inconvenient_soup(page, 'html.parser')


class TestSystemNotInitialized(HTTPTest):
    def setUp(self):
        super().setUp()
        with models.transaction(self.session) as session:
            self.user = models.User(email='a@a.com')
            session.add(self.user)

    @patch('minigrid.handlers.BaseHandler.get_current_user')
    def test_not_initialized_message(self, get_current_user):
        get_current_user.return_value = self.user
        response = self.fetch('/')
        self.assertResponseCode(response, 200)
        self.assertNotIn('Log In', response.body.decode())
        self.assertIn('Log Out', response.body.decode())
        self.assertIn(
            'You must initialize the system tariff information.',
            response.body.decode())

    @patch('minigrid.handlers.BaseHandler.get_current_user')
    def test_view_tariffs_not_initialized(self, get_current_user):
        get_current_user.return_value = self.user
        response = self.fetch('/tariffs', follow_redirects=False)
        self.assertResponseCode(response, 302)
        self.assertEqual(response.headers['Location'], '/')

    @patch('minigrid.handlers.BaseHandler.get_current_user')
    def test_post_tariffs_not_initialized(self, get_current_user):
        get_current_user.return_value = self.user
        response = self.fetch(
            '/tariffs?day_tariff=1&day_tariff_start=6'
            '&night_tariff=1&night_tariff_start=18',
            method='POST', body='')
        self.assertResponseCode(response, 200)
        self.assertNotIn(
            'You must initialize the system tariff information.',
            response.body.decode())
        system = self.session.query(models.System).one()
        self.assertEqual(system.day_tariff, 1)
        self.assertEqual(system.day_tariff_start, 6)
        self.assertEqual(system.night_tariff, 1)
        self.assertEqual(system.night_tariff_start, 18)

    @patch('minigrid.handlers.BaseHandler.get_current_user')
    def test_post_tariffs_not_initialized_missing_values(
            self, get_current_user):
        get_current_user.return_value = self.user
        with ExpectLog('tornado.access', '400'):
            response = self.fetch(
                '/tariffs?day_tariff=1', method='POST', body='')
        self.assertResponseCode(response, 400)
        self.assertIn('Null value', response.body.decode())
        self.assertIsNone(self.session.query(models.System).one_or_none())


class TestIndex(HTTPTest):
    def setUp(self):
        super().setUp()
        with models.transaction(self.session) as session:
            self.user = models.User(email='a@a.com')
            session.add(self.user)
            session.add(models.System(day_tariff=1, night_tariff=1))
            self.minigrids = (
                models.Minigrid(name='a'),
                models.Minigrid(name='b'),
            )
            session.add_all(self.minigrids)

    def test_get_not_logged_in(self):
        response = self.fetch('/')
        self.assertResponseCode(response, 200)
        self.assertNotIn('user', response.headers['Set-Cookie'])
        self.assertIn('Log In', response.body.decode())
        self.assertNotIn('Log Out', response.body.decode())

    @patch('minigrid.handlers.BaseHandler.get_current_user')
    def test_get_logged_in(self, get_current_user):
        get_current_user.return_value = self.user
        response = self.fetch('/')
        self.assertResponseCode(response, 200)
        self.assertNotIn('Log In', response.body.decode())
        self.assertIn('Log Out', response.body.decode())
        self.assertNotIn(
            'You must initialize the system tariff information.',
            response.body.decode())
        body = BeautifulSoup(response.body)
        minigrids = body.ul.findAll('li')
        self.assertEqual(len(minigrids), 2)
        self.assertEqual(
            minigrids[0].a['href'],
            '/minigrid/' + self.minigrids[0].minigrid_id,
        )
        self.assertEqual(minigrids[0].a.text, self.minigrids[0].name + ' »')


class TestMinigridView(HTTPTest):
    def setUp(self):
        super().setUp()
        with models.transaction(self.session) as session:
            self.user = models.User(email='a@a.com')
            session.add(self.user)
            session.add(models.System(day_tariff=1, night_tariff=1))
            self.minigrids = (
                models.Minigrid(name='a'),
                models.Minigrid(name='b'),
            )
            session.add_all(self.minigrids)

    def test_get_not_logged_in(self):
        response = self.fetch(
            '/minigrid/' + self.minigrids[0].minigrid_id,
            follow_redirects=False,
        )
        self.assertResponseCode(response, 302)

    @patch('minigrid.handlers.BaseHandler.get_current_user')
    def test_get_malformed_id(self, get_current_user):
        get_current_user.return_value = self.user
        with ExpectLog('tornado.access', '404'):
            response = self.fetch('/minigrid/' + 'nope')
        self.assertResponseCode(response, 404)

    @patch('minigrid.handlers.BaseHandler.get_current_user')
    def test_get_nonexistent_id(self, get_current_user):
        get_current_user.return_value = self.user
        with ExpectLog('tornado.access', '404'):
            response = self.fetch('/minigrid/' + str(uuid.uuid4()))
        self.assertResponseCode(response, 404)

    @patch('minigrid.handlers.BaseHandler.get_current_user')
    def test_get_success(self, get_current_user):
        get_current_user.return_value = self.user
        response = self.fetch('/minigrid/' + self.minigrids[0].minigrid_id)
        self.assertResponseCode(response, 200)
        body = BeautifulSoup(response.body)
        self.assertIn('Minigrid Name: a', body.h1)


class TestUsersView(HTTPTest):
    def setUp(self):
        super().setUp()
        with models.transaction(self.session) as session:
            self.users = (
                models.User(email='a@a.com'),
                models.User(email='b@b.com'),
            )
            session.add_all(self.users)

    def test_get_not_logged_in(self):
        response = self.fetch('/users', follow_redirects=False)
        self.assertResponseCode(response, 302)

    @patch('minigrid.handlers.BaseHandler.get_current_user')
    def test_get_logged_in(self, get_current_user):
        get_current_user.return_value = self.users[0]
        response = self.fetch('/users')
        self.assertResponseCode(response, 200)
        body = BeautifulSoup(response.body)
        user_ul = body.ul.findAll('li')
        self.assertEqual(user_ul[0].a['href'], 'mailto:a@a.com')
        self.assertEqual(user_ul[1].a['href'], 'mailto:b@b.com')

    def test_post_not_logged_in(self):
        with ExpectLog('tornado.access', '403'):
            response = self.fetch('/users', method='POST', body='')
        self.assertResponseCode(response, 403)

    @patch('minigrid.handlers.BaseHandler.get_current_user')
    def test_post_empty_email(self, get_current_user):
        get_current_user.return_value = self.users[0]
        response = self.fetch('/users?email=', method='POST', body='')
        self.assertIn('Could not create user account', response.body.decode())
        self.assertIn('not a valid e-mail address', response.body.decode())

    @patch('minigrid.handlers.BaseHandler.get_current_user')
    def test_post_invalid_email(self, get_current_user):
        get_current_user.return_value = self.users[0]
        response = self.fetch('/users?email=notemail', method='POST', body='')
        self.assertIn('Could not create user account', response.body.decode())
        self.assertIn('not a valid e-mail address', response.body.decode())

    @patch('minigrid.handlers.BaseHandler.get_current_user')
    def test_post_user_exists(self, get_current_user):
        get_current_user.return_value = self.users[0]
        response = self.fetch('/users?email=a@a.com', method='POST', body='')
        self.assertIn(
            'Account for a@a.com already exists', response.body.decode())

    @patch('minigrid.handlers.BaseHandler.get_current_user')
    def test_post_success(self, get_current_user):
        get_current_user.return_value = self.users[0]
        response = self.fetch('/users?email=ba@a.com', method='POST', body='')
        body = BeautifulSoup(response.body)
        user_ul = body.ul.findAll('li')
        self.assertEqual(user_ul[1].a['href'], 'mailto:ba@a.com')
        self.assertIsNotNone(
            self.session.query(models.User).filter_by(email='ba@a.com').one())


class TestTariffsView(HTTPTest):
    def setUp(self):
        super().setUp()
        with models.transaction(self.session) as session:
            self.user = models.User(email='a@a.com')
            session.add(self.user)
            session.add(models.System(day_tariff=1, night_tariff=1))

    def test_get_tariffs_not_logged_in(self):
        response = self.fetch('/tariffs')
        self.assertResponseCode(response, 200)
        self.assertNotIn('user', response.headers['Set-Cookie'])
        self.assertIn('Log In', response.body.decode())
        self.assertNotIn('Log Out', response.body.decode())

    @patch('minigrid.handlers.BaseHandler.get_current_user')
    def test_get_tariffs_logged_in(self, get_current_user):
        get_current_user.return_value = self.user
        response = self.fetch('/tariffs')
        self.assertResponseCode(response, 200)
        body = BeautifulSoup(response.body)
        self.assertEqual(
            body.findAll('p')[1].contents[0], 'Tariff information:')
        self.assertEqual(
            body.find('input', {'name': 'day_tariff'})['value'], '1')
        self.assertEqual(
            body.find('input', {'name': 'day_tariff_start'})['value'], '6')
        self.assertEqual(
            body.find('input', {'name': 'night_tariff'})['value'], '1')
        self.assertEqual(
            body.find('input', {'name': 'night_tariff_start'})['value'], '18')

    @patch('minigrid.handlers.BaseHandler.get_current_user')
    def test_update_tariffs(self, get_current_user):
        get_current_user.return_value = self.user
        self.assertEqual(
            self.session.query(models.System).one_or_none().day_tariff, 1)
        response = self.fetch(
            '/tariffs?day_tariff=2.5', method='POST', body='')
        self.assertEqual(
            self.session.query(models.System).one_or_none().day_tariff, 2.5)
        body = BeautifulSoup(response.body)
        self.assertEqual(
            body.find('input', {'name': 'day_tariff'})['value'], '2.5')

    @patch('minigrid.handlers.BaseHandler.get_current_user')
    def test_update_tariffs_bad_tariff_invalid_value(self, get_current_user):
        get_current_user.return_value = self.user
        self.assertEqual(
            self.session.query(models.System).one_or_none().day_tariff, 1)
        with ExpectLog('tornado.access', '400'):
            response = self.fetch(
                '/tariffs?day_tariff=-2', method='POST', body='')
        self.assertEqual(
            self.session.query(models.System).one_or_none().day_tariff, 1)
        self.assertIn('Invalid value', response.body.decode())

    @patch('minigrid.handlers.BaseHandler.get_current_user')
    def test_update_tariffs_missing_tariff(self, get_current_user):
        get_current_user.return_value = self.user
        self.assertEqual(
            self.session.query(models.System).one_or_none().day_tariff, 1)
        with ExpectLog('tornado.access', '400'):
            response = self.fetch(
                '/tariffs?day_tariff=', method='POST', body='')
        self.assertEqual(
            self.session.query(models.System).one_or_none().day_tariff, 1)
        self.assertIn('Invalid input syntax', response.body.decode())

    @patch('minigrid.handlers.BaseHandler.get_current_user')
    def test_update_tariffs_bad_day_tariff_start(self, get_current_user):
        get_current_user.return_value = self.user
        self.assertEqual(
            self.session.query(models.System).one_or_none().day_tariff_start,
            6)
        with ExpectLog('tornado.access', '400'):
            response = self.fetch(
                '/tariffs?day_tariff_start=-1', method='POST', body='')
        self.assertEqual(
            self.session.query(models.System).one_or_none().day_tariff_start,
            6)
        self.assertIn('Invalid value', response.body.decode())

    @patch('minigrid.handlers.BaseHandler.get_current_user')
    def test_update_tariffs_late_day_tariff_start(self, get_current_user):
        get_current_user.return_value = self.user
        self.assertEqual(
            self.session.query(models.System).one_or_none().day_tariff_start,
            6)
        with ExpectLog('tornado.access', '400'):
            response = self.fetch(
                '/tariffs?day_tariff_start=19', method='POST', body='')
        self.assertEqual(
            self.session.query(models.System).one_or_none().day_tariff_start,
            6)
        self.assertIn(
            'The daytime start hour must be less than'
            ' the nighttime start hour.',
            response.body.decode())

    @patch('minigrid.handlers.BaseHandler.get_current_user')
    def test_update_tariffs_early_night_tariff_start(self, get_current_user):
        get_current_user.return_value = self.user
        self.assertEqual(
            self.session.query(models.System).one_or_none().night_tariff_start,
            18)
        with ExpectLog('tornado.access', '400'):
            response = self.fetch(
                '/tariffs?night_tariff_start=5', method='POST', body='')
        self.assertEqual(
            self.session.query(models.System).one_or_none().night_tariff_start,
            18)
        self.assertIn(
            'The daytime start hour must be less than'
            ' the nighttime start hour.',
            response.body.decode())

    @patch('minigrid.handlers.BaseHandler.session')
    @patch('minigrid.handlers.BaseHandler.get_current_user')
    def test_update_tariffs_bad_tariff(self, get_current_user, session):
        get_current_user.return_value = self.user

        class FakePGError:
            pgerror = 'This should show up'
        session.execute.side_effect = IntegrityError(None, None, FakePGError)
        self.assertEqual(
            self.session.query(models.System).one_or_none().day_tariff, 1)
        with ExpectLog('tornado.access', '400'):
            response = self.fetch(
                '/tariffs?day_tariff=-2', method='POST', body='')
        self.assertEqual(
            self.session.query(models.System).one_or_none().day_tariff, 1)
        self.assertIn('This should show up', response.body.decode())


class TestXSRF(HTTPTest):
    def get_app(self):
        self.app = Application(self.session)
        return self.app

    def test_xsrf_parameter_missing(self):
        log_1 = ExpectLog('tornado.general', ".*_xsrf.*missing.*")
        log_2 = ExpectLog('tornado.access', '403')
        with log_1, log_2:
            response = self.fetch('/', method='POST', body='')
        self.assertResponseCode(response, 403)

    def test_verify_no_xsrf(self):
        log_1 = ExpectLog('tornado.general', ".*Missing argument id_token")
        log_2 = ExpectLog('tornado.access', '400')
        with log_1, log_2:
            response = self.fetch('/verify', method='POST', body='')
        self.assertNotIn('xsrf', response.error.message)


class TestAuthentication(HTTPTest):
    def create_user(self, email='a@a.com'):
        with models.transaction(self.session) as session:
            session.add(models.User(email=email))

    def test_login_missing_email(self):
        log_1 = ExpectLog('tornado.general', '.*Missing argument email')
        log_2 = ExpectLog('tornado.access', '400')
        with log_1, log_2:
            response = self.fetch('/', method='POST', body='')
        self.assertResponseCode(response, 400)

    def test_login_success(self):
        response = self.fetch(
            '/?email=a@a.com', method='POST', body='', follow_redirects=False)
        self.assertResponseCode(response, 302)
        query = parse_qs(urlparse(response.headers['Location']).query)
        self.assertEqual(query['login_hint'][0], 'a@a.com')
        self.assertIn(query['nonce'][0].encode(), redis_kv)
        self.assertTrue(query['redirect_uri'][0].endswith('/verify'))

    @patch('minigrid.handlers.get_verified_email', new_callable=CoroMock)
    def test_verify(self, get_verified_email):
        get_verified_email.coro.return_value = 'a@a.com'
        self.create_user()
        response = self.fetch(
            '/verify?id_token=', method='POST', body='', follow_redirects=False
        )
        self.assertResponseCode(response, 302)
        self.assertIn('user', response.headers['Set-Cookie'])
        index = self.fetch(
            '/', headers={'Cookie': response.headers['Set-Cookie']})
        self.assertResponseCode(index, 200)
        self.assertIn('a@a.com', index.body.decode())

    @patch('minigrid.handlers.get_verified_email', new_callable=CoroMock)
    def test_verify_user_does_not_exist(self, get_verified_email):
        get_verified_email.coro.return_value = 'a@a.com'
        with ExpectLog('tornado.access', '400'):
            response = self.fetch('/verify?id_token=', method='POST', body='')
        self.assertResponseCode(response, 400)
        self.assertEqual(
            response.error.message, 'There is no account for a@a.com')

    def test_verify_handle_error(self):
        url = '/verify?error=error&error_description=desc'
        with ExpectLog('tornado.access', '400'):
            response = self.fetch(url, method='POST', body='')
        self.assertResponseCode(response, 400)
        self.assertIn('desc', response.error.message)

    def test_get_logout(self):
        response = self.fetch('/logout')
        self.assertResponseCode(response, 200)
        self.assertIn('Log Out', response.body.decode())

    def test_post_logout(self):
        response = self.fetch(
            '/logout', method='POST', body='', follow_redirects=False)
        self.assertResponseCode(response, 302)
        self.assertEqual(response.headers['Location'], '/')
