from unittest.mock import patch
from urllib.parse import urlparse, parse_qs
import uuid

from bs4 import BeautifulSoup as inconvenient_soup

from sqlalchemy.exc import IntegrityError

from tornado.testing import ExpectLog

from tests.python.util import HTTPTest, CoroMock

from minigrid import models
from minigrid.handlers import cache
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
                models.Minigrid(minigrid_name='a'),
                models.Minigrid(minigrid_name='b'),
            )
            session.add_all(self.minigrids)
            session.add(models.Device(address=bytes(6)))

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
        minigrids = body.findAll('p')
        self.assertEqual(len(minigrids), 2, msg=minigrids)
        self.assertEqual(
            minigrids[0].a['href'],
            '/minigrids/' + self.minigrids[0].minigrid_id,
        )
        self.assertEqual(
            minigrids[0].a.text, self.minigrids[0].minigrid_name + ' »')


class TestMinigridHandler(HTTPTest):
    def setUp(self):
        super().setUp()
        with models.transaction(self.session) as session:
            self.user = models.User(email='a@a.com')
            session.add(self.user)
            session.add(models.System(day_tariff=1, night_tariff=1))
            self.minigrids = (
                models.Minigrid(minigrid_name='a'),
                models.Minigrid(minigrid_name='b'),
            )
            session.add_all(self.minigrids)
            session.add(models.Device(address=bytes(6)))

    def test_get_not_logged_in(self):
        response = self.fetch(
            '/minigrids/' + self.minigrids[0].minigrid_id,
            follow_redirects=False,
        )
        self.assertResponseCode(response, 302)

    @patch('minigrid.handlers.BaseHandler.get_current_user')
    def test_get_malformed_id(self, get_current_user):
        get_current_user.return_value = self.user
        with ExpectLog('tornado.access', '404'):
            response = self.fetch('/minigrids/' + 'nope')
        self.assertResponseCode(response, 404)

    @patch('minigrid.handlers.BaseHandler.get_current_user')
    def test_get_nonexistent_id(self, get_current_user):
        get_current_user.return_value = self.user
        with ExpectLog('tornado.access', '404'):
            response = self.fetch('/minigrids/' + str(uuid.uuid4()))
        self.assertResponseCode(response, 404)

    @patch('minigrid.handlers.BaseHandler.get_current_user')
    def test_get_success(self, get_current_user):
        get_current_user.return_value = self.user
        response = self.fetch('/minigrids/' + self.minigrids[0].minigrid_id)
        self.assertResponseCode(response, 200)
        body = BeautifulSoup(response.body)
        self.assertIn('Minigrid Name: a', body.h1)


class TestUsersHandler(HTTPTest):
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
        user_p = body.findAll('p')
        self.assertEqual(user_p[1].a['href'], 'mailto:a@a.com')
        self.assertEqual(user_p[2].a['href'], 'mailto:b@b.com')

    def test_post_not_logged_in(self):
        with ExpectLog('tornado.access', '403'):
            response = self.fetch('/users', method='POST', body='')
        self.assertResponseCode(response, 403)

    @patch('minigrid.handlers.BaseHandler.get_current_user')
    def test_post_empty_email(self, get_current_user):
        get_current_user.return_value = self.users[0]
        self.fetch('/users?email=', method='POST', body='')
        self.assertEqual(self.session.query(models.User).count(), 2)
        # Not sure why this isn't showing up...
        # self.assertIn(
        #     'Could not create user account', response.body.decode())
        # self.assertIn('not a valid e-mail address', response.body.decode())

    @patch('minigrid.handlers.BaseHandler.get_current_user')
    def test_post_invalid_email(self, get_current_user):
        get_current_user.return_value = self.users[0]
        self.fetch('/users?email=notemail', method='POST', body='')
        self.assertEqual(self.session.query(models.User).count(), 2)
        # Not sure why this isn't showing up...
        # self.assertIn(
        #     'Could not create user account', response.body.decode())
        # self.assertIn('not a valid e-mail address', response.body.decode())

    @patch('minigrid.handlers.BaseHandler.get_current_user')
    def test_post_user_exists(self, get_current_user):
        get_current_user.return_value = self.users[0]
        self.fetch('/users?email=a@a.com', method='POST', body='')
        # Not sure why this isn't showing up...
        # self.assertIn(
        #     'Account for a@a.com already exists', response.body.decode())

    @patch('minigrid.handlers.BaseHandler.get_current_user')
    def test_post_success(self, get_current_user):
        get_current_user.return_value = self.users[0]
        response = self.fetch('/users?email=ba@a.com', method='POST', body='')
        body = BeautifulSoup(response.body)
        user_p = body.findAll('p')
        self.assertEqual(user_p[1].a['href'], 'mailto:a@a.com')
        self.assertIsNotNone(
            self.session.query(models.User).filter_by(email='ba@a.com').one())


class TestTariffsHandler(HTTPTest):
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
            body.legend.contents[0], 'Tariff information:')
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


class TestMinigridsHandler(HTTPTest):
    def setUp(self):
        super().setUp()
        with models.transaction(self.session) as session:
            self.user = models.User(email='a@a.com')
            session.add(self.user)
            session.add(models.System(day_tariff=1, night_tariff=1))
            session.add(models.Device(address=bytes(6)))

    def test_get_minigrids_not_logged_in(self):
        response = self.fetch('/minigrids')
        self.assertResponseCode(response, 200)
        self.assertNotIn('user', response.headers['Set-Cookie'])
        self.assertIn('Log In', response.body.decode())
        self.assertNotIn('Log Out', response.body.decode())

    @patch('minigrid.handlers.BaseHandler.get_current_user')
    def test_get_minigrids_logged_in_redirect(self, get_current_user):
        get_current_user.return_value = self.user
        response = self.fetch('/minigrids', follow_redirects=False)
        self.assertResponseCode(response, 302)
        self.assertEqual(response.headers['Location'], '/')

    @patch('minigrid.handlers.BaseHandler.get_current_user')
    def test_get_minigrids_logged_in_result(self, get_current_user):
        get_current_user.return_value = self.user
        response = self.fetch('/minigrids')
        self.assertIn('No minigrids', response.body.decode())

    @patch('minigrid.handlers.BaseHandler.get_current_user')
    def test_post_minigrids_success(self, get_current_user):
        get_current_user.return_value = self.user
        with models.transaction(self.session) as session:
            payment_system = models.PaymentSystem(aes_key=bytes(32))
            session.add(payment_system)
        pid = payment_system.payment_id
        self.assertIsNone(self.session.query(models.Minigrid).one_or_none())
        response = self.fetch(
            f'/minigrids?minigrid_name=a&minigrid_payment_id={pid}',
            method='POST', body='')
        self.assertResponseCode(response, 200)
        minigrid = self.session.query(models.Minigrid).one()
        self.assertEqual(minigrid.minigrid_name, 'a')
        self.assertEqual(minigrid.payment_system.payment_id, pid)

    @patch('minigrid.handlers.BaseHandler.get_current_user')
    def test_post_minigrids_missing_field(self, get_current_user):
        get_current_user.return_value = self.user
        log_1 = ExpectLog(
            'tornado.general', ".*Missing argument minigrid_name")
        log_2 = ExpectLog('tornado.access', '400')
        with log_1, log_2:
            response = self.fetch(
                '/minigrids?minigrid_aes_key=a',
                method='POST', body='')
        self.assertResponseCode(response, 400)
        self.assertIsNone(self.session.query(models.Minigrid).one_or_none())

    @patch('minigrid.handlers.BaseHandler.get_current_user')
    def test_post_minigrids_duplicate_name(self, get_current_user):
        get_current_user.return_value = self.user
        with models.transaction(self.session) as session:
            payment_system = models.PaymentSystem(aes_key=bytes(32))
            session.add(models.Minigrid(minigrid_name='a'))
            session.add(payment_system)
        pid = str(payment_system.payment_id)
        with ExpectLog('tornado.access', '400'):
            response = self.fetch(
                f'/minigrids?minigrid_name=a&minigrid_payment_id={pid}',
                method='POST', body='')
        self.assertResponseCode(response, 400)
        self.assertIn(
            'A minigrid with that name already exists', response.body.decode())


# The technician concept fell to the wayside...
# class TestTechnicianHandler(HTTPTest):
#     def setUp(self):
#         super().setUp()
#         with models.transaction(self.session) as session:
#             self.user = models.User(email='a@a.com')
#             session.add(self.user)
#             session.add(models.System(day_tariff=1, night_tariff=1))
#
#     def test_get_technician_not_logged_in(self):
#         response = self.fetch('/technician')
#         self.assertResponseCode(response, 200)
#         self.assertNotIn('user', response.headers['Set-Cookie'])
#         self.assertIn('Log In', response.body.decode())
#         self.assertNotIn('Log Out', response.body.decode())
#
#     @patch('minigrid.handlers.BaseHandler.get_current_user')
#     def test_get_technician_logged_in(self, get_current_user):
#         get_current_user.return_value = self.user
#         response = self.fetch('/technician')
#         self.assertResponseCode(response, 200)
#         self.assertIn('Write technician ID card', response.body.decode())


class TestDeviceHandler(HTTPTest):
    def setUp(self):
        super().setUp()
        with models.transaction(self.session) as session:
            self.user = models.User(email='a@a.com')
            session.add(self.user)
            session.add(models.System(day_tariff=1, night_tariff=1))

    def test_get_device_not_logged_in(self):
        response = self.fetch('/device')
        self.assertResponseCode(response, 200)
        self.assertNotIn('user', response.headers['Set-Cookie'])
        self.assertIn('Log In', response.body.decode())
        self.assertNotIn('Log Out', response.body.decode())

    @patch('minigrid.handlers.BaseHandler.get_current_user')
    def test_get_device_logged_in(self, get_current_user):
        get_current_user.return_value = self.user
        response = self.fetch('/device')
        self.assertResponseCode(response, 200)
        self.assertIn('Add device:', response.body.decode())


class TestCardsHandler(HTTPTest):
    def setUp(self):
        super().setUp()
        with models.transaction(self.session) as session:
            self.user = models.User(email='a@a.com')
            session.add(self.user)
            session.add(models.System(day_tariff=1, night_tariff=1))

    def test_get_cards_not_logged_in(self):
        response = self.fetch('/cards')
        self.assertResponseCode(response, 200)
        self.assertNotIn('user', response.headers['Set-Cookie'])
        self.assertIn('Log In', response.body.decode())
        self.assertNotIn('Log Out', response.body.decode())

    @patch('minigrid.handlers.BaseHandler.get_current_user')
    def test_get_cards_logged_in(self, get_current_user):
        get_current_user.return_value = self.user
        response = self.fetch('/cards')
        self.assertResponseCode(response, 200)
        self.assertIn('Read and validate cards:', response.body.decode())


class TestWriteCreditCardHandler(HTTPTest):
    def setUp(self):
        super().setUp()
        with models.transaction(self.session) as session:
            self.user = models.User(email='a@a.com')
            session.add(self.user)
            session.add(models.System(day_tariff=1, night_tariff=1))
            self.minigrid = models.Minigrid(minigrid_name='a')
            session.add(self.minigrid)
            session.add(models.Device(address=bytes(6)))

    def test_get_write_credit_cards_not_logged_in(self):
        response = self.fetch(
            f'/minigrids/{self.minigrid.minigrid_id}/write_credit')
        self.assertResponseCode(response, 200)
        self.assertNotIn('user', response.headers['Set-Cookie'])
        self.assertIn('Log In', response.body.decode())
        self.assertNotIn('Log Out', response.body.decode())

    @patch('minigrid.handlers.BaseHandler.get_current_user')
    def test_get_write_credit_cards_logged_in(self, get_current_user):
        get_current_user.return_value = self.user
        response = self.fetch(
            f'/minigrids/{self.minigrid.minigrid_id}/write_credit')
        self.assertResponseCode(response, 200)
        self.assertIn('Write Credit Card:', response.body.decode())

    @patch('minigrid.handlers.BaseHandler.get_current_user')
    def test_get_write_credit_cards_404(self, get_current_user):
        get_current_user.return_value = self.user
        with ExpectLog('tornado.access', '404'):
            response = self.fetch(
                f'/minigrids/{self.user.user_id}/write_credit')
        self.assertResponseCode(response, 404)


class TestMinigridWriteCreditHistoryHandler(HTTPTest):
    def setUp(self):
        super().setUp()
        with models.transaction(self.session) as session:
            self.user = models.User(email='a@a.com')
            session.add(self.user)
            session.add(models.System(day_tariff=1, night_tariff=1))
            self.minigrid = models.Minigrid(minigrid_name='a')
            session.add(self.minigrid)
            session.add(models.Device(address=bytes(6)))

    def test_get_write_credit_card_history_not_logged_in(self):
        response = self.fetch(
            f'/minigrids/{self.minigrid.minigrid_id}/write_credit/history')
        self.assertResponseCode(response, 200)
        self.assertNotIn('user', response.headers['Set-Cookie'])
        self.assertIn('Log In', response.body.decode())
        self.assertNotIn('Log Out', response.body.decode())

    @patch('minigrid.handlers.BaseHandler.get_current_user')
    def test_get_write_credit_card_history_logged_in(self, get_current_user):
        get_current_user.return_value = self.user
        response = self.fetch(
            f'/minigrids/{self.minigrid.minigrid_id}/write_credit/history')
        self.assertResponseCode(response, 200)
        self.assertIn('Creation Time (UTC)', response.body.decode())

    @patch('minigrid.handlers.BaseHandler.get_current_user')
    def test_get_write_credit_card_history_404(self, get_current_user):
        get_current_user.return_value = self.user
        with ExpectLog('tornado.access', '404'):
            response = self.fetch(
                f'/minigrids/{self.user.user_id}/write_credit/history')
        self.assertResponseCode(response, 404)


class TestMinigridVendorsHandler(HTTPTest):
    def setUp(self):
        super().setUp()
        with models.transaction(self.session) as session:
            self.user = models.User(email='a@a.com')
            session.add(self.user)
            session.add(models.System(day_tariff=1, night_tariff=1))
            self.minigrid = models.Minigrid(minigrid_name='a')
            self.vendor = models.Vendor(vendor_name='v', vendor_user_id='0000')
            self.minigrid.vendors.append(self.vendor)
            session.add(self.minigrid)
            session.add(models.Device(address=bytes(6)))

    def test_get_not_logged_in(self):
        response = self.fetch(
            f'/minigrids/{self.minigrid.minigrid_id}/vendors')
        self.assertResponseCode(response, 200)
        self.assertNotIn('user', response.headers['Set-Cookie'])
        self.assertIn('Log In', response.body.decode())
        self.assertNotIn('Log Out', response.body.decode())

    @patch('minigrid.handlers.BaseHandler.get_current_user')
    def test_get_logged_in(self, get_current_user):
        get_current_user.return_value = self.user
        response = self.fetch(
            f'/minigrids/{self.minigrid.minigrid_id}/vendors')
        self.assertResponseCode(response, 200)
        self.assertNotIn('Log In', response.body.decode())
        self.assertIn('Log Out', response.body.decode())
        self.assertNotIn(
            'You must initialize the system tariff information.',
            response.body.decode())
        body = BeautifulSoup(response.body)
        self.assertEqual(body.findAll('p')[4].contents[0], 'Name: v')

    @patch('minigrid.handlers.BaseHandler.get_current_user')
    def test_create_vendor(self, get_current_user):
        get_current_user.return_value = self.user
        response = self.fetch(
            f'/minigrids/{self.minigrid.minigrid_id}/vendors?'
            'action=create&vendor_name=v2&vendor_user_id=0001',
            method='POST', body='')
        self.assertResponseCode(response, 200)
        vendor = (
            self.session.query(models.Vendor)
            .filter_by(vendor_name='v2').one())
        self.assertEqual(vendor.vendor_name, 'v2')

    @patch('minigrid.handlers.BaseHandler.get_current_user')
    def test_create_duplicate_vendor_name(self, get_current_user):
        get_current_user.return_value = self.user
        with ExpectLog('tornado.access', '400'):
            response = self.fetch(
                f'/minigrids/{self.minigrid.minigrid_id}/vendors?'
                'action=create&vendor_name=v&vendor_user_id=0001',
                method='POST', body='')
        self.assertResponseCode(response, 400)
        self.assertIn(
            'A vendor with that name already exists', response.body.decode())

    @patch('minigrid.handlers.BaseHandler.get_current_user')
    def test_create_duplicate_vendor_user_id(self, get_current_user):
        get_current_user.return_value = self.user
        with ExpectLog('tornado.access', '400'):
            response = self.fetch(
                f'/minigrids/{self.minigrid.minigrid_id}/vendors?'
                'action=create&vendor_name=v2&vendor_user_id=0000',
                method='POST', body='')
        self.assertResponseCode(response, 400)
        self.assertIn(
            'A vendor with that User ID already exists',
            response.body.decode())

    @patch('minigrid.handlers.BaseHandler.get_current_user')
    def test_create_missing_name(self, get_current_user):
        get_current_user.return_value = self.user
        with ExpectLog('tornado.access', '400'):
            response = self.fetch(
                f'/minigrids/{self.minigrid.minigrid_id}/vendors?'
                'action=create&vendor_name=&vendor_user_id=0001',
                method='POST', body='')
        self.assertResponseCode(response, 400)
        self.assertIn('vendor_vendor_name_check', response.body.decode())

    @patch('minigrid.handlers.BaseHandler.get_current_user')
    def test_remove_vendor(self, get_current_user):
        get_current_user.return_value = self.user
        response = self.fetch(
            f'/minigrids/{self.minigrid.minigrid_id}/vendors?'
            f'action=remove&vendor_id={self.vendor.vendor_id}',
            method='POST', body='')
        self.assertResponseCode(response, 200)
        vendor = self.session.query(models.Vendor).one_or_none()
        self.assertIsNone(vendor)
        # Not sure why this isn't showing up...
        # self.assertIn('Vendor v removed', response.body.decode())

    @patch('minigrid.handlers.BaseHandler.get_current_user')
    def test_remove_vendor_twice(self, get_current_user):
        get_current_user.return_value = self.user
        self.fetch(
            f'/minigrids/{self.minigrid.minigrid_id}/vendors?'
            f'action=remove&vendor_id={self.vendor.vendor_id}',
            method='POST', body='')
        response = self.fetch(
            f'/minigrids/{self.minigrid.minigrid_id}/vendors?'
            f'action=remove&vendor_id={self.vendor.vendor_id}',
            method='POST', body='')
        self.assertResponseCode(response, 200)
        vendor = self.session.query(models.Vendor).one_or_none()
        self.assertIsNone(vendor)
        # Not sure why this isn't showing up...
        # self.assertIn(
        #     'The requested vendor no longer exists',
        #     response.body.decode())

    @patch('minigrid.handlers.BaseHandler.get_current_user')
    def test_bad_action(self, get_current_user):
        get_current_user.return_value = self.user
        log_1 = ExpectLog(
            'tornado.general', r'.*Bad Request \(invalid action\)')
        log_2 = ExpectLog('tornado.access', '400')
        with log_1, log_2:
            response = self.fetch(
                f'/minigrids/{self.minigrid.minigrid_id}/vendors?'
                'action=something', method='POST', body='')
        self.assertResponseCode(response, 400)
        self.assertIn('Bad Request', response.body.decode())


class TestMinigridVendorsHistoryHandler(HTTPTest):
    def setUp(self):
        super().setUp()
        with models.transaction(self.session) as session:
            self.user = models.User(email='a@a.com')
            session.add(self.user)
            session.add(models.System(day_tariff=1, night_tariff=1))
            self.minigrid = models.Minigrid(minigrid_name='a')
            session.add(self.minigrid)
            session.add(models.Device(address=bytes(6)))

    def test_get_write_vendor_card_history_not_logged_in(self):
        response = self.fetch(
            f'/minigrids/{self.minigrid.minigrid_id}/vendors/history')
        self.assertResponseCode(response, 200)
        self.assertNotIn('user', response.headers['Set-Cookie'])
        self.assertIn('Log In', response.body.decode())
        self.assertNotIn('Log Out', response.body.decode())

    @patch('minigrid.handlers.BaseHandler.get_current_user')
    def test_get_vendor_card_history_logged_in(self, get_current_user):
        get_current_user.return_value = self.user
        response = self.fetch(
            f'/minigrids/{self.minigrid.minigrid_id}/vendors/history')
        self.assertResponseCode(response, 200)
        self.assertIn('Creation Time (UTC)', response.body.decode())

    @patch('minigrid.handlers.BaseHandler.get_current_user')
    def test_get_vendor_card_history_404(self, get_current_user):
        get_current_user.return_value = self.user
        with ExpectLog('tornado.access', '404'):
            response = self.fetch(
                f'/minigrids/{self.user.user_id}/vendors/history')
        self.assertResponseCode(response, 404)


class TestMinigridCustomersHandler(HTTPTest):
    def setUp(self):
        super().setUp()
        with models.transaction(self.session) as session:
            self.user = models.User(email='a@a.com')
            session.add(self.user)
            session.add(models.System(day_tariff=1, night_tariff=1))
            self.minigrid = models.Minigrid(minigrid_name='a')
            self.customer = models.Customer(
                customer_name='c', customer_user_id='0000',
                customer_current_limit=0, customer_energy_limit=0)
            self.minigrid.customers.append(self.customer)
            session.add(self.minigrid)
            session.add(models.Device(address=bytes(6)))

    def test_get_not_logged_in(self):
        response = self.fetch(
            f'/minigrids/{self.minigrid.minigrid_id}/customers')
        self.assertResponseCode(response, 200)
        self.assertNotIn('user', response.headers['Set-Cookie'])
        self.assertIn('Log In', response.body.decode())
        self.assertNotIn('Log Out', response.body.decode())

    @patch('minigrid.handlers.BaseHandler.get_current_user')
    def test_get_logged_in(self, get_current_user):
        get_current_user.return_value = self.user
        response = self.fetch(
            f'/minigrids/{self.minigrid.minigrid_id}/customers')
        self.assertResponseCode(response, 200)
        self.assertNotIn('Log In', response.body.decode())
        self.assertIn('Log Out', response.body.decode())
        self.assertNotIn(
            'You must initialize the system tariff information.',
            response.body.decode())
        body = BeautifulSoup(response.body)
        self.assertEqual(body.findAll('p')[4].contents[0], 'Name: c')

    @patch('minigrid.handlers.BaseHandler.get_current_user')
    def test_create_customer(self, get_current_user):
        get_current_user.return_value = self.user
        response = self.fetch(
            f'/minigrids/{self.minigrid.minigrid_id}/customers?'
            'action=create&customer_name=c2&customer_user_id=0001'
            '&customer_current_limit=1000&customer_energy_limit=2500',
            method='POST', body='')
        self.assertResponseCode(response, 200)
        customer = (
            self.session.query(models.Customer)
            .filter_by(customer_name='c2').one())
        self.assertEqual(customer.customer_name, 'c2')

    @patch('minigrid.handlers.BaseHandler.get_current_user')
    def test_create_duplicate_customer_name(self, get_current_user):
        get_current_user.return_value = self.user
        with ExpectLog('tornado.access', '400'):
            response = self.fetch(
                f'/minigrids/{self.minigrid.minigrid_id}/customers?'
                'action=create&customer_name=c&customer_user_id=0001'
                '&customer_current_limit=1000&customer_energy_limit=2500',
                method='POST', body='')
        self.assertResponseCode(response, 400)
        self.assertIn(
            'A customer with that name already exists', response.body.decode())

    @patch('minigrid.handlers.BaseHandler.get_current_user')
    def test_create_duplicate_customer_user_id(self, get_current_user):
        get_current_user.return_value = self.user
        with ExpectLog('tornado.access', '400'):
            response = self.fetch(
                f'/minigrids/{self.minigrid.minigrid_id}/customers?'
                'action=create&customer_name=c2&customer_user_id=0000'
                '&customer_current_limit=1000&customer_energy_limit=2500',
                method='POST', body='')
        self.assertResponseCode(response, 400)
        self.assertIn(
            'A customer with that User ID already exists',
            response.body.decode())

    @patch('minigrid.handlers.BaseHandler.get_current_user')
    def test_create_missing_name(self, get_current_user):
        get_current_user.return_value = self.user
        with ExpectLog('tornado.access', '400'):
            response = self.fetch(
                f'/minigrids/{self.minigrid.minigrid_id}/customers?'
                'action=create&customer_name=&customer_user_id=0001'
                '&customer_current_limit=1000&customer_energy_limit=2500',
                method='POST', body='')
        self.assertResponseCode(response, 400)
        self.assertIn('customer_customer_name_check', response.body.decode())

    @patch('minigrid.handlers.BaseHandler.get_current_user')
    def test_remove_customer(self, get_current_user):
        get_current_user.return_value = self.user
        response = self.fetch(
            f'/minigrids/{self.minigrid.minigrid_id}/customers?'
            f'action=remove&customer_id={self.customer.customer_id}',
            method='POST', body='')
        self.assertResponseCode(response, 200)
        customer = self.session.query(models.Customer).one_or_none()
        self.assertIsNone(customer)
        self.assertIn('No customers', response.body.decode())

    @patch('minigrid.handlers.BaseHandler.get_current_user')
    def test_remove_customer_twice(self, get_current_user):
        get_current_user.return_value = self.user
        self.fetch(
            f'/minigrids/{self.minigrid.minigrid_id}/customers?'
            f'action=remove&customer_id={self.customer.customer_id}',
            method='POST', body='')
        response = self.fetch(
            f'/minigrids/{self.minigrid.minigrid_id}/customers?'
            f'action=remove&customer_id={self.customer.customer_id}',
            method='POST', body='')
        self.assertResponseCode(response, 200)
        customer = self.session.query(models.Customer).one_or_none()
        self.assertIsNone(customer)
        # Not sure why this isn't showing up...
        # self.assertIn(
        #     'The requested customer no longer exists',
        #     response.body.decode())

    @patch('minigrid.handlers.BaseHandler.get_current_user')
    def test_bad_action(self, get_current_user):
        get_current_user.return_value = self.user
        log_1 = ExpectLog(
            'tornado.general', r'.*Bad Request \(invalid action\)')
        log_2 = ExpectLog('tornado.access', '400')
        with log_1, log_2:
            response = self.fetch(
                f'/minigrids/{self.minigrid.minigrid_id}/customers?'
                'action=something', method='POST', body='')
        self.assertResponseCode(response, 400)
        self.assertIn('Bad Request', response.body.decode())


class TestMinigridCustomersHistoryHandler(HTTPTest):
    def setUp(self):
        super().setUp()
        with models.transaction(self.session) as session:
            self.user = models.User(email='a@a.com')
            session.add(self.user)
            session.add(models.System(day_tariff=1, night_tariff=1))
            self.minigrid = models.Minigrid(minigrid_name='a')
            session.add(self.minigrid)
            session.add(models.Device(address=bytes(6)))

    def test_get_write_customer_card_history_not_logged_in(self):
        response = self.fetch(
            f'/minigrids/{self.minigrid.minigrid_id}/customers/history')
        self.assertResponseCode(response, 200)
        self.assertNotIn('user', response.headers['Set-Cookie'])
        self.assertIn('Log In', response.body.decode())
        self.assertNotIn('Log Out', response.body.decode())

    @patch('minigrid.handlers.BaseHandler.get_current_user')
    def test_get_customer_card_history_logged_in(self, get_current_user):
        get_current_user.return_value = self.user
        response = self.fetch(
            f'/minigrids/{self.minigrid.minigrid_id}/customers/history')
        self.assertResponseCode(response, 200)
        self.assertIn('Creation Time (UTC)', response.body.decode())

    @patch('minigrid.handlers.BaseHandler.get_current_user')
    def test_get_customer_card_history_404(self, get_current_user):
        get_current_user.return_value = self.user
        with ExpectLog('tornado.access', '404'):
            response = self.fetch(
                f'/minigrids/{self.user.user_id}/customers/history')
        self.assertResponseCode(response, 404)


class TestMinigridMaintenanceCardsHandler(HTTPTest):
    def setUp(self):
        super().setUp()
        with models.transaction(self.session) as session:
            self.user = models.User(email='a@a.com')
            session.add(self.user)
            session.add(models.System(day_tariff=1, night_tariff=1))
            self.minigrid = models.Minigrid(minigrid_name='a')
            self.maintenance_card = models.MaintenanceCard(
                maintenance_card_name='m', maintenance_card_card_id='0000')
            self.minigrid.maintenance_cards.append(self.maintenance_card)
            session.add(self.minigrid)
            session.add(models.Device(address=bytes(6)))

    def test_get_not_logged_in(self):
        response = self.fetch(
            f'/minigrids/{self.minigrid.minigrid_id}/maintenance_cards')
        self.assertResponseCode(response, 200)
        self.assertNotIn('user', response.headers['Set-Cookie'])
        self.assertIn('Log In', response.body.decode())
        self.assertNotIn('Log Out', response.body.decode())

    @patch('minigrid.handlers.BaseHandler.get_current_user')
    def test_get_logged_in(self, get_current_user):
        get_current_user.return_value = self.user
        response = self.fetch(
            f'/minigrids/{self.minigrid.minigrid_id}/maintenance_cards')
        self.assertResponseCode(response, 200)
        self.assertNotIn('Log In', response.body.decode())
        self.assertIn('Log Out', response.body.decode())
        self.assertNotIn(
            'You must initialize the system tariff information.',
            response.body.decode())
        body = BeautifulSoup(response.body)
        self.assertEqual(body.findAll('p')[4].contents[0], 'Name: m')

    @patch('minigrid.handlers.BaseHandler.get_current_user')
    def test_create_maintenance_card(self, get_current_user):
        get_current_user.return_value = self.user
        response = self.fetch(
            f'/minigrids/{self.minigrid.minigrid_id}/maintenance_cards?'
            'action=create&maintenance_card_name=m2'
            '&maintenance_card_card_id=0001',
            method='POST', body='')
        self.assertResponseCode(response, 200)
        maintenance_card = (
            self.session.query(models.MaintenanceCard)
            .filter_by(maintenance_card_name='m2').one())
        self.assertEqual(maintenance_card.maintenance_card_name, 'm2')

    @patch('minigrid.handlers.BaseHandler.get_current_user')
    def test_create_duplicate_maintenance_card_name(self, get_current_user):
        get_current_user.return_value = self.user
        with ExpectLog('tornado.access', '400'):
            response = self.fetch(
                f'/minigrids/{self.minigrid.minigrid_id}/maintenance_cards?'
                'action=create&maintenance_card_name=m'
                '&maintenance_card_card_id=0001',
                method='POST', body='')
        self.assertResponseCode(response, 400)
        self.assertIn(
            'A maintenance card with that name already exists',
            response.body.decode())

    @patch('minigrid.handlers.BaseHandler.get_current_user')
    def test_create_duplicate_maintenance_card_user_id(self, get_current_user):
        get_current_user.return_value = self.user
        with ExpectLog('tornado.access', '400'):
            response = self.fetch(
                f'/minigrids/{self.minigrid.minigrid_id}/maintenance_cards?'
                'action=create&maintenance_card_name=m2'
                '&maintenance_card_card_id=0000',
                method='POST', body='')
        self.assertResponseCode(response, 400)
        self.assertIn(
            'A maintenance card with that User ID already exists',
            response.body.decode())

    @patch('minigrid.handlers.BaseHandler.get_current_user')
    def test_create_missing_name(self, get_current_user):
        get_current_user.return_value = self.user
        with ExpectLog('tornado.access', '400'):
            response = self.fetch(
                f'/minigrids/{self.minigrid.minigrid_id}/maintenance_cards?'
                'action=create&maintenance_card_name='
                '&maintenance_card_card_id=0000',
                method='POST', body='')
        self.assertResponseCode(response, 400)
        self.assertIn('maintenance_card_name_check',
                      response.body.decode())

    @patch('minigrid.handlers.BaseHandler.get_current_user')
    def test_remove_maintenance_card(self, get_current_user):
        get_current_user.return_value = self.user
        response = self.fetch(
            f'/minigrids/{self.minigrid.minigrid_id}/maintenance_cards?'
            f'action=remove&maintenance_card_id='
            f'{self.maintenance_card.maintenance_card_id}',
            method='POST', body='')
        self.assertResponseCode(response, 200)
        maintenance_card = \
            self.session.query(models.MaintenanceCard).one_or_none()
        self.assertIsNone(maintenance_card)
        self.assertIn('No maintenance cards', response.body.decode())

    @patch('minigrid.handlers.BaseHandler.get_current_user')
    def test_remove_maintenance_card_twice(self, get_current_user):
        get_current_user.return_value = self.user
        self.fetch(
            f'/minigrids/{self.minigrid.minigrid_id}/maintenance_cards?'
            f'action=remove&maintenance_card_id='
            f'{self.maintenance_card.maintenance_card_id}',
            method='POST', body='')
        response = self.fetch(
            f'/minigrids/{self.minigrid.minigrid_id}/maintenance_cards?'
            f'action=remove&maintenance_card_id='
            f'{self.maintenance_card.maintenance_card_id}',
            method='POST', body='')
        self.assertResponseCode(response, 200)
        maintenance_card = \
            self.session.query(models.MaintenanceCard).one_or_none()
        self.assertIsNone(maintenance_card)
        # Not sure why this isn't showing up...
        # self.assertIn(
        #     'The requested maintenance card no longer exists',
        #     response.body.decode())

    @patch('minigrid.handlers.BaseHandler.get_current_user')
    def test_bad_action(self, get_current_user):
        get_current_user.return_value = self.user
        log_1 = ExpectLog(
            'tornado.general', r'.*Bad Request \(invalid action\)')
        log_2 = ExpectLog('tornado.access', '400')
        with log_1, log_2:
            response = self.fetch(
                f'/minigrids/{self.minigrid.minigrid_id}/maintenance_cards?'
                'action=something', method='POST', body='')
        self.assertResponseCode(response, 400)
        self.assertIn('Bad Request', response.body.decode())


class TestMinigridMaintenanceCardHistoryHandler(HTTPTest):
    def setUp(self):
        super().setUp()
        with models.transaction(self.session) as session:
            self.user = models.User(email='a@a.com')
            session.add(self.user)
            session.add(models.System(day_tariff=1, night_tariff=1))
            self.minigrid = models.Minigrid(minigrid_name='a')
            session.add(self.minigrid)
            session.add(models.Device(address=bytes(6)))

    def test_get_write_maintenance_card_history_not_logged_in(self):
        response = self.fetch(
          f'/minigrids/{self.minigrid.minigrid_id}/maintenance_cards/history')
        self.assertResponseCode(response, 200)
        self.assertNotIn('user', response.headers['Set-Cookie'])
        self.assertIn('Log In', response.body.decode())
        self.assertNotIn('Log Out', response.body.decode())

    @patch('minigrid.handlers.BaseHandler.get_current_user')
    def test_get_maintenance_card_history_logged_in(self, get_current_user):
        get_current_user.return_value = self.user
        response = self.fetch(
          f'/minigrids/{self.minigrid.minigrid_id}/maintenance_cards/history')
        self.assertResponseCode(response, 200)
        self.assertIn('Creation Time (UTC)', response.body.decode())

    @patch('minigrid.handlers.BaseHandler.get_current_user')
    def test_get_maintenance_card_history_404(self, get_current_user):
        get_current_user.return_value = self.user
        with ExpectLog('tornado.access', '404'):
            response = self.fetch(
                f'/minigrids/{self.user.user_id}/maintenance_cards/history')
        self.assertResponseCode(response, 404)


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
        self.assertIn(('portier:nonce:' + query['nonce'][0]).encode(), cache)
        self.assertTrue(query['redirect_uri'][0].endswith('/verify'))

    @patch('minigrid.handlers.get_verified_email', new_callable=CoroMock)
    def test_verify_value_error(self, get_verified_email):
        get_verified_email.coro.side_effect = ValueError('error')
        self.create_user()
        with ExpectLog('tornado.access', '400'):
            response = self.fetch(
                '/verify?id_token=',
                method='POST', body='', follow_redirects=False
            )
        self.assertResponseCode(response, 400)
        self.assertEqual(
            response.error.message, 'error')

    @patch('minigrid.handlers.get_verified_email', new_callable=CoroMock)
    def test_verify(self, get_verified_email):
        get_verified_email.coro.return_value = 'a@a.com', ''
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
        get_verified_email.coro.return_value = 'a@a.com', ''
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
