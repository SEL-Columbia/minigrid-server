"""Handlers for the URL endpoints."""
import time
from binascii import unhexlify
from collections import OrderedDict
from datetime import datetime, timedelta
import secrets
from urllib.parse import urlencode
from uuid import uuid4, UUID

import logging

from asyncio_portier import get_verified_email

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

import redis

from sockjs.tornado import SockJSConnection, SockJSRouter
from sqlalchemy import exists
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.exc import DataError, IntegrityError
from sqlalchemy.orm.exc import NoResultFound, UnmappedInstanceError

from tornado.escape import json_encode, json_decode
import tornado.web
import tornado.ioloop

from minigrid.device_interface import (
    write_maintenance_card_card, erase_card,
    write_vendor_card, write_customer_card, write_credit_card)
import minigrid.error
import minigrid.models as models
from minigrid.options import options

import matplotlib.pyplot as plt
import io
from itertools import islice

plt.switch_backend('Agg')

AES = algorithms.AES
cache = redis.StrictRedis.from_url(options.redis_url)
broker_url = 'https://broker.portier.io'

# cache.config_set('notify-keyspace-events', 'Ex') # not available in fakeRedis
pubsub = cache.pubsub()
pubsub.subscribe("__keyevent@0__:expired")


_card_type_dict = {
    'A': 'Vendor ID Card',
    'B': 'Customer ID Card',
    'C': 'Credit Card',
    'D': 'Maintenance Card',
    'E': 'Blank Card',
}


_secret_value_type = {
    'A': 'Vendor User ID',
    'B': 'Customer User ID',
    'C': 'Credit Amount',
    'D': 'Maintenance Card ID',
    'E': 'Card Type',
}


class BaseHandler(tornado.web.RequestHandler):
    """The base class for all handlers."""

    @property
    def session(self):
        """Database session.

        Use the models.transaction(session) context manager.
        """
        return self.application.session

    def get_current_user(self):
        """Return the signed-in user object or None.

        Available as current_user in templates.
        """
        user_id = self.get_secure_cookie('user')
        if not user_id:
            return None
        return self.session.query(models.User).get(user_id.decode())

    def write_error(self, status_code, **kwargs):
        """Override default behavior for MinigridHTTPError."""
        error = kwargs['exc_info'][1]
        if isinstance(error, minigrid.error.MinigridHTTPError):
            self.set_status(error.status_code, reason=error.reason)
            message = getattr(error, 'message', error.reason)
            self.render(
                error.template_name, message=message, **error.template_kwargs)
            return
        super().write_error(status_code, **kwargs)

    def render(self, *args, **kwargs):
        """Override default render to include a message of None."""
        if 'message' not in kwargs:
            kwargs['message'] = self.get_secure_cookie('message')
            self.clear_cookie('message')
        super().render(*args, **kwargs)

    def redirect(self, url, message=None, **kwargs):
        """Override default redirect to deal with success/fail message."""
        if message is not None:
            self.set_secure_cookie('message', message)
        super().redirect(url, **kwargs)


class ReadCardBaseHandler(BaseHandler):
    """Base class for card-writing handlers."""

    def render(self, *args, **kwargs):
        """Override default render to include cached information."""
        if 'device_active' not in kwargs:
            kwargs['device_active'] = cache.get('device_active')
        if 'received_info' not in kwargs:
            kwargs['received_info'] = cache.get('received_info')
        if 'write_info' not in kwargs:
            kwargs['write_info'] = cache.get('write_info')
        if 'notification' not in kwargs:
            kwargs['notification'] = cache.get('notification')
        if 'card_read_error' not in kwargs:
            kwargs['card_read_error'] = cache.get('card_read_error')
        super().render(*args, **kwargs)


class MainHandler(BaseHandler):
    """Handlers for the site index."""

    def get(self):
        """Render the homepage."""
        if self.current_user:
            system = self.session.query(models.System).one_or_none()
            minigrids = models.get_minigrids(self.session)
            any_devices = self.session.query(
                exists().where(models.Device.address.isnot(None))).scalar()
            self.render(
                'index-minigrid-list.html',
                system=system, minigrids=minigrids, any_devices=any_devices)
            return
        self.render(
            'index-logged-out.html', next_page=self.get_argument('next', '/'))

    def post(self):
        """Send login information to the portier broker."""
        nonce = uuid4().hex
        next_page = self.get_argument('next', '/')
        expiration = timedelta(minutes=15)
        cache.set('portier:nonce:{}'.format(nonce), next_page, expiration)
        query_args = urlencode({
            'login_hint': self.get_argument('email'),
            'scope': 'openid email',
            'nonce': nonce,
            'response_type': 'id_token',
            'response_mode': 'form_post',
            'client_id': options.minigrid_website_url,
            'redirect_uri': options.minigrid_website_url + '/verify'})
        self.redirect(broker_url + '/auth?' + query_args)


class TariffsHandler(BaseHandler):
    """Handlers for tariffs."""

    def _get_value(self, attribute):
        existing_value = getattr(self.system, attribute, None)
        return self.get_argument(attribute, existing_value)

    @tornado.web.authenticated
    def get(self):
        """Display the system tariff information."""
        try:
            system = self.session.query(models.System).one()
        except NoResultFound:
            self.redirect('/')
            return
        self.render('tariffs.html', system=system)

    @tornado.web.authenticated
    def post(self):
        """Upsert system tariff information."""
        self.system = self.session.query(models.System).one_or_none()
        data = {
            'system_id': '1',
            'day_tariff': self._get_value('day_tariff'),
            'day_tariff_start': self._get_value('day_tariff_start'),
            'night_tariff': self._get_value('night_tariff'),
            'night_tariff_start': self._get_value('night_tariff_start')}
        tat = self._get_value('tariff_activation_timestamp')
        if tat:
            data['tariff_activation_timestamp'] = tat
        statement = (
            insert(models.System)
            .values(**data)
            .on_conflict_do_update(index_elements=['system_id'], set_=data))
        try:
            with models.transaction(self.session) as session:
                session.execute(statement)
            message = 'Updated tariff information'
        except (IntegrityError, DataError) as error:
            if 'minigrid_system_check' in error.orig.pgerror:
                message = (
                    'Error: The daytime start hour must be less than'
                    ' the nighttime start hour.')
            elif 'not-null constraint' in error.orig.pgerror:
                message = 'Null value'
            elif 'invalid input syntax' in error.orig.pgerror:
                message = 'Invalid input syntax'
            elif 'check constraint' in error.orig.pgerror:
                message = 'Invalid value'
            else:
                message = ' '.join(error.orig.pgerror.split())
            raise minigrid.error.MinigridHTTPError(
                message, 400, 'tariffs.html', system=self.system)
        self.redirect('/tariffs', message=message)


class MinigridsHandler(BaseHandler):
    """Handlers for minigrids."""

    @tornado.web.authenticated
    def get(self):
        """Redirect to index."""
        self.redirect('/')

    @tornado.web.authenticated
    def post(self):
        """Create a new minigrid model."""
        try:
            with models.transaction(self.session) as session:
                session.add(models.Minigrid(
                    # TODO: remove this!!!
                    # The database should generate IDs
                    minigrid_id=secrets.token_hex(8).encode('ascii').hex(),
                    minigrid_name=self.get_argument('minigrid_name'),
                    minigrid_payment_id=self.get_argument(
                        'minigrid_payment_id')))
        except (IntegrityError, DataError) as error:
            if 'minigrid_name_key' in error.orig.pgerror:
                message = 'A minigrid with that name already exists'
            else:
                message = ' '.join(error.orig.pgerror.split())
            raise minigrid.error.MinigridHTTPError(
                message, 400, 'index-minigrid-list.html',
                system=self.session.query(models.System).one_or_none(),
                any_devices=self.session.query(
                    exists().where(models.Device.address.isnot(None))
                ).scalar(),
                minigrids=models.get_minigrids(session))
        self.redirect('/')


class UsersHandler(BaseHandler):
    """Handlers for user management."""

    @tornado.web.authenticated
    def get(self):
        """Render the view for user management."""
        users = self.session.query(models.User).order_by('email')
        self.render('users.html', users=users)

    @tornado.web.authenticated
    def post(self):
        """Create a new user model."""
        email = self.get_argument('email')
        message = None
        try:
            with models.transaction(self.session) as session:
                session.add(models.User(email=email))
        except IntegrityError as error:
            if 'user_email_check' in error.orig.pgerror:
                message = f'{email} is not a valid e-mail address'
            else:
                message = f'Account for {email} already exists'
        self.redirect('/users', message=message)


# TODO: review the concept of a technician for this system
# class TechnicianHandler(BaseHandler):
#     """Handlers for technician view."""
#
#     @tornado.web.authenticated
#     def get(self):
#         """Render the technician ID writing form."""
#         self.render('technician.html')


class DeviceHandler(BaseHandler):
    """Handlers for device view."""

    @tornado.web.authenticated
    def get(self):
        """Render the device form."""
        Device = models.Device
        devices = self.session.query(Device).order_by(Device.address)
        self.render('device.html', devices=devices)

    @tornado.web.authenticated
    def post(self):
        """Create a new device model."""
        # TODO: raise an error
        # status = 201
        try:
            with models.transaction(self.session) as session:
                session.add(models.Device(
                    address=unhexlify(self.get_argument('device_address'))))
            message = 'Device added'
        except (IntegrityError, DataError) as error:
            message = str(error)
        self.redirect('/device', message=message)


class CardsHandler(ReadCardBaseHandler):
    """Handlers for cards view."""

    @tornado.web.authenticated
    def get(self):
        """Render the cards form."""
        http_protocol = 'https' if options.minigrid_https else 'http'
        self.render('cards.html', http_protocol=http_protocol)

    @tornado.web.authenticated
    def post(self):
        """Erase card."""
        erase_card(self.session, cache)
        self.redirect('/cards')


class MinigridHandler(BaseHandler):
    """Handlers for a minigrid view."""

    @tornado.web.authenticated
    def get(self, minigrid_id):
        """Render the view for a minigrid record."""
        self.render(
            'minigrid.html',
            minigrid=models.get_minigrid(self.session, minigrid_id))

    @tornado.web.authenticated
    def post(self, minigrid_id):
        """Update minigrid payment system ID."""
        try:
            with models.transaction(self.session) as session:
                minigrid = models.get_minigrid(session, minigrid_id)
                minigrid.minigrid_payment_id = self.get_argument(
                    'minigrid_payment_id')
            message = 'Payment ID updated'
        except (IntegrityError, DataError) as error:
            message = str(error)
        self.redirect(f'/minigrids/{minigrid_id}/', message=message)


class MinigridWriteCreditHandler(ReadCardBaseHandler):
    """Handlers for writing credit cards view."""

    @tornado.web.authenticated
    def get(self, minigrid_id):
        """Render the write credit card form."""
        http_protocol = 'https' if options.minigrid_https else 'http'

        self.render(
            'minigrid_write_credit.html',
            minigrid=models.get_minigrid(self.session, minigrid_id),
            http_protocol=http_protocol)

    @tornado.web.authenticated
    def post(self, minigrid_id):
        """Write a credit card for this minigrid."""
        minigrid = models.get_minigrid(self.session, minigrid_id)
        system = self.session.query(models.System).one()
        credit_write = int(self.get_argument('credit_value'))
        write_credit_card(
            self.session,
            cache,
            minigrid.payment_system.aes_key,
            minigrid_id,
            minigrid.payment_system.payment_id,
            credit_write,
            system.day_tariff,
            system.day_tariff_start,
            system.night_tariff,
            system.night_tariff_start,
            system.tariff_creation_timestamp,
            system.tariff_activation_timestamp,
        )
        self.redirect(f'/minigrids/{minigrid_id}/write_credit')


class MinigridWriteCreditHistoryHandler(BaseHandler):
    """Handlers for credit card history view."""

    @tornado.web.authenticated
    def get(self, minigrid_id):
        """Render the credit card history form."""
        http_protocol = 'https' if options.minigrid_https else 'http'

        self.render(
            'minigrid_credit_history.html',
            minigrid=models.get_minigrid(self.session, minigrid_id),
            http_protocol=http_protocol)


class MinigridVendorsHandler(ReadCardBaseHandler):
    """Handlers for vendors view."""

    @tornado.web.authenticated
    def get(self, minigrid_id):
        """Render the vendors view."""
        http_protocol = 'https' if options.minigrid_https else 'http'

        self.render(
            'minigrid_vendors.html',
            http_protocol=http_protocol,
            minigrid=models.get_minigrid(self.session, minigrid_id))

    @tornado.web.authenticated
    def post(self, minigrid_id):
        """Add a vendor."""
        grid = models.get_minigrid(self.session, minigrid_id)
        action = self.get_argument('action')
        user_id_exists = 'vendor_vendor_minigrid_id_vendor_user_id_key'
        http_protocol = 'https' if options.minigrid_https else 'http'
        if action == 'create':
            try:
                with models.transaction(self.session) as session:
                    grid.vendors.append(models.Vendor(
                        vendor_user_id=self.get_argument('vendor_user_id'),
                        vendor_name=self.get_argument('vendor_name')))
            except (IntegrityError, DataError) as error:
                if 'vendor_name_key' in error.orig.pgerror:
                    message = 'A vendor with that name already exists'
                elif user_id_exists in error.orig.pgerror:
                    message = 'A vendor with that User ID already exists'
                else:
                    message = ' '.join(error.orig.pgerror.split())
                raise minigrid.error.MinigridHTTPError(
                    message, 400, 'minigrid_vendors.html', minigrid=grid,
                    http_protocol=http_protocol,  # lazy fix
                )
            self.set_status(201)
        elif action == 'remove':
            vendor_id = self.get_argument('vendor_id')
            try:
                with models.transaction(self.session) as session:
                    vendor = session.query(models.Vendor).get(vendor_id)
                    session.delete(vendor)
                message = f'Vendor {vendor.vendor_name} removed'
            except UnmappedInstanceError:
                message = 'The requested vendor no longer exists'
            self.redirect(f'/minigrids/{minigrid_id}/vendors', message=message)
            return
        elif action == 'write':
            vendor = (
                self.session.query(models.Vendor)
                .get(self.get_argument('vendor_id')))
            try:
                write_vendor_card(
                    self.session,
                    cache,
                    grid.payment_system.aes_key,
                    minigrid_id,
                    grid.payment_system.payment_id,
                    vendor
                )
            except Exception as error:
                logging.error(str(error))
            self.redirect(f'/minigrids/{minigrid_id}/vendors')
            return
        else:
            raise tornado.web.HTTPError(400, 'Bad Request (invalid action)')
        self.redirect(f'/minigrids/{minigrid_id}/vendors')


class MinigridVendorsHistoryHandler(BaseHandler):
    """Handlers for Vendor card history view."""

    @tornado.web.authenticated
    def get(self, minigrid_id):
        """Render the vendor card history form."""
        http_protocol = 'https' if options.minigrid_https else 'http'

        self.render(
            'minigrid_vendor_history.html',
            minigrid=models.get_minigrid(self.session, minigrid_id),
            http_protocol=http_protocol)


class MinigridCustomersHandler(ReadCardBaseHandler):
    """Handlers for customers view."""

    @tornado.web.authenticated
    def get(self, minigrid_id):
        """Render the customers view."""
        http_protocol = 'https' if options.minigrid_https else 'http'

        self.render(
            'minigrid_customers.html',
            http_protocol=http_protocol,
            minigrid=models.get_minigrid(self.session, minigrid_id))

    @tornado.web.authenticated
    def post(self, minigrid_id):
        """Add a customer."""
        grid = models.get_minigrid(self.session, minigrid_id)
        action = self.get_argument('action')
        user_id_exists = 'customer_customer_minigrid_id_customer_user_id_key'
        http_protocol = 'https' if options.minigrid_https else 'http'
        if action == 'create':
            try:
                with models.transaction(self.session) as session:
                    grid.customers.append(models.Customer(
                        customer_user_id=self.get_argument('customer_user_id'),
                        customer_name=self.get_argument('customer_name'),
                        customer_current_limit=self.get_argument(
                            'customer_current_limit'),
                        customer_energy_limit=self.get_argument(
                            'customer_energy_limit')))
            except (IntegrityError, DataError) as error:
                if 'customer_name_key' in error.orig.pgerror:
                    message = 'A customer with that name already exists'
                elif user_id_exists in error.orig.pgerror:
                    message = 'A customer with that User ID already exists'
                else:
                    message = ' '.join(error.orig.pgerror.split())
                raise minigrid.error.MinigridHTTPError(
                    message, 400, 'minigrid_customers.html', minigrid=grid,
                    http_protocol=http_protocol,  # lazy fix
                )
            self.set_status(201)
        elif action == 'remove':
            customer_id = self.get_argument('customer_id')
            try:
                with models.transaction(self.session) as session:
                    customer = session.query(models.Customer).get(customer_id)
                    session.delete(customer)
                message = f'Customer {customer.customer_name} removed'
            except UnmappedInstanceError:
                message = 'The requested customer no longer exists'
            self.redirect(
                f'/minigrids/{minigrid_id}/customers', message=message)
            return
        elif action == 'write':
            customer = (
                self.session.query(models.Customer)
                .get(self.get_argument('customer_id')))
            try:
                write_customer_card(
                    self.session,
                    cache,
                    grid.payment_system.aes_key,
                    minigrid_id,
                    grid.payment_system.payment_id,
                    customer
                )
            except Exception as error:
                logging.error(str(error))
            self.redirect(f'/minigrids/{minigrid_id}/customers')
            return
        else:
            raise tornado.web.HTTPError(400, 'Bad Request (invalid action)')
        self.redirect(f'/minigrids/{minigrid_id}/customers')


class MinigridCustomersHistoryHandler(BaseHandler):
    """Handlers for Customer card history view."""

    @tornado.web.authenticated
    def get(self, minigrid_id):
        """Render the customer card history form."""
        http_protocol = 'https' if options.minigrid_https else 'http'

        self.render(
            'minigrid_customer_history.html',
            minigrid=models.get_minigrid(self.session, minigrid_id),
            http_protocol=http_protocol)


class MinigridMaintenanceCardsHandler(ReadCardBaseHandler):
    """Handlers for maintenance cards view."""

    @tornado.web.authenticated
    def get(self, minigrid_id):
        """Render the maintenance cards view."""
        http_protocol = 'https' if options.minigrid_https else 'http'

        self.render(
            'minigrid_maintenance_cards.html',
            http_protocol=http_protocol,
            minigrid=models.get_minigrid(self.session, minigrid_id))

    @tornado.web.authenticated
    def post(self, minigrid_id):
        """Add a maintenance card."""
        grid = models.get_minigrid(self.session, minigrid_id)
        action = self.get_argument('action')
        # variable shortened should be fixed
        card_name_exists = (
            'maintenance_card_mc_minigrid_id_maintenance_card_name_key'
        )
        # variable shortened should be fixed
        card_id_exists = (
            'maintenance_card_mc_minigrid_id_maintenance_card_card_id_key'
        )
        http_protocol = 'https' if options.minigrid_https else 'http'
        if action == 'create':
            try:
                with models.transaction(self.session) as session:
                    mcci = self.get_argument('maintenance_card_card_id')
                    mcn = self.get_argument('maintenance_card_name')
                    grid.maintenance_cards.append(models.MaintenanceCard(
                        maintenance_card_card_id=mcci,
                        maintenance_card_name=mcn))
            except (IntegrityError, DataError) as error:
                if card_name_exists in error.orig.pgerror:
                    message = (
                        'A maintenance card with that name already exists')
                elif card_id_exists in error.orig.pgerror:
                    message = (
                        'A maintenance card with that User ID already exists')
                else:
                    message = ' '.join(error.orig.pgerror.split())
                raise minigrid.error.MinigridHTTPError(
                    message, 400, 'minigrid_maintenance_cards.html',
                    minigrid=grid,
                    http_protocol=http_protocol,  # lazy fix
                )
            self.set_status(201)
        elif action == 'remove':
            maintenance_card_id = self.get_argument('maintenance_card_id')
            try:
                with models.transaction(self.session) as session:
                    maintenance_card = (
                        session.query(models.MaintenanceCard)
                        .get(maintenance_card_id))
                    session.delete(maintenance_card)
                message = (
                    'Maintenance card'
                    ' {maintenance_card.maintenance_card_name} removed')
            except UnmappedInstanceError:
                message = 'The requested maintenance_card no longer exists'
            self.redirect(
                f'/minigrids/{minigrid_id}/maintenance_cards', message=message)
            return
        elif action == 'write':
            maintenance_card = (
                self.session.query(models.MaintenanceCard)
                .get(self.get_argument('maintenance_card_id')))
            try:
                write_maintenance_card_card(
                    self.session,
                    cache,
                    grid.payment_system.aes_key,
                    minigrid_id,
                    grid.payment_system.payment_id,
                    maintenance_card
                )
            except Exception as error:
                logging.error(str(error))
            self.redirect(f'/minigrids/{minigrid_id}/maintenance_cards')
            return
        else:
            raise tornado.web.HTTPError(400, 'Bad Request (invalid action)')
        self.redirect(f'/minigrids/{minigrid_id}/maintenance_cards')


class MinigridMaintenanceHistoryHandler(BaseHandler):
    """Handlers for Maintenance card history view."""

    @tornado.web.authenticated
    def get(self, minigrid_id):
        """Render the maintenance card history form."""
        http_protocol = 'https' if options.minigrid_https else 'http'

        self.render(
            'minigrid_maintenance_history.html',
            minigrid=models.get_minigrid(self.session, minigrid_id),
            http_protocol=http_protocol)


class VerifyLoginHandler(BaseHandler):
    """Handlers for portier verification."""

    def check_xsrf_cookie(self):
        """Disable XSRF check.

        OpenID doesn't reply with _xsrf header.
        https://github.com/portier/demo-rp/issues/10
        """
        pass

    async def post(self):
        """Verify the response from the portier broker."""
        if 'error' in self.request.arguments:
            error = self.get_argument('error')
            description = self.get_argument('error_description')
            raise minigrid.error.LoginError(
                reason=f'Broker Error: {error}: {description}')
        token = self.get_argument('id_token')
        try:
            email, next_page = await get_verified_email(
                broker_url,
                token,
                options.minigrid_website_url,
                broker_url,
                cache)
        except ValueError as exc:
            raise minigrid.error.LoginError(
                reason=f'ValueError: {exc}')
        try:
            user = (
                self.session
                .query(models.User)
                .filter_by(email=email)
                .one())
        except NoResultFound:
            raise minigrid.error.LoginError(
                reason=f'There is no account for {email}')
        self.set_secure_cookie(
            'user', str(user.user_id),
            httponly=True, secure=options.minigrid_https)
        self.redirect(next_page)


class LogoutHandler(BaseHandler):
    """Handlers for logging out."""

    def get(self):
        """Render the (technically unnecessary) logout page."""
        self.render('logout.html')

    def post(self):
        """Delete the user cookie, which is httponly."""
        self.clear_cookie('user')
        self.redirect('/')


def _decrypt(cipher, data):
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(data) + decryptor.finalize()
    checksum = sum(plaintext[:-1]) & 0xFF
    if checksum != plaintext[-1]:
        raise minigrid.error.CardReadError(
            'Checksum error in encrypted data. Try reading the card again.')
    return plaintext


def _user_or_maintenance_card(binary):
    result = OrderedDict()
    # result[3] = binary[183:273].decode('ascii')
    # result[4] = binary[274:].decode('ascii')
    return result


def _credit_card(session, cipher, binary, credit_card_id, minigrid_id):
    result = OrderedDict()
    # raw_sector_3 = unhexlify(binary[183:273])
    # logging.info(f'Sector 3: {raw_sector_3}')
    # result[3] contains tariff information
    # result[3] = _decrypt(cipher, unhexlify(binary[183:273])).hex()
    raw_sector_4 = unhexlify(binary[274:])
    # logging.info(f'Raw Sector 4: {raw_sector_4}')
    if not any(raw_sector_4):
        return result
    sector_4 = raw_sector_4.split(b'###')[0][:-2]
    logging.info(f'Sector 4: {sector_4}')
    # If card has been used...
    record_timestamp = datetime.fromtimestamp(
        int(sector_4[4:14].decode('ascii'))).isoformat()
    result['Timestamp of Recorded Data'] = record_timestamp
    meter_records = sector_4[15:].decode('ascii').split()
    logging.info(f'meter_records: {meter_records}')
    for record in meter_records:
        meter_id, usage, credit = record.split(',')
        with models.transaction(session) as tx_session:
            tx_session.add(models.SystemHistory(
                sh_credit_card_id=credit_card_id,
                sh_meter_id=meter_id,
                sh_meter_energy_usage=usage,
                sh_meter_credit=credit,
                sh_record_timestamp=record_timestamp,
                sh_minigrid_id=minigrid_id,
            ))
    return result


def _pack_into_dict(session, binary):
    # TODO: here there be dragons...
    import logging
    logging.info(f'Card Contents: {binary}')
    try:
        # Checks device address in first 12 characters
        device_address = unhexlify(binary[:12])
        logging.info(f'Device Address: {device_address}')
        device_exists = session.query(
            exists().where(models.Device.address == device_address)).scalar()
    except Exception as error:
        logging.error(str(error))
        device_exists = False
    if not device_exists:  # TODO: new error class
        raise tornado.web.HTTPError(
            400, 'bad device id {}'.format(binary[:12]))
    binary = binary[12:]  # Remove device address form binary
    result = OrderedDict()
    result['Connected Device'] = device_address.hex()
    # Is it safe to assume that sector 1 is always first? I hope so
    # Sector label is one character, ignore it, take 90 after as sector 1
    sector_1 = unhexlify(binary[1:91])
    # logging.info(f'Sector 1: {sector_1}')
    # Use this for the future... displaying in the UI
    system_id = sector_1[:2].decode('ascii')
    # application_id = sector_1[2:4]
    if system_id == 'up':
        logging.info(f'Operator Box is {system_id}')
        return json_encode(result)
    else:
        cache.set('device_active', 1, 10)
        cache.set('received_info', json_encode(result), 10)
    card_type = sector_1[4:5].decode('ascii')
    logging.info(f'Card Type: {card_type}')
    try:
        result['Card Type'] = _card_type_dict[card_type]
    except KeyError:
        if card_type == '\x00':
            found = OrderedDict()
            found['Card Type'] = 'Blank Card'
            found['Connected Device'] = device_address.hex()
            cache.set('received_info', json_encode(found), 10)
            raise minigrid.error.CardReadError('This card appears blank')
        raise minigrid.error.CardReadError(
            f'This card appears to have the invalid card type {card_type}')
    # offset = sector_1[5:6]
    # length = sector_1[6:8]
    card_produced_time = sector_1[8:12]
    logging.info(f'Card Produce Time Unencrypted: {card_produced_time}')
    result['Card Creation Time'] = datetime.fromtimestamp(
        int.from_bytes(card_produced_time, 'big')).isoformat()
    card_last_read_time = sector_1[12:16]
    logging.info(f'Card Last Read Time: {card_last_read_time}')
    result['Card Last Read Time'] = datetime.fromtimestamp(
        int.from_bytes(card_last_read_time, 'big')).isoformat()
    payment_id = sector_1[16:32].hex()
    payment_system = session.query(models.PaymentSystem).get(payment_id)
    # TODO: Special case all zeroes
    if payment_system is None:
        raise minigrid.error.CardReadError(f'No device with id {payment_id}')
    result['Payment System ID'] = payment_system.payment_id
    key = payment_system.aes_key
    cipher = Cipher(AES(key), modes.ECB(), backend=default_backend())
    sector_2_enc = unhexlify(binary[92:156])
    # logging.info(f'Sector 2 Encrypted: {sector_2_enc}')
    sector_2 = _decrypt(cipher, sector_2_enc)
    # logging.info(f'Sector 2: {sector_2}')
    raw_secret_value = sector_2[:4]
    if card_type == 'C':
        secret_value = int.from_bytes(raw_secret_value, 'big')
        card_produce_time = datetime.fromtimestamp(
            int.from_bytes(sector_2[20:24], 'big'))
        logging.info(f'Card Produce Time Encrypted: {card_produce_time}')
        result['Card Creation Time'] = card_produce_time.isoformat()
        current_timestamp = datetime.now()
        delta = current_timestamp - card_produce_time
        if delta.days > 90:
            result['Expiration status'] = f'Expired {delta.days - 90} days ago'
        else:
            result['Expiration status'] = (
                f'Valid for {90 - delta.days} more days')
    else:
        secret_value = raw_secret_value.decode('ascii')
    result[_secret_value_type[card_type]] = secret_value
    if card_type == 'B':
        result['Current Limit (mA)'] = int.from_bytes(sector_2[20:24], 'big')
        result['Energy Limit (Wh)'] = int.from_bytes(sector_2[24:28], 'big')
    if card_type in {'A', 'B', 'D'}:
        result['Minigrid ID'] = str(UUID(bytes=sector_2[4:20]))
        specific_data = _user_or_maintenance_card(binary)
    elif card_type == 'C':
        cc_id = str(UUID(bytes=sector_2[4:20]))
        result['Credit Card ID'] = cc_id
        minigrids = models.get_minigrids(session)
        minigrid_id = ''
        for mg in minigrids:
            for credit_card_history in mg.credit_card_history:
                if cc_id == str(credit_card_history.credit_card_id):
                    minigrid_id = mg.minigrid_id
                    break
            if str(minigrid_id) == str(mg.minigrid_id):
                break
        specific_data = _credit_card(session, cipher, binary, cc_id,
                                     minigrid_id)
    else:
        raise tornado.web.HTTPError(400, f'bad card type {card_type}')
    if card_type == 'C':
        application_flag = sector_1[32:33].hex()
        logging.info(f'Application Flag: {application_flag}')
        if application_flag == '00':
            result['Credit Status'] = 'Unused'
        elif application_flag == '01':
            result['Credit Status'] = 'Previously Used'
    result.update(specific_data)
    return json_encode(result)


def _verify_written_card(session):
    # Check if a card has actually been written by reading it
    # notify on success or failure
    notify = OrderedDict()
    try:
        expire_message = pubsub.get_message()
        if expire_message:
            logging.info(f'PubSub Notification: {expire_message["data"]}')
            if expire_message["data"] == b'write_info':
                notify['notification'] = 'Error Writing Card'
                notify['type'] = 'alert-danger'
                cache.set('notification', json_encode(notify), 10)
                return
        # -2 on pttl not set, expired, or deleted
        # logging.info(f'PubSub pttl(write_info): {cache.pttl("write_info")}')
    except Exception as error:
        logging.error(str(error))
    if cache.get('write_info') and cache.get('received_info'):
        write_result = json_decode(cache.get('write_info'))
        device_info = json_decode(cache.get('received_info'))
    else:
        return
    try:
        card_type = device_info['Card Type']
        write_card_type = write_result['card_type']
    except NameError:
        return
    if card_type != write_card_type:
        return
    for type, value in _card_type_dict.items():
        if value == card_type:
            logging.info(f'Verify Written Card: {type}')
            cached_marker = device_info[_secret_value_type[type]]
            if type == 'A':  # Vendor
                vendor_id_write = write_result['user_id']
                creation_time_write = write_result['creation_time']
                minigrid_id_write = write_result['minigrid_id']
                cached_creation_time = device_info['Card Creation Time']
                cached_minigrid_id = device_info['Minigrid ID']
                logging.info(f'cached_marker: {cached_marker}')
                logging.info(f'vendor_id_write: {vendor_id_write}')
                logging.info(f'cached_creation_time: {cached_creation_time}')
                logging.info(f'creation_time_write: {creation_time_write}')
                logging.info(f'cached_minigrid_id: {cached_minigrid_id}')
                logging.info(f'minigrid_id_write: {minigrid_id_write}')
                if cached_marker == vendor_id_write and \
                   cached_creation_time == creation_time_write and \
                   cached_minigrid_id == minigrid_id_write:
                    notify['notification'] = 'Vendor Card Written'
                    notify['type'] = 'alert-success'
                    cache.set('notification', json_encode(notify), 10)
                    logging.info(f'Vendor Card Written: {cached_marker}')
                    with models.transaction(session) as tx_session:
                        tx_session.add(models.VendorCardHistory(
                            vendor_card_minigrid_id=minigrid_id_write,
                            vendor_card_vendor_id=write_result['vendor_id'],
                            vendor_card_user_id=vendor_id_write,
                        ))
                    cache.delete('write_info')
            elif type == 'B':  # Customer
                customer_id_write = write_result['user_id']
                creation_time_write = write_result['creation_time']
                minigrid_id_write = write_result['minigrid_id']
                cached_creation_time = device_info['Card Creation Time']
                cached_minigrid_id = device_info['Minigrid ID']
                logging.info(f'cached_marker: {cached_marker}')
                logging.info(f'customer_id_write: {customer_id_write}')
                logging.info(f'cached_creation_time: {cached_creation_time}')
                logging.info(f'creation_time_write: {creation_time_write}')
                logging.info(f'cached_minigrid_id: {cached_minigrid_id}')
                logging.info(f'minigrid_id_write: {minigrid_id_write}')
                if cached_marker == customer_id_write and \
                   cached_creation_time == creation_time_write and \
                   cached_minigrid_id == minigrid_id_write:
                    notify['notification'] = 'Customer Card Written'
                    notify['type'] = 'alert-success'
                    cache.set('notification', json_encode(notify), 10)
                    logging.info(f'Customer Card Written: {cached_marker}')
                    with models.transaction(session) as tx_session:
                        tx_session.add(models.CustomerCardHistory(
                         customer_card_minigrid_id=minigrid_id_write,
                         customer_card_customer_id=write_result['customer_id'],
                         customer_card_user_id=customer_id_write,
                        ))
                    cache.delete('write_info')
            elif type == 'C':  # Credit
                credit_write = write_result['credit_amount']
                credit_card_id_write = write_result['credit_card_id']
                cached_credit_card_id = device_info['Credit Card ID']
                if cached_marker == credit_write and \
                   cached_credit_card_id == credit_card_id_write:
                    notify['notification'] = 'Credit Card Written'
                    notify['type'] = 'alert-success'
                    cache.set('notification', json_encode(notify), 10)
                    logging.info(f'Credit Card Written: {cached_marker}')
                    data = {
                        'credit_card_id': write_result['credit_card_id'],
                        'credit_minigrid_id': write_result['minigrid_id'],
                        'credit_amount': write_result['credit_amount'],
                        'credit_day_tariff': write_result['day_tariff'],
                        'credit_day_tariff_start':
                            write_result['day_tariff_start'],
                        'credit_night_tariff': write_result['night_tariff'],
                        'credit_night_tariff_start':
                            write_result['night_tariff_start'],
                        'credit_tariff_creation_timestamp':
                            write_result['tariff_creation_timestamp'],
                        'credit_tariff_activation_timestamp':
                            write_result['tariff_activation_timestamp'],
                    }
                    statement = (
                        insert(models.CreditCardHistory)
                        .values(**data)
                        .on_conflict_do_nothing())
                    with models.transaction(session) as tx_session:
                        tx_session.execute(statement)
                    cache.delete('write_info')
            elif type == 'D':  # Maintenance
                maintenance_id_write = write_result['maintenance_id']
                creation_time_write = write_result['creation_time']
                minigrid_id_write = write_result['minigrid_id']
                cached_creation_time = device_info['Card Creation Time']
                cached_minigrid_id = device_info['Minigrid ID']
                logging.info(f'cached_marker: {cached_marker}')
                logging.info(f'maintenance_id_write: {maintenance_id_write}')
                logging.info(f'cached_creation_time: {cached_creation_time}')
                logging.info(f'creation_time_write: {creation_time_write}')
                logging.info(f'cached_minigrid_id: {cached_minigrid_id}')
                logging.info(f'minigrid_id_write: {minigrid_id_write}')
                if cached_marker == maintenance_id_write and \
                   cached_creation_time == creation_time_write and \
                   cached_minigrid_id == minigrid_id_write:
                    notify['notification'] = 'Maintenance Card Written'
                    notify['type'] = 'alert-success'
                    cache.set('notification', json_encode(notify), 10)
                    logging.info(f'Maintenance Card Written: {cached_marker}')
                    with models.transaction(session) as tx_session:
                        mccid = write_result['mc_maintenance_card_id']
                        mcid = write_result['maintenance_id']
                        tx_session.add(models.MaintenanceCardHistory(
                            mc_minigrid_id=minigrid_id_write,
                            mc_maintenance_card_id=mccid,
                            mc_maintenance_card_card_id=mcid,
                        ))
                    cache.delete('write_info')
            elif type == 'E':  # Blank card
                future = write_result['future_time']
                logging.info(f'future: {future}')
                if int(future) > int(time.time()):
                    notify['notification'] = 'Card Blank'
                    notify['type'] = 'alert-success'
                    cache.set('notification', json_encode(notify), 10)
                    logging.info('Card Erased')
                    cache.delete('write_info')
            else:
                # Error case for card type
                notify['notification'] = 'Invalid Card Type'
                notify['type'] = 'alert-danger'
                logging.info(f'Invalid Card Type: {type}')
                cache.delete('write_info')


class DeviceInfoHandler(BaseHandler):
    """Handlers for the operator module."""

    def check_xsrf_cookie(self):
        """Disable XSRF check.

        OpenID doesn't reply with _xsrf header.
        https://github.com/portier/demo-rp/issues/10
        """
        pass

    def get(self):
        """Return the device info."""
        cache.set('device_active', 1, 10)
        cache.set('received_info', self.request.query_arguments, 10)
        device_info = cache.get('device_info')
        if device_info is not None:
            self.write(device_info)
            cache.delete('device_info')

    def post(self):
        """Process the operator module's request."""
        body = self.request.body
        # TODO: after successfully writing a card, the response is "success"
        # try:
        #     # TODO: deal with multi-user -- exclusive lock?
        #     device_address = unhexlify(binary[:12])
        # except Exception as error:
        #     self.write(str(error))
        # body = binary[12:]
        if len(body) > 0:
            try:
                sector_1 = unhexlify(body[1:91])
                # logging.info(f'sector_1: {sector_1}')
                # logging.info(f'sector_1[6:8]: {sector_1[6:8]}')
                system_id = sector_1[6:8].decode('ascii')
                # logging.info(f'system_id: {system_id}')
                # Failure to read the card should be displayed somehow, but
                # shouldn't prevent overwriting the card
                # TODO: clean this up
                payload = _pack_into_dict(self.session, body)
                if system_id == 'up':
                    cache.set('device_active', 0, 10)
                else:
                    cache.set('device_active', 1, 10)
            except Exception as error:
                logging.error(f'Card Process Error: {error}')
                cache.set('card_read_error', str(error), 10)
            else:
                cache.set('received_info', payload, 10)
                cache.delete('card_read_error')
            try:
                _verify_written_card(self.session)
            except Exception as error:
                logging.error(f'Verify Error: {error}')
        device_info = cache.get('device_info')
        if device_info is not None:
            self.write(device_info)
            cache.delete('device_info')


class JSONDeviceConnection(SockJSConnection):
    """Handlers for SockJS real-time card reader functionality."""

    def on_open(self, info):
        """Send data every so often."""
        self.timeout = tornado.ioloop.PeriodicCallback(self._send_data, 1000)
        self.timeout.start()

    def on_close(self):
        """Stop sending data."""
        self.timeout.stop()

    def _send_data(self):
        result = {
            'device_active': bool(int(cache.get('device_active') or 0)),
            'received_info': json_decode(cache.get('received_info') or '{}'),
            'write_info': json_decode(cache.get('write_info') or '{}'),
            'notification': json_decode(cache.get('notification') or '{}'),
            'card_read_error': (cache.get('card_read_error') or b'').decode(),
        }
        self.send(result)


class ManualHandler(BaseHandler):
    """Handlers for cards view."""

    @tornado.web.authenticated
    def get(self):
        """Render the cards form."""
        http_protocol = 'https' if options.minigrid_https else 'http'
        self.render('manual.html', http_protocol=http_protocol)


class ImageHandler(BaseHandler):
    """Handlers for data plot."""

    def genImage(self, minigrid_id):
        """Return the plot png."""
        x = []
        y = []
        with models.transaction(self.session) as session:
            minigrid = models.get_minigrid(session, minigrid_id)
            for credit_card_history \
                    in islice(reversed(minigrid.credit_card_history), 0, 25):
                x.append(credit_card_history.credit_card_created)
                y.append(credit_card_history.credit_amount)
        # fig = plt.figure()
        memdata = io.BytesIO()
        if x:
            min = x[0]
            max = x[-1]
        # plt.plot(x, y)
        # plt.bar(x, y, align='center', alpha=0.5)
        plt.scatter(x, y, alpha=0.5)
        plt.xlim(max, min)
        plt.title('Recent Credit Cards')
        plt.xlabel('Card Creation Time')
        plt.ylabel('Amount [UGX]')
        plt.xticks(rotation=45)
        plt.tight_layout()
        plt.grid(True)
        plt.savefig(memdata, format='png')
        image = memdata.getvalue()
        return image

    @tornado.web.authenticated
    def get(self, minigrid_id):
        """Render the credit card history form."""
        image = self.genImage(minigrid_id)
        self.set_header('Content-type', 'image/png')
        self.set_header('Content-length', len(image))
        self.write(image)


_mmch = MinigridMaintenanceCardsHandler
application_urls = [
    (r'/', MainHandler),
    (r'/minigrids/(.{36})/?', MinigridHandler),
    (r'/minigrids/(.{36})/vendors/?', MinigridVendorsHandler),
    (r'/minigrids/(.{36})/vendors/history/?',
        MinigridVendorsHistoryHandler),
    (r'/minigrids/(.{36})/customers/?', MinigridCustomersHandler),
    (r'/minigrids/(.{36})/customers/history/?',
        MinigridCustomersHistoryHandler),
    (r'/minigrids/(.{36})/maintenance_cards/?',
        MinigridMaintenanceCardsHandler),
    (r'/minigrids/(.{36})/maintenance_cards/history/?',
        MinigridMaintenanceHistoryHandler),
    (r'/minigrids/(.{36})/write_credit/?', MinigridWriteCreditHandler),
    (r'/minigrids/(.{36})/write_credit/history/?',
        MinigridWriteCreditHistoryHandler),
    (r'/device_info/?', DeviceInfoHandler),
    (r'/tariffs/?', TariffsHandler),
    (r'/minigrids/?', MinigridsHandler),
    (r'/users/?', UsersHandler),
    # (r'/technician/?', TechnicianHandler),
    (r'/device/?', DeviceHandler),
    (r'/cards/?', CardsHandler),
    (r'/verify/?', VerifyLoginHandler),
    (r'/logout/?', LogoutHandler),
    (r'/manual/?', ManualHandler),
    (r'/minigrids/(.{36})/write_credit/history/plot.png', ImageHandler)]


def get_urls():
    """Gather all the URLs for the Tornado Application object."""
    sockjs_urls = SockJSRouter(JSONDeviceConnection, r'/cardconn/?').urls
    return application_urls + sockjs_urls
