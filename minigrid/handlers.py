"""Handlers for the URL endpoints."""
from datetime import timedelta
from urllib.parse import urlencode
from uuid import uuid4

from asyncio_portier import get_verified_email

import redis

from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.exc import DataError, IntegrityError
from sqlalchemy.orm.exc import NoResultFound, UnmappedInstanceError

import tornado.web

from minigrid.device_interface import (
    write_vendor_card, write_customer_card, write_credit_card)
import minigrid.error
import minigrid.models as models
from minigrid.options import options


cache = redis.StrictRedis.from_url(options.redis_url)
broker_url = 'https://broker.portier.io'


class BaseHandler(tornado.web.RequestHandler):
    """The base class for all handlers."""

    @property
    def session(self):
        """The database session.

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
            kwargs['message'] = None
        super().render(*args, **kwargs)


class MainHandler(BaseHandler):
    """Handlers for the site index."""

    def get(self):
        """Render the homepage."""
        if self.current_user:
            system = self.session.query(models.System).one_or_none()
            minigrids = models.get_minigrids(self.session)
            self.render(
                'index-minigrid-list.html', system=system, minigrids=minigrids)
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
        self.render(
            'tariffs.html',
            system=self.session.query(models.System).one_or_none(),
            message=message)


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
                    minigrid_name=self.get_argument('minigrid_name'),
                    aes_key=self.get_argument('minigrid_aes_key')))
        except (IntegrityError, DataError) as error:
            if 'minigrid_name_key' in error.orig.pgerror:
                message = 'A minigrid with that name already exists'
            else:
                message = ' '.join(error.orig.pgerror.split())
            raise minigrid.error.MinigridHTTPError(
                message, 400, 'index-minigrid-list.html',
                system=self.session.query(models.System).one_or_none(),
                minigrids=models.get_minigrids(session))
        self.set_status(201)
        self.render(
            'index-minigrid-list.html',
            system=self.session.query(models.System).one_or_none(),
            minigrids=models.get_minigrids(session))


class UsersHandler(BaseHandler):
    """Handlers for user management."""

    def _render_users(self, message=None):
        users = self.session.query(models.User).order_by('email')
        self.render('users.html', users=users, message=message)

    @tornado.web.authenticated
    def get(self):
        """Render the view for user management."""
        self._render_users()

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
        self._render_users(message=message)


# TODO: this button should do something
class TechnicianHandler(BaseHandler):
    """Handlers for technician view."""

    @tornado.web.authenticated
    def get(self):
        """Render the technician ID writing form."""
        self.render('technician.html')


# TODO: this button should do something
class DeviceHandler(BaseHandler):
    """Handlers for device view."""

    @tornado.web.authenticated
    def get(self):
        """Render the device form."""
        self.render('device.html')


# TODO: this button should do something
class CardsHandler(BaseHandler):
    """Handlers for cards view."""

    @tornado.web.authenticated
    def get(self):
        """Render the cards form."""
        self.render('cards.html')


class MinigridHandler(BaseHandler):
    """Handlers for a minigrid view."""

    @tornado.web.authenticated
    def get(self, minigrid_id):
        """Render the view for a minigrid record."""
        self.render(
            'minigrid.html',
            minigrid=models.get_minigrid(self.session, minigrid_id))


class MinigridWriteCreditHandler(BaseHandler):
    """Handlers for writing credit cards view."""

    @tornado.web.authenticated
    def get(self, minigrid_id):
        """Render the write credit card form."""
        self.render(
            'minigrid_write_credit.html',
            minigrid=models.get_minigrid(self.session, minigrid_id))

    @tornado.web.authenticated
    def post(self, minigrid_id):
        """Write a credit card for this minigrid."""
        minigrid = models.get_minigrid(self.session, minigrid_id)
        system = self.session.query(models.System).one()
        write_credit_card(
            minigrid_id,
            int(self.get_argument('credit_value')),
            system.day_tariff,
            system.night_tariff,
        )
        message = 'Card written'
        self.render(
            'minigrid_write_credit.html', minigrid=minigrid, message=message)


class MinigridVendorsHandler(BaseHandler):
    """Handlers for vendors view."""

    @tornado.web.authenticated
    def get(self, minigrid_id):
        """Render the vendors view."""
        self.render(
            'minigrid_vendors.html',
            minigrid=models.get_minigrid(self.session, minigrid_id))

    @tornado.web.authenticated
    def post(self, minigrid_id):
        """Add a vendor."""
        grid = models.get_minigrid(self.session, minigrid_id)
        action = self.get_argument('action')
        user_id_exists = 'vendor_vendor_minigrid_id_vendor_user_id_key'
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
                    message, 400, 'minigrid_vendors.html', minigrid=grid)
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
            self.render(
                'minigrid_vendors.html', minigrid=grid, message=message)
            return
        elif action == 'write':
            vendor = (
                self.session.query(models.Vendor)
                .get(self.get_argument('vendor_id')))
            write_vendor_card(minigrid_id, vendor)
            message = 'Card written'
            self.render(
                'minigrid_vendors.html', minigrid=grid, message=message)
            return
        else:
            raise tornado.web.HTTPError(400, 'Bad Request (invalid action)')
        self.render('minigrid_vendors.html', minigrid=grid)


class MinigridCustomersHandler(BaseHandler):
    """Handlers for customers view."""

    @tornado.web.authenticated
    def get(self, minigrid_id):
        """Render the customers view."""
        self.render(
            'minigrid_customers.html',
            minigrid=models.get_minigrid(self.session, minigrid_id))

    @tornado.web.authenticated
    def post(self, minigrid_id):
        """Add a customer."""
        grid = models.get_minigrid(self.session, minigrid_id)
        action = self.get_argument('action')
        user_id_exists = 'customer_customer_minigrid_id_customer_user_id_key'
        if action == 'create':
            try:
                with models.transaction(self.session) as session:
                    grid.customers.append(models.Customer(
                        customer_user_id=self.get_argument('customer_user_id'),
                        customer_name=self.get_argument('customer_name')))
            except (IntegrityError, DataError) as error:
                if 'customer_name_key' in error.orig.pgerror:
                    message = 'A customer with that name already exists'
                elif user_id_exists in error.orig.pgerror:
                    message = 'A customer with that User ID already exists'
                else:
                    message = ' '.join(error.orig.pgerror.split())
                raise minigrid.error.MinigridHTTPError(
                    message, 400, 'minigrid_customers.html', minigrid=grid)
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
            self.render(
                'minigrid_customers.html', minigrid=grid, message=message)
            return
        elif action == 'write':
            customer = (
                self.session.query(models.Customer)
                .get(self.get_argument('customer_id')))
            write_customer_card(minigrid_id, customer)
            message = 'Card written'
            self.render(
                'minigrid_customers.html', minigrid=grid, message=message)
            return
        else:
            raise tornado.web.HTTPError(400, 'Bad Request (invalid action)')
        self.render('minigrid_customers.html', minigrid=grid)


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
            raise minigrid.error.LoginError(reason=str(exc))
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


application_urls = [
    (r'/', MainHandler),
    (r'/minigrids/(.{36})/?', MinigridHandler),
    (r'/minigrids/(.{36})/vendors/?', MinigridVendorsHandler),
    (r'/minigrids/(.{36})/customers/?', MinigridCustomersHandler),
    (r'/minigrids/(.{36})/write_credit/?', MinigridWriteCreditHandler),
    (r'/tariffs/?', TariffsHandler),
    (r'/minigrids/?', MinigridsHandler),
    (r'/users/?', UsersHandler),
    (r'/technician/?', TechnicianHandler),
    (r'/device/?', DeviceHandler),
    (r'/cards/?', CardsHandler),
    (r'/verify/?', VerifyLoginHandler),
    (r'/logout/?', LogoutHandler)]
