"""Handlers for the URL endpoints."""
from datetime import timedelta
from urllib.parse import urlencode
from uuid import uuid4

from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.exc import DataError, IntegrityError
from sqlalchemy.orm.exc import NoResultFound

import tornado.web

import minigrid.error
import minigrid.models as models
from minigrid.options import options
from minigrid.portier import get_verified_email, redis_kv


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
            self.render(
                error.template_name, reason=error.reason,
                **error.template_kwargs)
            return
        super().write_error(status_code, **kwargs)


class MainHandler(BaseHandler):
    """Handlers for the site index."""

    def get(self):
        """Render the homepage."""
        if self.current_user:
            system = self.session.query(models.System).one_or_none()
            minigrids = (
                self.session
                .query(models.Minigrid).order_by(models.Minigrid.name))
            self.render(
                'index-minigrid-list.html', system=system, minigrids=minigrids)
            return
        self.render('index-logged-out.html', reason=None)

    def post(self):
        """Send login information to the portier broker."""
        nonce = uuid4().hex
        redis_kv.setex(nonce, timedelta(minutes=15), '')
        query_args = urlencode({
            'login_hint': self.get_argument('email'),
            'scope': 'openid email',
            'nonce': nonce,
            'response_type': 'id_token',
            'response_mode': 'form_post',
            'client_id': options.minigrid_website_url,
            'redirect_uri': options.minigrid_website_url + '/verify'})
        self.redirect('https://broker.portier.io/auth?' + query_args)


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
        self.render('tariffs.html', system=system, reason=None)

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
            reason = 'Updated tariff information'
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
        self.set_status(200)
        self.render(
            'tariffs.html',
            system=self.session.query(models.System).one_or_none(),
            reason=reason)


class UsersHandler(BaseHandler):
    """Handlers for user management."""

    def _render_users(self, reason=None):
        users = self.session.query(models.User).order_by('email')
        self.render('users.html', users=users, reason=reason)

    @tornado.web.authenticated
    def get(self):
        """Render the view for user management."""
        self._render_users()

    @tornado.web.authenticated
    def post(self):
        """Create a new user model."""
        email = self.get_argument('email')
        reason = None
        try:
            with models.transaction(self.session) as session:
                session.add(models.User(email=email))
        except IntegrityError as error:
            if 'user_email_check' in error.orig.pgerror:
                reason = f'{email} is not a valid e-mail address'
            else:
                reason = f'Account for {email} already exists'
        self._render_users(reason=reason)


class MinigridHandler(BaseHandler):
    """Handlers for a minigrid view."""

    @tornado.web.authenticated
    def get(self, minigrid_id):
        """Render the view for a minigrid record."""
        try:
            minigrid = (
                self.session
                .query(models.Minigrid)
                .filter_by(minigrid_id=minigrid_id)
                .one())
        except (NoResultFound, DataError):
            raise tornado.web.HTTPError(404)
        self.render('minigrid.html', minigrid=minigrid)


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
        email = await get_verified_email(token)
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
        self.redirect(self.get_argument('next', '/'))


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
    (r'/minigrid/(.+)?', MinigridHandler),
    (r'/tariffs/?', TariffsHandler),
    (r'/users/?', UsersHandler),
    (r'/verify/?', VerifyLoginHandler),
    (r'/logout/?', LogoutHandler)]
