"""Handlers for the URL endpoints."""
from datetime import timedelta
from urllib.parse import urlencode
from uuid import uuid4

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

        Use the models.transaction(session) context manager."""
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
            self.render(error.template_name, reason=error.reason)
            return
        super().write_error(status_code, **kwargs)


class MainHandler(BaseHandler):
    """Handlers for the site index."""

    def get(self):
        """Render the homepage."""
        if self.current_user:
            minigrids = (
                self.session
                .query(models.Minigrid).order_by(models.Minigrid.name))
            self.render('index-minigrid-list.html', minigrids=minigrids)
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
            'redirect_uri': options.minigrid_website_url + '/verify',
        })
        self.redirect('https://broker.portier.io/auth?' + query_args)


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
                reason = '{} is not a valid e-mail address'.format(email)
            else:
                reason = 'Account for {} already exists'.format(email)
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
                .one()
            )
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
                reason='Broker Error: {}: {}'.format(error, description))
        token = self.get_argument('id_token')
        email = await get_verified_email(token)
        try:
            user = (
                self.session
                .query(models.User)
                .filter_by(email=email)
                .one()
            )
        except NoResultFound:
            raise minigrid.error.LoginError(
                reason='There is no account for {}'.format(email))
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
    (r'/users/?', UsersHandler),
    (r'/verify/?', VerifyLoginHandler),
    (r'/logout/?', LogoutHandler),
]
