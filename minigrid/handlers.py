"""Handlers for the URL endpoints."""
from datetime import timedelta
from urllib.parse import urlencode
from uuid import uuid4

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
        """The database session. Use session.begin() for transactions."""
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
    def get(self):
        self.render('index.html', reason=None)

    def post(self):
        """This is the login URL endpoint."""
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


class VerifyLoginHandler(BaseHandler):
    def check_xsrf_cookie(self):
        """OpenID doesn't reply with _xsrf header.

        https://github.com/portier/demo-rp/issues/10
        """
        pass

    async def post(self):
        """This endpoint verifies the response from the portier broker."""
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
    def post(self):
        """Delete the user cookie, which is httponly."""
        self.clear_cookie('user')
        self.redirect('/')


application_urls = [
    (r'/', MainHandler),
    (r'/verify/?', VerifyLoginHandler),
    (r'/logout/?', LogoutHandler),
]
