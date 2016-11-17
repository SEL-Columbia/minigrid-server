"""Handlers for the URL endpoints."""
import tornado.web

from minigrid.models import User


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
        return self.session.query(User).get(user_id.decode())


class MainHandler(BaseHandler):
    def get(self):
        self.render('index.html')


application_urls = [
    (r'/', MainHandler),
]
