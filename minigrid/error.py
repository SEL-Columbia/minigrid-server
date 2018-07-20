"""Application-defined errors."""
import tornado.web


class MinigridHTTPError(tornado.web.HTTPError):
    """Base class for application HTTP errors."""

    def __init__(self, reason, status_code, template_name, **template_kwargs):
        """Create an instance of this Error.

        Subclasses should include a default status_code and template_name.
        """
        self.reason = reason
        self.status_code = status_code
        self.template_name = template_name
        self.log_message = None
        self.template_kwargs = template_kwargs
        template_kwargs['next_page'] = '/'


class LoginError(MinigridHTTPError):
    """Error during login."""

    def __init__(self,
                 status_code=400,
                 template_name='index-logged-out.html',
                 *, reason, **template_kwargs):
        """Create a login error (400 by default)."""
        super().__init__(reason, status_code, template_name, **template_kwargs)


class CardReadError(Exception):
    """Error while reading a card."""

class CardWriteError(Exception):
    """Error while writing a card."""

    
