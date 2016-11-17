"""Minigrid access web server."""
from asyncio import get_event_loop
import logging

from sqlalchemy.orm import sessionmaker

import tornado.ioloop
from tornado.platform.asyncio import AsyncIOMainLoop
import tornado.web

if __name__ == '__main__':
    from minigrid.options import parse_command_line
    parse_command_line()

from minigrid import models  # noqa
from minigrid.handlers import application_urls  # noqa
import minigrid.options  # noqa
from minigrid.options import options  # noqa


def settings():
    """Get the Application settings from minigrid.options."""
    result = minigrid.options.application_settings()
    if result['cookie_secret'] is None:
        result['cookie_secret'] = minigrid.options.get_cookie_secret()
    if result['debug']:
        logging.info('Debug mode is on')
    return result


class Application(tornado.web.Application):
    """Application class for the minigrid server."""
    def __init__(self, session=None):
        """Create the Application, with URLs, settings, and a db session."""
        super().__init__(application_urls, **settings())
        if session is None:
            engine = models.create_engine()
            models.Base.metadata.create_all(engine)
            Session = sessionmaker(bind=engine, autocommit=True)
            self.session = Session()
        else:
            self.session = session


if __name__ == '__main__':
    AsyncIOMainLoop().install()
    Application().listen(options.minigrid_port)
    print('Listening on port {}'.format(options.minigrid_port))
    logging.info('Application started')
    get_event_loop().run_forever()
