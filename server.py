"""Minigrid access web server."""
from asyncio import get_event_loop
import logging

from sqlalchemy.orm import sessionmaker

import tornado.ioloop
from tornado.platform.asyncio import AsyncIOMainLoop
import tornado.web

if __name__ == '__main__':  # pragma: nocover
    from minigrid.options import parse_command_line
    parse_command_line()

from minigrid import models  # noqa
from minigrid.handlers import application_urls  # noqa
from minigrid.options import application_settings, options  # noqa


class Application(tornado.web.Application):
    """Application class for the minigrid server."""
    def __init__(self, session=None, **kwargs):
        """Create the Application, with URLs, settings, and a db session."""
        settings = {**application_settings(), **kwargs}
        if settings['debug']:
            logging.info('Debug mode is on')
        super().__init__(application_urls, **settings)
        if session is None:
            engine = models.create_engine()
            models.Base.metadata.create_all(engine)
            Session = sessionmaker(bind=engine, autocommit=True)
            self.session = Session()
        else:
            self.session = session


def main():
    AsyncIOMainLoop().install()
    Application().listen(options.minigrid_port)
    print('Listening on port {}'.format(options.minigrid_port))
    logging.info('Application started')
    get_event_loop().run_forever()


if __name__ == '__main__':  # pragma: nocover
    main()
