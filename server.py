"""Minigrid access web server."""
from asyncio import get_event_loop
import logging
from time import sleep

from sqlalchemy.exc import OperationalError
from sqlalchemy.orm import sessionmaker

from tornado.platform.asyncio import AsyncIOMainLoop
import tornado.web

if __name__ == '__main__':  # pragma: nocover
    from minigrid.options import parse_command_line
    parse_command_line()

from minigrid import models  # noqa
from minigrid.handlers import get_urls  # noqa
from minigrid.options import application_settings, options  # noqa


class Application(tornado.web.Application):
    """Application class for the minigrid server."""

    def __init__(self, session=None, **kwargs):
        """Create the Application, with URLs, settings, and a db session."""
        settings = {**application_settings(), **kwargs}
        if settings['debug']:
            logging.info('Debug mode is on')
        super().__init__(get_urls(), **settings)
        if session is None:
            engine = models.create_engine()
            try:
                models.Base.metadata.create_all(engine)
            except OperationalError:
                logging.error(
                    'Database connection failed... trying again in 5 seconds.')
                sleep(5)
                models.Base.metadata.create_all(engine)
            Session = sessionmaker(bind=engine)
            self.session = Session()
        else:
            self.session = session


def main():
    """Start the Tornado application."""
    AsyncIOMainLoop().install()
    Application().listen(options.minigrid_port)
    print(f'Listening on port {options.minigrid_port}')
    logging.info('Application started')
    get_event_loop().run_forever()


if __name__ == '__main__':  # pragma: nocover
    main()
