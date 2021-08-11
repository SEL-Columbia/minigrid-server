"""Test utilities."""
from asyncio import coroutine
import shutil
import os
import sys
import unittest

import fakeredis

from sqlalchemy import event
from sqlalchemy.orm import sessionmaker

from tornado.testing import AsyncHTTPTestCase

from minigrid.options import path
from minigrid import models


class Dummy:
    """Dummy class to help fake redis in tests."""


DummyRedis = Dummy
DummyRedis.StrictRedis = Dummy
DummyRedis.StrictRedis.from_url = lambda _: fakeredis.FakeStrictRedis()
sys.modules['redis'] = DummyRedis
import minigrid.handlers  # noqa
from server import Application  # noqa


engine = models.create_engine()
Session = sessionmaker()


class Test(unittest.TestCase):
    """Base Test class that runs code in a transaction."""

    def setUp(self):
        """Get the database ready for a test."""
        shutil.rmtree(path('../tests/python/tmp'), ignore_errors=True)
        os.mkdir(path('../tests/python/tmp'))
        models.Base.metadata.create_all(engine)
        self.connection = engine.connect()
        self.transaction = self.connection.begin()
        self.session = Session(bind=self.connection)
        self.session.begin_nested()

        @event.listens_for(self.session, 'after_transaction_end')
        def restart_savepoint(session, transaction):
            """Taken from...

            http://docs.sqlalchemy.org/en/latest/orm/session_transaction.html
            #joining-a-session-into-an-external-transaction
            -such-as-for-test-suites
            """
            if transaction.nested and not transaction._parent.nested:
                session.expire_all()
                session.begin_nested()

        super().setUp()

    def tearDown(self):
        """Clean up the database."""
        self.session.close()
        self.transaction.rollback()
        self.connection.close()
        for tbl in reversed(models.Base.metadata.sorted_tables):
            engine.execute(tbl.delete())
        shutil.rmtree(path('../tests/python/tmp'), ignore_errors=True)
        minigrid.handlers.cache.flushall()
        super().tearDown()


class HTTPTest(Test, AsyncHTTPTestCase):
    """Tests for endpoints."""

    def get_app(self):
        """Return a Tornado Application object."""
        self.app = Application(self.session, xsrf_cookies=False)
        return self.app

    def assertResponseCode(self, response, code):
        """Assert that a response has the given code, and print any error."""
        self.assertEqual(response.code, code, msg=response)


def CoroMock():
    """Mock callable lifted from http://stackoverflow.com/a/32505333."""
    Mock = unittest.mock.Mock
    coro = Mock(name="CoroutineResult")
    corofunc = Mock(name="CoroutineFunction", side_effect=coroutine(coro))
    corofunc.coro = coro
    return corofunc
