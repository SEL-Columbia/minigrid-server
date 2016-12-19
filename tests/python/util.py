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

from minigrid.options import options, path
options.db_schema = 'minigrid_test'  # noqa
import minigrid.options
minigrid.options.cookie_secret_path = path(
    '../tests/python/tmp/COOKIE_SECRET')  # noqa
from minigrid import models


class Dummy:
    pass


DummyRedis = Dummy
DummyRedis.StrictRedis = Dummy
DummyRedis.StrictRedis.from_url = lambda _: fakeredis.FakeStrictRedis()
sys.modules['redis'] = DummyRedis
from minigrid import portier  # noqa
from server import Application  # noqa


engine = models.create_engine()
Session = sessionmaker()


class Test(unittest.TestCase):
    def setUp(self):
        shutil.rmtree(path('../tests/python/tmp'), ignore_errors=True)
        os.mkdir(path('../tests/python/tmp'))
        models.Base.metadata.create_all(engine)
        self.connection = engine.connect()
        self.transaction = self.connection.begin()
        self.session = Session(bind=self.connection)
        self.session.begin_nested()

        @event.listens_for(self.session, 'after_transaction_end')
        def restart_savepoint(session, transaction):
            """Taken from

            http://docs.sqlalchemy.org/en/latest/orm/session_transaction.html
            #joining-a-session-into-an-external-transaction
            -such-as-for-test-suites
            """
            if transaction.nested and not transaction._parent.nested:
                session.expire_all()
                session.begin_nested()

        super().setUp()

    def tearDown(self):
        self.session.close()
        self.transaction.rollback()
        self.connection.close()
        for tbl in reversed(models.Base.metadata.sorted_tables):
            engine.execute(tbl.delete())
        shutil.rmtree(path('../tests/python/tmp'), ignore_errors=True)
        portier.redis_kv.flushall()
        super().tearDown()


class HTTPTest(Test, AsyncHTTPTestCase):
    def get_app(self):
        self.app = Application(self.session, xsrf_cookies=False)
        return self.app

    def assertResponseCode(self, response, code):
        self.assertEqual(response.code, code, msg=response)


def CoroMock():
    """Mock callable lifted from http://stackoverflow.com/a/32505333."""
    Mock = unittest.mock.Mock
    coro = Mock(name="CoroutineResult")
    corofunc = Mock(name="CoroutineFunction", side_effect=coroutine(coro))
    corofunc.coro = coro
    return corofunc
