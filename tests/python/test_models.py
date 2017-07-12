import uuid

from sqlalchemy.orm.exc import NoResultFound

from tornado.web import HTTPError

from tests.python.util import Test

from minigrid import models


class TestUser(Test):
    def test_create(self):
        with models.transaction(self.session) as session:
            session.add(models.User(email='a@b.com'))
        user = self.session.query(models.User).one()
        self.assertEqual(user.email, 'a@b.com')


class TestMinigrid(Test):
    def setUp(self):
        super().setUp()
        with models.transaction(self.session) as session:
            session.add(models.Minigrid(minigrid_name='a'))

    def test_get_minigrid_regular(self):
        minigrid = self.session.query(models.Minigrid).one()
        grid = models.get_minigrid(self.session, minigrid.minigrid_id)
        self.assertIs(grid, minigrid)

    def test_get_minigrid_raise_404(self):
        with self.assertRaises(HTTPError) as error:
            models.get_minigrid(self.session, str(uuid.uuid4()))
        self.assertEqual(error.exception.status_code, 404)

    def test_get_minigrid_reraise(self):
        with self.assertRaises(NoResultFound):
            models.get_minigrid(
                self.session, str(uuid.uuid4()), exception=None)
