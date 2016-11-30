from tests.python.util import Test

from minigrid import models


class TestUser(Test):
    def test_create(self):
        with self.session.begin():
            self.session.add(models.User(email='a@b.com'))
        user = self.session.query(models.User).one()
        self.assertEqual(user.email, 'a@b.com')
