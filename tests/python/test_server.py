from unittest.mock import patch

from sqlalchemy.exc import OperationalError

from tests.python.util import Test

from server import Application, main


class TestApplication(Test):
    @patch('server.logging')
    def test_b64dec_incorrect_padding(self, mock_logging):
        Application()
        self.assertFalse(mock_logging.info.called)
        Application(debug=True)
        self.assertTrue(mock_logging.info.called)

    @patch('server.models.Base.metadata.create_all')
    @patch('server.sleep')
    def test_wait_for_db(self, sleep, create_all):
        create_all.side_effect = OperationalError(None, None, None)
        with self.assertLogs(level='ERROR'):
            self.assertRaises(OperationalError, Application)
        self.assertEqual(len(create_all.mock_calls), 2)
        self.assertTrue(sleep.called)


class TestServer(Test):
    @patch('server.AsyncIOMainLoop')
    @patch('server.Application')
    @patch('server.print')
    @patch('server.get_event_loop')
    def test_main(self, get_event_loop, mock_print, application, main_loop):
        with self.assertLogs(level='INFO'):
            main()
        self.assertTrue(main_loop().install.called)
        self.assertTrue(application().listen.called)
        self.assertTrue(mock_print.called)
        self.assertTrue(get_event_loop().run_forever.called)
