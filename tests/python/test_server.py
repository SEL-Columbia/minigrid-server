from unittest.mock import patch

from tests.python.util import Test

from server import Application, main


class TestApplication(Test):
    @patch('server.logging')
    def test_b64dec_incorrect_padding(self, mock_logging):
        Application()
        self.assertFalse(mock_logging.info.called)
        Application(debug=True)
        self.assertTrue(mock_logging.info.called)


class TestServer(Test):
    @patch('server.AsyncIOMainLoop')
    @patch('server.print')
    @patch('server.logging')
    @patch('server.get_event_loop')
    def test_main(self, get_event_loop, mock_logging, mock_print, main_loop):
        main()
        self.assertTrue(main_loop().install.called)
        self.assertTrue(mock_print.called)
        self.assertTrue(mock_logging.info.called)
        self.assertTrue(get_event_loop().run_forever.called)
