import unittest
from unittest.mock import patch
import sys
from io import StringIO
from privesc_assistant.cli import main

class TestCLI(unittest.TestCase):
    @patch('sys.stdout', new_callable=StringIO)
    def test_scan_no_checks(self, mock_stdout):
        test_args = ["privesc-assistant", "scan"]
        with patch.object(sys, 'argv', test_args):
            main()
        self.assertIn("0 findings", mock_stdout.getvalue())

    @patch('sys.stdout', new_callable=StringIO)
    def test_list_checks(self, mock_stdout):
        test_args = ["privesc-assistant", "list-checks"]
        with patch.object(sys, 'argv', test_args):
            main()
        # Since no checks are registered by default in the fresh environment
        output = mock_stdout.getvalue()
        self.assertTrue("No checks registered." in output or "-" in output)

    def test_version(self):
        test_args = ["privesc-assistant", "--version"]
        with patch.object(sys, 'argv', test_args):
            with self.assertRaises(SystemExit) as cm:
                main()
            self.assertEqual(cm.exception.code, 0)

if __name__ == '__main__':
    unittest.main()
