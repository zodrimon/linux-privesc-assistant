import unittest
import subprocess
import os
import json
import tempfile

class TestCliExecution(unittest.TestCase):
    def setUp(self):
        # We need to run the CLI from the project root
        self.project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
        self.env = os.environ.copy()
        self.env["PYTHONPATH"] = os.path.join(self.project_root, "src")
        self.cli_path = os.path.join(self.project_root, "src", "privesc_assistant", "cli.py")

    def test_cli_list_checks(self):
        result = subprocess.run(
            ["python", self.cli_path, "list-checks"],
            env=self.env,
            capture_output=True,
            text=True
        )
        self.assertEqual(result.returncode, 0)
        self.assertIn("suid_sgid", result.stdout)
        self.assertIn("misconfigurations", result.stdout)

    def test_cli_scan_json_output(self):
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            out_path = f.name
            
        try:
            # We run a quick scan. To prevent it taking too long or failing due to permissions,
            # we can run it with a limited set of checks if needed, but for E2E we want to ensure
            # the engine runs and outputs valid JSON without crashing.
            result = subprocess.run(
                ["python", self.cli_path, "scan", "--format", "json", "--output", out_path],
                env=self.env,
                capture_output=True,
                text=True
            )
            
            self.assertEqual(result.returncode, 0)
            self.assertIn("Report saved to", result.stdout)
            
            with open(out_path, "r") as f:
                data = json.load(f)
                
            self.assertIn("metadata", data)
            self.assertIn("findings", data)
            self.assertIn("statistics", data)
        finally:
            if os.path.exists(out_path):
                os.remove(out_path)

if __name__ == '__main__':
    unittest.main()
