import unittest
import os
import tempfile
from privesc_assistant.config.loader import load_config, _deep_merge
from privesc_assistant.config.schema import validate_config

class TestConfig(unittest.TestCase):
    def test_deep_merge(self):
        target = {"a": {"b": 1}, "c": 2}
        source = {"a": {"d": 3}, "c": 4}
        merged = _deep_merge(target, source)
        self.assertEqual(merged["a"]["b"], 1)
        self.assertEqual(merged["a"]["d"], 3)
        self.assertEqual(merged["c"], 4)

    def test_schema_validation_valid(self):
        valid_config = {
            "output": {"format": "json"},
            "checks": {"suid_sgid": True}
        }
        # Should not raise
        validate_config(valid_config)

    def test_schema_validation_invalid(self):
        invalid_config = {
            "output": "not_a_dict"
        }
        with self.assertRaises(ValueError):
            validate_config(invalid_config)
            
        invalid_format = {
            "output": {"format": "unsupported"}
        }
        with self.assertRaises(ValueError):
            validate_config(invalid_format)

    def test_load_config_missing_user_file(self):
        with self.assertRaises(FileNotFoundError):
            load_config("nonexistent_file.yaml")

    def test_load_config_partial_override(self):
        # Create a temporary user config
        with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".yaml") as tmp:
            tmp.write("output:\n  format: json\nchecks:\n  suid_sgid: false\n")
            tmp_path = tmp.name

        try:
            config = load_config(tmp_path)
            self.assertEqual(config["output"]["format"], "json")
            self.assertFalse(config["checks"]["suid_sgid"])
            # Defaults should still be present
            self.assertTrue("capabilities" in config["checks"])
        finally:
            os.remove(tmp_path)

if __name__ == "__main__":
    unittest.main()
