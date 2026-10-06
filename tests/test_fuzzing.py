import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import fuzzing


class FuzzingWorkspaceTests(unittest.TestCase):
    def test_workspace_creates_a_seed(self):
        with tempfile.TemporaryDirectory() as tmp:
            seeds, output = fuzzing.ensure_workspace(Path(tmp) / "seeds", Path(tmp) / "out")
            self.assertTrue((seeds / "seed-empty").is_file())
            self.assertTrue(output.is_dir())

    def test_crash_metadata_and_listing(self):
        with tempfile.TemporaryDirectory() as tmp:
            crash = Path(tmp) / "processscope" / "crashes" / "id:000001,sig:11,src:000000"
            crash.parent.mkdir(parents=True)
            crash.write_bytes(b"boom")
            records = fuzzing.list_crashes(tmp)
            self.assertEqual(records[0]["metadata"]["sig"], "11")
            self.assertEqual(records[0]["size"], 4)

    def test_reproduce_rejects_missing_paths(self):
        self.assertFalse(fuzzing.reproduce("/does/not/exist", "/also/missing")["ok"])


if __name__ == "__main__":
    unittest.main()
