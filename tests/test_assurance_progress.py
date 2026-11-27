import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from app import assurance_progress as progress


class AssuranceProgressTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        directory = patch.object(progress, "DIRECTORY", Path(temporary.name))
        directory.start()
        self.addCleanup(directory.stop)
        self.run_id = "a" * 32

    def test_progress_is_stage_driven_and_contains_no_internal_paths(self):
        progress.publish(self.run_id, "attacked", completed=("clean_user", "goal_capability"), requests=4, tools=2)
        value = progress.read(self.run_id)
        self.assertEqual(value, {"stage": "attacked", "completed": ["clean_user", "goal_capability"], "requests": 4, "tools": 2})
        self.assertNotIn(str(progress.DIRECTORY), json.dumps(value))

    def test_bad_identity_and_missing_progress_are_not_read(self):
        self.assertIsNone(progress.read("../secret"))
        self.assertIsNone(progress.read(self.run_id))
        with self.assertRaises(ValueError):
            progress.publish("../secret", "clean_user")

    def test_invalid_stage_or_partial_file_does_not_break_polling(self):
        path = progress.DIRECTORY / (self.run_id + ".json")
        for value in ('{', '{"stage":"made_up"}', 'null'):
            path.write_text(value)
            self.assertIsNone(progress.read(self.run_id))

    def test_progress_sharing_violation_does_not_abort_benchmark(self):
        with patch.object(Path, "replace", side_effect=PermissionError("sharing violation")):
            progress.publish(self.run_id, "clean_user")
        self.assertIsNone(progress.read(self.run_id))
