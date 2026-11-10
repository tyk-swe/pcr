from contextlib import redirect_stdout, redirect_stderr
import io
import json
from pathlib import Path
import tempfile
import unittest

from support import load_script

mutation = load_script("check_mutation_score")


class CheckMutationScoreTests(unittest.TestCase):
    def run_report(self, **overrides: int | str | None) -> tuple[int, str]:
        report = {"caught": 9, "missed": 1, "timeout": 0, "unviable": 0, "end_time": "finished"}
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "outcomes.json"
            path.write_text(json.dumps(report | overrides))
            output = io.StringIO()
            with redirect_stdout(output), redirect_stderr(output):
                status = mutation.main([str(path)])
        return status, output.getvalue()

    def test_exact_threshold_passes_and_unviable_mutants_do_not_inflate_it(self):
        status, output = self.run_report(unviable=200)
        self.assertEqual(status, 0)
        self.assertIn("9/10 = 90.00%", output)
        status, _ = self.run_report(caught=8, missed=2, unviable=200)
        self.assertEqual(status, 1)

    def test_timeouts_count_as_uncaught(self):
        status, output = self.run_report(caught=9, missed=0, timeout=1)
        self.assertEqual(status, 0)
        self.assertIn("1 timed out", output)
        status, _ = self.run_report(caught=9, missed=1, timeout=1)
        self.assertEqual(status, 1)

    def test_rounding_cannot_pass_a_score_below_the_threshold(self):
        status, _ = self.run_report(caught=89999, missed=10001)
        self.assertEqual(status, 1)

    def test_missing_invalid_and_unfinished_results_fail(self):
        for overrides in [
            {"caught": 0, "missed": 0, "unviable": 200},
            {"caught": -1}, {"caught": True}, {"timeout": None},
            {"end_time": None},
        ]:
            with self.subTest(overrides=overrides):
                status, _ = self.run_report(**overrides)
                self.assertEqual(status, 1)
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "outcomes.json"
            for content in [None, "{", "[]"]:
                if content is not None:
                    path.write_text(content)
                with self.subTest(content=content), redirect_stderr(io.StringIO()):
                    self.assertEqual(mutation.main([str(path)]), 1)


if __name__ == "__main__":
    unittest.main()
