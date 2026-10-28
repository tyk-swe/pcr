import os
import subprocess
import tempfile
import unittest
from importlib.machinery import SourceFileLoader
from pathlib import Path

csr = SourceFileLoader(
    "codex_sol_review", str(Path(__file__).with_name("codex-sol-review"))
).load_module()


def msg(phase, text):
    return {"type": "agentMessage", "phase": phase, "text": text}


class PickMessage(unittest.TestCase):
    def test_partial_and_final_answers_are_kept_in_order(self):
        got = csr.pick_message(
            [
                msg("commentary", "looking"),
                msg("partial_answer", "VERDICT: CHANGES\nS1 finding"),
                msg("final_answer", "S2 finding"),
            ]
        )
        self.assertEqual(got, "VERDICT: CHANGES\nS1 finding\nS2 finding")

    def test_final_answer_alone(self):
        got = csr.pick_message([msg("final_answer", "VERDICT: APPROVE")])
        self.assertEqual(got, "VERDICT: APPROVE")

    def test_no_answer_phase_falls_back_to_last_message(self):
        got = csr.pick_message([msg("commentary", "only this")])
        self.assertEqual(got, "only this")

    def test_no_messages_fails_the_turn(self):
        with self.assertRaises(csr.TurnFailed):
            csr.pick_message([])


def sol(model_id, tiers):
    return {"model": model_id, "serviceTiers": [{"id": t} for t in tiers]}


class SelectSolTier(unittest.TestCase):
    def test_picks_latest_sol_offering_the_tier(self):
        models = [sol("gpt-6-sol", ["priority"]), sol("gpt-6.1-sol", ["priority", "ultrafast"])]
        self.assertEqual(csr.select_sol(models, None, "ultrafast"), "gpt-6.1-sol")

    def test_skips_a_newer_sol_that_lacks_the_tier(self):
        models = [sol("gpt-7-sol", ["priority"]), sol("gpt-6.1-sol", ["ultrafast"])]
        self.assertEqual(csr.select_sol(models, None, "ultrafast"), "gpt-6.1-sol")

    def test_fails_when_no_sol_offers_the_tier(self):
        with self.assertRaises(csr.SetupError):
            csr.select_sol([sol("gpt-6-sol", ["priority"])], None, "ultrafast")

    def test_named_sol_without_the_tier_fails(self):
        with self.assertRaises(csr.SetupError):
            csr.select_sol([sol("gpt-6-sol", ["priority"])], "gpt-6-sol", "ultrafast")

    def test_named_sol_with_the_tier_is_kept(self):
        models = [sol("gpt-6.1-sol", ["ultrafast"]), sol("gpt-7-sol", ["ultrafast"])]
        self.assertEqual(csr.select_sol(models, "gpt-6.1-sol", "ultrafast"), "gpt-6.1-sol")

    def test_no_tier_requested_picks_latest_sol(self):
        models = [sol("gpt-6-sol", []), sol("gpt-6.1-sol", [])]
        self.assertEqual(csr.select_sol(models, None, None), "gpt-6.1-sol")

    def test_additional_speed_tiers_count_when_service_tiers_absent(self):
        models = [{"model": "gpt-6.1-sol", "additionalSpeedTiers": ["fast", "ultrafast"]}]
        self.assertEqual(csr.select_sol(models, None, "ultrafast"), "gpt-6.1-sol")


class RoundStatus(unittest.TestCase):
    def test_completed_only_when_every_reviewer_completed(self):
        done = [{"status": "completed"}] * 4
        self.assertEqual(csr.round_status(done, True), "completed")
        mixed = done[:3] + [{"status": "failed"}]
        self.assertEqual(csr.round_status(mixed, True), "incomplete")

    def test_changed_snapshot_is_incomplete(self):
        done = [{"status": "completed"}] * 4
        self.assertEqual(csr.round_status(done, False), "incomplete")

    def test_no_reviewers_is_incomplete(self):
        self.assertEqual(csr.round_status([], True), "incomplete")


class GitSnapshot(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.repo = self.tmp.name
        env = {
            **os.environ,
            "GIT_AUTHOR_NAME": "t",
            "GIT_AUTHOR_EMAIL": "t@t",
            "GIT_COMMITTER_NAME": "t",
            "GIT_COMMITTER_EMAIL": "t@t",
        }
        def git(*args):
            subprocess.run(["git", "-C", self.repo, *args], check=True, env=env,
                           capture_output=True)
        git("init", "-q")
        Path(self.repo, "a.txt").write_text("one\n")
        git("add", "a.txt")
        git("commit", "-qm", "init")

    def tearDown(self):
        self.tmp.cleanup()

    def test_stable_when_nothing_changes(self):
        self.assertEqual(csr.git_snapshot(self.repo), csr.git_snapshot(self.repo))

    def test_changes_with_an_unstaged_edit(self):
        before = csr.git_snapshot(self.repo)
        Path(self.repo, "a.txt").write_text("two\n")
        self.assertNotEqual(before, csr.git_snapshot(self.repo))

    def test_changes_with_an_untracked_file(self):
        before = csr.git_snapshot(self.repo)
        Path(self.repo, "b.txt").write_text("new\n")
        self.assertNotEqual(before, csr.git_snapshot(self.repo))


if __name__ == "__main__":
    unittest.main()
