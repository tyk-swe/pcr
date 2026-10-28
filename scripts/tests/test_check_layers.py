# Copyright (C) 2026 tyk-swe
# SPDX-License-Identifier: AGPL-3.0-only
import tempfile
import unittest
from pathlib import Path

from support import load_script

layers = load_script("check_layers")

TABLE = {"mini": {("low",): 1, ("high",): 2, ("engine",): 3, ("engine", "stats"): 1}}


def workspace(files):
    temporary = tempfile.TemporaryDirectory()
    root = Path(temporary.name)
    src = root / "crates" / "mini" / "src"
    for relative, text in files.items():
        path = src / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)
    return temporary, root


class CheckLayersTests(unittest.TestCase):
    def check(self, files, allowlist=()):
        temporary, root = workspace(files)
        self.addCleanup(temporary.cleanup)
        return layers.check_workspace(root, layers=TABLE, allowlist=allowlist)

    def test_downward_and_same_layer_dependencies_pass(self):
        problems = self.check({
            "low.rs": "pub struct Thing;",
            "high.rs": "use crate::low::Thing;\nuse crate::high::Other;",
        })
        self.assertEqual(problems, [])

    def test_upward_dependencies_fail_in_plain_and_grouped_paths(self):
        problems = self.check({
            "low.rs": "use crate::high::Thing;",
            "engine/stats.rs": "use crate::{engine::Run, high::Other};",
        })
        self.assertEqual(len(problems), 3)
        self.assertTrue(any("low (layer 1) depends on high::Thing (layer 2)" in p for p in problems))
        self.assertTrue(any("engine::stats (layer 1) depends on engine::Run (layer 3)" in p for p in problems))
        self.assertTrue(any("engine::stats (layer 1) depends on high::Other (layer 2)" in p for p in problems))

    def test_relative_super_paths_resolve_against_the_owning_module(self):
        problems = self.check({
            "low/child.rs": "use super::super::high::Thing;",
            "high/child.rs": "use super::super::low::Thing;",
        })
        self.assertEqual(len(problems), 1)
        self.assertIn("low::child (layer 1) depends on high::Thing (layer 2)", problems[0])

    def test_grouped_self_and_glob_imports_keep_their_prefix(self):
        problems = self.check({
            "low.rs": "use crate::high::{self as workflows};",
            "engine/stats.rs": "use crate::high::*;",
        })
        self.assertEqual(len(problems), 2)
        self.assertTrue(any("low (layer 1) depends on high (layer 2)" in p for p in problems))
        self.assertTrue(any("engine::stats (layer 1) depends on high (layer 2)" in p for p in problems))

    def test_visibility_qualifiers_are_not_dependencies(self):
        problems = self.check({
            "engine/stats.rs": (
                "pub(super) struct Counter;\n"
                "pub(crate) fn count() {}\n"
                "pub(in crate::engine) fn inner() {}"
            ),
        })
        self.assertEqual(problems, [])

    def test_inline_modules_resolve_relative_to_their_own_scope(self):
        problems = self.check({
            "engine/stats.rs": "mod inner { use super::super::high::Thing; }",
        })
        self.assertEqual(len(problems), 1)
        self.assertIn(
            "engine::stats::inner (layer 1) depends on engine::high::Thing (layer 3)",
            problems[0],
        )

    def test_inline_modules_keep_their_own_layer_for_comparison(self):
        problems = self.check({
            "engine.rs": "mod stats { use crate::high::Thing; }",
        })
        self.assertEqual(len(problems), 1)
        self.assertIn(
            "engine::stats (layer 1) depends on high::Thing (layer 2)", problems[0]
        )

    def test_cfg_test_fields_do_not_swallow_following_production_code(self):
        problems = self.check({
            "low.rs": (
                "struct Inner { pending: u32, #[cfg(test)] refuse: bool, }\n"
                "fn build() -> Inner { Inner { pending: 0, "
                "#[cfg(test)] refuse: false, } }\n"
                "pub fn reserve() { let _ = crate::high::Thing; }\n"
            ),
        })
        self.assertEqual(len(problems), 1)
        self.assertIn("low (layer 1) depends on high::Thing (layer 2)", problems[0])

    def test_test_code_comments_and_strings_do_not_create_dependencies(self):
        problems = self.check({
            "low.rs": (
                "// use crate::high::Thing;\n"
                'const TEXT: &str = "crate::high::Thing";\n'
                "#[cfg(test)]\nmod tests { use crate::high::Thing; }\n"
            ),
            "low/tests.rs": "use crate::high::Thing;",
        })
        self.assertEqual(problems, [])

    def test_allowlist_covers_only_the_named_edge(self):
        allowlist = (("mini", ("low",), ("high", "Special"), "named edge"),)
        problems = self.check(
            {"low.rs": "use crate::high::{Other, Special};"},
            allowlist=allowlist,
        )
        self.assertEqual(len(problems), 1)
        self.assertIn("high::Other", problems[0])

    def test_stale_allowlist_entry_fails(self):
        allowlist = (("mini", ("low",), ("high", "Special"), "named edge"),)
        problems = self.check({"low.rs": "pub struct Thing;"}, allowlist=allowlist)
        self.assertEqual(len(problems), 1)
        self.assertIn("stale allowlist entry low -> high::Special", problems[0])

    def test_module_missing_from_the_layer_table_fails(self):
        problems = self.check({"mystery.rs": "pub struct Thing;"})
        self.assertEqual(len(problems), 1)
        self.assertIn("module mystery is not in the layer table", problems[0])


if __name__ == "__main__":
    unittest.main()
