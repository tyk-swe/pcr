# Copyright (C) 2026 tyk-swe
# SPDX-License-Identifier: AGPL-3.0-only
import unittest

from support import load_script

rust_source = load_script("rust_source")


class WithoutTestItemsTests(unittest.TestCase):
    def test_braces_inside_literals_do_not_leak_test_code(self):
        source = (
            '#[cfg(test)]\nmod tests { fn g() { let _ = "}"; let _ = \'}\'; } }\n'
            "fn live() {}\n"
        )
        self.assertEqual(rust_source.without_test_items(source), "\nfn live() {}\n")

    def test_field_and_statement_items_end_at_their_terminator(self):
        source = (
            "struct S {\n    #[cfg(test)]\n    probe: u8,\n    real: u8,\n}\n"
            "fn f() {\n    #[cfg(test)]\n    helper();\n    live();\n}\n"
        )
        stripped = rust_source.without_test_items(source)
        self.assertNotIn("probe", stripped)
        self.assertNotIn("helper", stripped)
        self.assertIn("real: u8", stripped)
        self.assertIn("live();", stripped)

    def test_commas_inside_delimiters_do_not_end_items_early(self):
        source = (
            "#[cfg(test)]\nfn helper(first: u8, second: [u8; 2]) -> u8 { first }\n"
            "fn live() {\n    #[cfg(test)]\n    gated.call(false, Order::Relaxed);\n    live();\n}\n"
        )
        stripped = rust_source.without_test_items(source)
        self.assertNotIn("helper", stripped)
        self.assertNotIn("gated", stripped)
        self.assertIn("live();", stripped)

    def test_module_declaration_and_all_cfg_forms_are_removed(self):
        source = "#[cfg(all(test, unix))]\nmod tests;\nfn live() {}\n"
        self.assertEqual(rust_source.without_test_items(source), "\nfn live() {}\n")


class BlankCommentsTests(unittest.TestCase):
    def test_comments_blank_but_literals_survive(self):
        source = 'let a = "cli.live"; // see example.test.invalid\n/* api.example.test */ let b = "x//y";'
        blanked = rust_source.blank_comments(source)
        self.assertIn('"cli.live"', blanked)
        self.assertIn('"x//y"', blanked)
        self.assertNotIn("example.test.invalid", blanked)
        self.assertNotIn("api.example.test", blanked)
        self.assertEqual(len(blanked), len(source))


if __name__ == "__main__":
    unittest.main()
