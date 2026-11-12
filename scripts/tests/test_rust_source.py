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

    def test_comparisons_in_test_helpers_preserve_following_production(self):
        for body in ("assert!(1 < 2);", "let _ = 1 << 2;", "let _ = [1 < 2];"):
            with self.subTest(body=body):
                source = (
                    "#[cfg(test)]\nfn helper<T: Into<Result<u8, u16>>>() { "
                    + body + " }\nfn live() {}\n"
                )
                self.assertEqual(rust_source.without_test_items(source), "\nfn live() {}\n")

    def test_test_constants_preserve_following_production_items(self):
        for declaration in (
            "const LESS: bool = 1 < 2;",
            "const LESS_EQUAL: bool = 1 <= 2;",
            "static SHIFT: u8 = 1 << 2;",
            "const ARRAY: Option<[u8; 2]> = None;",
            "const GENERIC: Example<{ let n = 1; n + 1 }> = Example;",
        ):
            with self.subTest(declaration=declaration):
                source = "#[cfg(test)]\n" + declaration + "\nfn live() {}\n"
                self.assertEqual(rust_source.without_test_items(source), "\nfn live() {}\n")

    def test_attribute_text_in_comments_and_literals_is_preserved(self):
        for prefix in (
            "// #[cfg(test)]\n",
            "/* #[cfg(test)] */\n",
            "/* nested /* #[cfg(test)] */ comment */\n",
            'const DOC: &str = "#[cfg(test)]";\n',
            'const DOC: &str = r##"example: "#[cfg(test)]""##;\n',
        ):
            with self.subTest(prefix=prefix):
                production = "pub struct Live;\n"
                source = prefix + production + "#[cfg(test)]\nfn helper() {}\nfn live() {}\n"
                self.assertEqual(
                    rust_source.without_test_items(source),
                    prefix + production + "\nfn live() {}\n",
                )


class BlankCommentsTests(unittest.TestCase):
    def test_multiline_literals_preserve_newlines_and_following_code(self):
        for literal in ('"first\n/* still a string */\nlast"',
                        'br##"first\n" // still raw\nlast"##'):
            with self.subTest(literal=literal):
                source = f'const TEXT: &str = {literal};\nfn live() {{}}\n'
                blanked = rust_source.blank_comments_and_strings(source)
                self.assertEqual(blanked.count("\n"), source.count("\n"))
                self.assertNotIn("still", blanked)
                self.assertIn("fn live() {}", blanked)

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
