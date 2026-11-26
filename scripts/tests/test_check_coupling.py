# Copyright (C) 2026 tyk-swe
# SPDX-License-Identifier: AGPL-3.0-only
import tempfile
import unittest
from pathlib import Path

from support import load_script

coupling = load_script("check_coupling")


class CheckCouplingTests(unittest.TestCase):
    def workspace(self, files):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        for relative, text in files.items():
            path = root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text)
        return root

    def test_counts_production_sites_and_skips_tests(self):
        root = self.workspace({
            "crates/packetcraftr-core/src/protocol/catalog.rs":
                'Foo { canonical: "foo", aliases: [] }',
            "crates/mini/src/codec.rs":
                "use crate::thing::*;\nfn make_layer() {}\n"
                'fn f() { Id::new("foo"); layer.field("x"); Instant::now(); }',
            "crates/mini/src/tests.rs":
                "fn make_layer() {}\nfn g() { Instant::now(); }",
        })
        measured = coupling.inventory(root)
        self.assertEqual(measured["make_layer_impls"], 1)
        self.assertEqual(measured["glob_imports"], 1)
        self.assertEqual(measured["builtin_id_literals"], 1)
        self.assertEqual(measured["instant_now"], 1)
        self.assertEqual(measured["dynamic_field_sites"], 0)

    def test_checkout_under_a_tests_directory_keeps_its_sources(self):
        root = self.workspace({
            "tests/checkout/crates/mini/src/lib.rs": "",
            "tests/checkout/crates/mini/src/tests.rs": "",
            "tests/checkout/crates/mini/src/tests/case.rs": "",
        }) / "tests" / "checkout"

        self.assertEqual(
            [path.relative_to(root).as_posix() for path in coupling.production_sources(root)],
            ["crates/mini/src/lib.rs"],
        )

    def test_inline_tests_preserve_production_counts_and_exemptions(self):
        fixtures = (
            'Foo { canonical: "fixture", aliases: [] }\n'
            'pub const LIMIT: usize = 64;\n'
            'pub fn helper() {}\n'
            'use crate::thing::*;\n'
            'fn make_layer() {}\n'
            'fn sample_layout_wire() {}\n'
            'fn fixture() {\n'
            '    FieldLayout { name: "field" };\n'
            '    Id::new("foo"); layer.field("x");\n'
            '    Code::new("fixture.code");\n'
            '    Instant::now(); SystemTime::now(); getrandom();\n'
            '    layer.downcast_ref::<Tcp>(); control.check();\n'
            '}\n'
        )
        files = {
            relative: "" for relative in coupling.CRATE_ROOTS.values()
        } | {
            "crates/packetcraftr-core/src/protocol/catalog.rs":
                'Foo { canonical: "foo", aliases: [] }',
            "crates/packetcraftr-core/src/protocol/identity.rs": "",
            "crates/packetcraftr/src/identify/io.rs": "",
            "crates/mini/src/codec.rs": "",
            "crates/mini/src/plain.rs": 'fn live() { Id::new("fixture"); }',
        }
        root = self.workspace(files | {"crates/mini/src/tests.rs": fixtures})
        expected_counts = coupling.inventory(root)
        expected_problems = coupling.allowlist_problems(root)

        for relative, source in files.items():
            (root / relative).write_text(
                source + "\n#[cfg(all(test, unix))]\nmod tests {\n" + fixtures + "}\n"
            )

        self.assertEqual(coupling.inventory(root), expected_counts)
        self.assertEqual(coupling.allowlist_problems(root), expected_problems)

    def test_cast_outside_allowlist_is_counted(self):
        root = self.workspace({
            "crates/packetcraftr-core/src/protocol/catalog.rs":
                'Foo { canonical: "foo", aliases: [] }',
            "crates/packetcraftr-core/src/protocol/identity.rs":
                "fn f(layer: &dyn Layer) { layer.downcast_ref::<Tcp>(); }",
            "crates/mini/src/codec.rs":
                "fn f(layer: &dyn Layer) { layer.downcast_ref::<Tcp>(); }",
        })
        measured = coupling.inventory(root)
        self.assertEqual(measured["downcast_sites"], 1)
        self.assertEqual(measured["downcast_outside_allowlist"], 1)

    def test_stale_allowlist_entry_is_reported(self):
        root = self.workspace({
            "crates/packetcraftr-core/src/protocol/identity.rs":
                "fn f(layer: &dyn Layer) { layer.downcast_ref::<Tcp>(); }",
        })
        problems = coupling.allowlist_problems(root)
        self.assertTrue(
            any("stale cast allowlist entry: crates/packetcraftr-core/src/packet.rs"
                in problem for problem in problems)
        )
        self.assertFalse(any("identity.rs" in problem for problem in problems))

    def test_stale_boundary_exemption_is_reported(self):
        root = self.workspace({
            "crates/mini/src/codec.rs": 'fn f() { layer.field("x"); }',
        })
        problems = coupling.allowlist_problems(root)
        self.assertFalse(
            any("stale boundary exemption: codec.rs" in problem for problem in problems)
        )
        self.assertTrue(
            any("stale boundary exemption: template.rs" in problem for problem in problems)
        )

    def test_comments_neither_count_as_coupling_nor_keep_exemptions_alive(self):
        root = self.workspace({
            "crates/packetcraftr-core/src/protocol/identity.rs":
                "// layer.downcast_ref::<Tcp>();\n",
            "crates/mini/src/codec.rs": '/* layer.field("x"); */',
            "crates/mini/src/plain.rs": '/* layer.field("x"); Instant::now(); */',
        })
        measured = coupling.inventory(root)
        self.assertEqual(measured["downcast_sites"], 0)
        self.assertEqual(measured["dynamic_field_sites"], 0)
        self.assertEqual(measured["instant_now"], 0)
        problems = coupling.allowlist_problems(root)
        self.assertIn("stale cast allowlist entry: crates/packetcraftr-core/src/protocol/identity.rs", problems)
        self.assertIn("stale boundary exemption: codec.rs", problems)

    def test_duplicate_constant_literals_are_counted(self):
        root = self.workspace({
            "crates/packetcraftr-core/src/protocol/catalog.rs":
                'Foo { canonical: "foo", aliases: [] }',
            "crates/mini/src/a.rs":
                "pub const LIMIT: usize = 64;\npub const ALIAS: usize = LIMIT_PLACEHOLDER;\n",
            "crates/mini/src/b.rs":
                "pub const LIMIT: usize = 64;\npub const OTHER: usize = crate::a::LIMIT;\n",
        })
        measured = coupling.inventory(root)
        self.assertEqual(measured["duplicate_constants"], 1)

    def test_duplicate_wire_codes_detect_cross_crate_and_intra_file_collisions(self):
        root = self.workspace({
            "crates/packetcraftr-core/src/error/code.rs":
                'impl Code {\n'
                '    pub const Shared: Self = Self::new("io.shared");\n'
                '    pub const Unique: Self = Self::new("io.unique");\n'
                '}\n',
            "crates/packetcraftr/src/code.rs":
                'pub(crate) const Shared: Code = packetcraftr_core::error::Code::new("io.shared");\n'
                'pub(crate) const First: Code = Code::new("cli.twice");\n'
                'pub(crate) const Second: Code = Code::new(\n'
                '    "cli.twice",\n'
                ');\n'
                '// Code::new("io.unique")\n'
                '#[cfg(test)]\n'
                'pub(crate) const TestOnly: Code = Code::new("io.unique");\n',
            "crates/packetcraftr-cli/src/other.rs":
                'const A: OtherCode = OtherCode::new("io.unique");\n'
                'impl Other { const B: Self = Self::new("io.unique"); }\n',
        })
        sources = coupling.production_sources(root)
        self.assertEqual(
            coupling.duplicate_wire_codes(root, sources),
            {
                "cli.twice": [
                    "crates/packetcraftr/src/code.rs",
                    "crates/packetcraftr/src/code.rs",
                ],
                "io.shared": [
                    "crates/packetcraftr-core/src/error/code.rs",
                    "crates/packetcraftr/src/code.rs",
                ],
            },
        )
        self.assertEqual(coupling.inventory(root)["duplicate_wire_codes"], 2)

    def test_cancellation_polls_count_every_receiver_spelling(self):
        root = self.workspace({
            "crates/packetcraftr-core/src/protocol/catalog.rs":
                'Foo { canonical: "foo", aliases: [] }',
            "crates/packetcraftr-cli/src/a.rs":
                "// #[cfg(test)] appears only in this example\n"
                'const DOC: &str = "#[cfg(test)]";\n'
                "fn f() { invocation.check()?; control.check()?; i.check()?; }\n"
                "fn g() { invocation\n    .check_interrupted()?; }\n"
                "fn h() { invocation.control.cancellation.check()?; }\n"
                "#[cfg(test)]\nmod tests { fn t() { assert!(1 < 2); invocation.check()?; } }\n"
                "fn after_tests() { control.check()?; }\n",
            "crates/packetcraftr-cli/src/invocation.rs":
                "fn f() { invocation.check()?; }",
            "crates/packetcraftr/src/b.rs":
                "fn f() { invocation.check()?; }",
        })
        measured = coupling.inventory(root)
        self.assertEqual(measured["manual_cancellation_polls"], 6)

    def test_cancellation_polls_require_a_word_boundary(self):
        sources = {
            Path("crates/packetcraftr-cli/src/a.rs"):
                "fn f() { api.check()?; multi.check()?; i.check()?; "
                "invocation.check()?; self.i.check()?; }",
        }
        self.assertEqual(coupling.cancellation_polls(sources), 3)

    def test_cancellation_polls_preserve_token_boundaries(self):
        root = self.workspace({
            "crates/packetcraftr-cli/src/a.rs":
                "fn first() { return invocation\n    .check(); }\n"
                "fn second() { return control /* deadline */ . check_interrupted(); }\n",
        })
        measured = coupling.inventory(root)
        self.assertEqual(measured["manual_cancellation_polls"], 2)

    def test_cancellation_polls_ignore_comments_and_strings(self):
        root = self.workspace({
            "crates/packetcraftr-cli/src/a.rs":
                '// invocation.check();\n'
                'const EXAMPLE: &str = "cancellation.check()";\n',
        })
        measured = coupling.inventory(root)
        self.assertEqual(measured["manual_cancellation_polls"], 0)

    def test_repository_stays_under_ceilings(self):
        measured = coupling.inventory()
        for name, value in measured.items():
            self.assertLessEqual(value, coupling.CEILINGS[name], name)
        self.assertEqual(measured["make_layer_impls"], 0)
        self.assertEqual(measured["downcast_outside_allowlist"], 0)
        self.assertEqual(coupling.allowlist_problems(), [])


if __name__ == "__main__":
    unittest.main()
