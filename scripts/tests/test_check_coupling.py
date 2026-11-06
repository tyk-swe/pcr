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

    def test_cancellation_polls_count_every_receiver_spelling(self):
        root = self.workspace({
            "crates/packetcraftr-core/src/protocol/catalog.rs":
                'Foo { canonical: "foo", aliases: [] }',
            "crates/packetcraftr-cli/src/a.rs":
                "fn f() { invocation.check()?; control.check()?; i.check()?; }\n"
                "fn g() { invocation\n    .check_interrupted()?; }\n"
                "fn h() { invocation.control.cancellation.check()?; }\n"
                "#[cfg(test)]\nmod tests { fn t() { invocation.check()?; } }\n",
            "crates/packetcraftr-cli/src/invocation.rs":
                "fn f() { invocation.check()?; }",
            "crates/packetcraftr/src/b.rs":
                "fn f() { invocation.check()?; }",
        })
        measured = coupling.inventory(root)
        self.assertEqual(measured["manual_cancellation_polls"], 5)

    def test_repository_stays_under_ceilings(self):
        measured = coupling.inventory()
        for name, value in measured.items():
            self.assertLessEqual(value, coupling.CEILINGS[name], name)
        self.assertEqual(measured["make_layer_impls"], 0)
        self.assertEqual(measured["downcast_outside_allowlist"], 0)
        self.assertEqual(coupling.allowlist_problems(), [])


if __name__ == "__main__":
    unittest.main()
