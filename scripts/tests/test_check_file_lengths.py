# Copyright (C) 2026 tyk-swe
# SPDX-License-Identifier: AGPL-3.0-only
import tempfile
import unittest
from pathlib import Path

from support import load_script

lengths = load_script("check_file_lengths")

RUST = """// header comment

fn one() {
    let a = 1; // trailing comment
    /* block
       comment */
    let b = 2;
}
"""

PYTHON = '''"""Module docstring.
More docstring."""
# a comment
x = 1  # trailing

def f():
    return x
'''


class CheckFileLengthsTests(unittest.TestCase):
    def workspace(self, files):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        for relative, text in files.items():
            path = root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text)
        return root

    def test_counting_excludes_comments_blanks_and_closing_only_lines(self):
        self.assertEqual(lengths.rust_code_lines(RUST), 3)
        self.assertEqual(lengths.python_code_lines(PYTHON), 3)

    def test_comment_markers_inside_strings_do_not_hide_code(self):
        text = 'fn f() {\n    let open = "/*";\n    let a = 1;\n    let close = "*/";\n}\n'
        self.assertEqual(lengths.rust_code_lines(text), 4)
        raw = 'const S: &[u8] = br#"a" /*"#;\nlet a = 1;\nlet b = 2;\n'
        self.assertEqual(lengths.rust_code_lines(raw), 3)

    def test_oversized_non_test_file_fails_but_test_file_only_ranks(self):
        big = "\n".join(f"let v{i} = {i};" for i in range(20))
        root = self.workspace({
            "crates/x/src/big.rs": big,
            "crates/x/src/tests.rs": big,
            "crates/x/src/small.rs": "fn f() {}",
        })
        rows = lengths.rank_files(root)
        bad = lengths.violations(rows, 10)
        self.assertEqual([row["path"] for row in bad], ["crates/x/src/big.rs"])
        rendered = "\n".join(lengths.render(rows, 10, 2))
        self.assertIn("files over 10 code lines: 2 total, 1 non-test", rendered)

    def test_target_named_sources_count_but_build_output_is_skipped(self):
        big = "\n".join(f"let v{i} = {i};" for i in range(20))
        root = self.workspace({
            "crates/x/src/target/model.rs": big,
            "crates/x/src/protocol/target/model.rs": big,
            "crates/x/target/generated.rs": big,
        })
        rows = lengths.rank_files(root)
        self.assertEqual(
            sorted(row["path"] for row in rows),
            ["crates/x/src/protocol/target/model.rs", "crates/x/src/target/model.rs"],
        )
        self.assertEqual(
            sorted(row["path"] for row in lengths.violations(rows, 10)),
            ["crates/x/src/protocol/target/model.rs", "crates/x/src/target/model.rs"],
        )

    def test_ranking_orders_by_size_then_path(self):
        root = self.workspace({
            "crates/x/src/b.rs": "let a = 1;\nlet b = 2;",
            "crates/x/src/a.rs": "let a = 1;",
        })
        rows = lengths.rank_files(root)
        self.assertEqual([row["path"] for row in rows],
                         ["crates/x/src/b.rs", "crates/x/src/a.rs"])


if __name__ == "__main__":
    unittest.main()
