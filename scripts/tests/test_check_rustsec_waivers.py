import importlib.util
import pathlib
import unittest


SCRIPT = pathlib.Path(__file__).parents[1] / "check-rustsec-waivers.py"
SPEC = importlib.util.spec_from_file_location("check_rustsec_waivers", SCRIPT)
assert SPEC is not None
assert SPEC.loader is not None
WAIVERS = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(WAIVERS)


class ExactDependencyPathTests(unittest.TestCase):
    ROOT = "root"
    RTNETLINK = "rtnetlink"
    ROUTE = "route"
    PROTO = "proto"
    CORE = "core"
    PASTE = "paste"
    EXPECTED_PATHS = (
        (ROOT, RTNETLINK, CORE, PASTE),
        (ROOT, RTNETLINK, ROUTE, CORE, PASTE),
        (ROOT, RTNETLINK, PROTO, CORE, PASTE),
    )

    @staticmethod
    def packages(*package_ids):
        return {
            package_id: {"name": package_id, "version": "1.0.0"}
            for package_id in package_ids
        }

    @staticmethod
    def nodes(extra_dependencies=()):
        dependencies = {
            ExactDependencyPathTests.ROOT: {
                ExactDependencyPathTests.RTNETLINK
            },
            ExactDependencyPathTests.RTNETLINK: {
                ExactDependencyPathTests.ROUTE,
                ExactDependencyPathTests.PROTO,
                ExactDependencyPathTests.CORE,
            },
            ExactDependencyPathTests.ROUTE: {ExactDependencyPathTests.CORE},
            ExactDependencyPathTests.PROTO: {ExactDependencyPathTests.CORE},
            ExactDependencyPathTests.CORE: {ExactDependencyPathTests.PASTE},
            ExactDependencyPathTests.PASTE: set(),
        }
        for parent_id, child_id in extra_dependencies:
            dependencies.setdefault(parent_id, set()).add(child_id)
            dependencies.setdefault(child_id, set())
        return {
            package_id: {
                "id": package_id,
                "deps": [{"pkg": dependency_id} for dependency_id in dependency_ids],
            }
            for package_id, dependency_ids in dependencies.items()
        }

    def validate(self, nodes):
        packages = self.packages(*nodes)
        WAIVERS.validate_exact_dependency_paths(
            nodes,
            packages,
            self.ROOT,
            self.PASTE,
            self.EXPECTED_PATHS,
        )

    def test_accepts_only_the_complete_expected_subgraph(self):
        self.validate(self.nodes())

    def test_rejects_an_additional_direct_path_to_paste(self):
        nodes = self.nodes(((self.ROOT, "unrelated"), ("unrelated", self.PASTE)))

        with self.assertRaisesRegex(SystemExit, "unexpected packages: unrelated"):
            self.validate(nodes)

    def test_rejects_an_additional_transitive_path_to_shared_core(self):
        nodes = self.nodes(((self.ROOT, "unrelated"), ("unrelated", self.CORE)))

        with self.assertRaisesRegex(SystemExit, "unexpected packages: unrelated"):
            self.validate(nodes)


if __name__ == "__main__":
    unittest.main()
