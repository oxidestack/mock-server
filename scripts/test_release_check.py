"""`scripts/release-check.sh`: a release whose CHANGELOG.md section has Action required needs its
`## Upgrading to <version>` section in docs/guide/upgrading.md; a release that asks nothing, and a pre-release, do
not; without a tag the Unreleased section is checked leniently. Needs only sh and awk. Run:
python3 -m unittest discover -s scripts
"""

import os
import subprocess
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
SCRIPT = os.path.join(HERE, "release-check.sh")


def check(args, changelog, upgrading):
    with tempfile.TemporaryDirectory() as tmp:
        files = {}
        for name, text in (("CHANGELOG", changelog), ("UPGRADING", upgrading)):
            files[name] = os.path.join(tmp, name)
            with open(files[name], "w", encoding="utf-8") as f:
                f.write(text)
        env = {**os.environ, **files}
        return subprocess.run(["sh", SCRIPT, *args], capture_output=True, text=True, env=env)


def release(kind):
    return f"# Changelog\n\n## Unreleased\n\n## [1.2.3] - 2026-11-01\n\n### {kind}\n\n- an entry\n\n## [1.2.2]\n\n### Bug fixes\n"


GUIDE = "# Upgrading\n\n## How to upgrade\n"


class ReleaseCheck(unittest.TestCase):
    def test_action_required_without_its_section_fails(self):
        done = check(["v1.2.3"], release("Action required"), GUIDE + "\n## Upgrading to 1.2.2\n")
        self.assertEqual(done.returncode, 1, done.stderr)
        self.assertIn("has no ## Upgrading to 1.2.3", done.stderr)

    def test_action_required_with_its_section_passes(self):
        done = check(["v1.2.3"], release("Action required"), GUIDE + "\n## Upgrading to 1.2.3\n")
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertEqual(done.stdout.strip(), "1.2.3")

    def test_action_required_of_another_release_does_not_count(self):
        text = "## [1.2.3]\n\n### Bug fixes\n\n## [1.2.2]\n\n### Action required\n\n- x\n"
        self.assertEqual(check(["v1.2.3"], text, GUIDE).returncode, 0)
        self.assertEqual(check(["v1.2.2"], text, GUIDE).returncode, 1)

    def test_a_release_that_asks_nothing_needs_no_section(self):
        done = check(["v1.2.3"], release("Bug fixes"), GUIDE)
        self.assertEqual(done.returncode, 0, done.stderr)

    def test_a_release_without_a_changelog_section_fails(self):
        done = check(["v2.0.0"], release("Bug fixes"), GUIDE)
        self.assertEqual(done.returncode, 1, done.stderr)

    def test_a_pre_release_needs_nothing(self):
        done = check(["v1.2.3-rc.1"], "", "")
        self.assertEqual(done.returncode, 0, done.stderr)

    def test_a_pre_release_ignores_action_required(self):
        done = check(["v1.2.3-rc.1"], release("Action required"), GUIDE)
        self.assertEqual(done.returncode, 0, done.stderr)

    def test_unreleased_with_action_required_needs_some_section(self):
        text = "## Unreleased\n\n### Action required\n\n- x\n"
        self.assertEqual(check([], text, GUIDE).returncode, 1)
        done = check([], text, GUIDE + "\n## Upgrading to X.Y.Z (first release)\n")
        self.assertEqual(done.returncode, 0, done.stderr)

    def test_the_trees_own_files_pass(self):
        done = subprocess.run(["sh", SCRIPT], capture_output=True, text=True)
        self.assertEqual(done.returncode, 0, done.stderr)


if __name__ == "__main__":
    unittest.main()
