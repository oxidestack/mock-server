"""tools/ci/release.sh and tools/ci/publish-image.sh, the parts that need no registry and no network.

- `check <tag>`: a release tag needs Cargo.toml's version and scripts/release-check.sh's rule (a CHANGELOG.md section,
  and when it has Action required, its `## Upgrading to <version>` in the upgrade guide); a pre-release needs neither.
- `notes <version> [<digest>]`: the GitHub release's body, the CHANGELOG section then how to run and verify the image,
  naming quay.io and the release workflow's identity at the tag; a pre-release without a section carries Unreleased.
- `version` and `tags`: which tags a version publishes; `latest` and `mockserver-<version>` only for a release.

Needs only sh, sed and awk. The registry steps are exercised by tools/ci/release-dry-run.sh (Docker).
"""

import os
import re
import subprocess
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
RELEASE = os.path.join(ROOT, "tools", "ci", "release.sh")
PUBLISH = os.path.join(ROOT, "tools", "ci", "publish-image.sh")

with open(os.path.join(ROOT, "Cargo.toml"), encoding="utf-8") as f:
    VERSION = re.search(r'^version = "(.*)"$', f.read(), re.M).group(1)

IDENTITY = f"https://github.com/oxidestack/mock-server/.github/workflows/release.yml@refs/tags/v{VERSION}"


def run(script, *args, changelog=None, upgrading=None):
    with tempfile.TemporaryDirectory() as tmp:
        env = {k: v for k, v in os.environ.items() if k != "GITHUB_REPOSITORY"}
        for name, text in (("CHANGELOG", changelog), ("UPGRADING", upgrading)):
            if text is not None:
                env[name] = os.path.join(tmp, name)
                with open(env[name], "w", encoding="utf-8") as f:
                    f.write(text)
        return subprocess.run(["sh", script, *args], capture_output=True, text=True, env=env)


HEAD = "# Changelog\n\nThe head.\n\n"
UNRELEASED = "## Unreleased\n\n### Features\n\n- an unreleased entry\n\n"
SECTION = f"## [{VERSION}] - 2026-11-18\n\n### {{kind}}\n\n- an entry\n\n[{VERSION}]: https://example.org/compare\n"
GUIDE = "# Upgrading\n\n## How to upgrade\n"


class Check(unittest.TestCase):
    def test_action_required_without_its_section_fails(self):
        done = run(RELEASE, "check", f"v{VERSION}", changelog=HEAD + SECTION.format(kind="Action required"),
                   upgrading=GUIDE)
        self.assertEqual(done.returncode, 1, done.stderr)
        self.assertIn(f"has no ## Upgrading to {VERSION}", done.stderr)

    def test_action_required_with_its_section_passes(self):
        done = run(RELEASE, "check", f"v{VERSION}", changelog=HEAD + SECTION.format(kind="Action required"),
                   upgrading=GUIDE + f"\n## Upgrading to {VERSION}\n")
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertEqual(done.stdout.strip(), VERSION)

    def test_a_release_without_a_section_fails(self):
        done = run(RELEASE, "check", f"v{VERSION}", changelog=HEAD + UNRELEASED, upgrading=GUIDE)
        self.assertEqual(done.returncode, 1, done.stderr)
        self.assertIn(f"no section ## [{VERSION}]", done.stderr)

    def test_a_release_cargo_toml_does_not_name_fails(self):
        done = run(RELEASE, "check", "v99.0.0", changelog=HEAD + "## [99.0.0]\n\n- x\n", upgrading=GUIDE)
        self.assertEqual(done.returncode, 1, done.stderr)
        self.assertIn(f"Cargo.toml's version is {VERSION}, the tag says 99.0.0", done.stderr)

    def test_a_pre_release_needs_nothing(self):
        done = run(RELEASE, "check", "v9.2.0-rc.1", changelog="", upgrading="")
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertEqual(done.stdout.strip(), "9.2.0-rc.1")

    def test_a_tag_that_is_no_version_is_refused(self):
        done = run(RELEASE, "check", "9.2.0")
        self.assertEqual(done.returncode, 2, done.stderr)


class Notes(unittest.TestCase):
    def test_the_section_then_run_and_verify(self):
        done = run(RELEASE, "notes", VERSION, "sha256:" + "0" * 64,
                   changelog=HEAD + UNRELEASED + SECTION.format(kind="Bug fixes"))
        self.assertEqual(done.returncode, 0, done.stderr)
        body = done.stdout
        self.assertTrue(body.startswith("### Bug fixes\n\n- an entry\n"), body[:200])
        self.assertNotIn(f"[{VERSION}]: https://", body)
        self.assertNotIn("unreleased entry", body)
        self.assertIn(f"docker run --rm -p 1080:1080 quay.io/oxidestack/mock-server:{VERSION}\n", body)
        self.assertIn("(`sha256:" + "0" * 64 + "`)", body)
        self.assertIn(f"--certificate-identity {IDENTITY} ", body)
        self.assertLess(body.index("## Run"), body.index("## Verify"))
        self.assertIn("cosign 3 or later", body)

    def test_a_pre_release_carries_the_unreleased_section(self):
        done = run(RELEASE, "notes", "9.2.0-rc.1", changelog=HEAD + UNRELEASED)
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertTrue(done.stdout.startswith("A pre-release of 9.2.0"), done.stdout[:200])
        self.assertIn("- an unreleased entry", done.stdout)
        self.assertIn("quay.io/oxidestack/mock-server:9.2.0-rc.1", done.stdout)

    def test_a_release_without_a_section_has_no_notes(self):
        done = run(RELEASE, "notes", "9.9.9", changelog=HEAD + UNRELEASED)
        self.assertEqual(done.returncode, 1, done.stderr)


class Tags(unittest.TestCase):
    def tags(self, version):
        done = run(PUBLISH, "tags", version)
        self.assertEqual(done.returncode, 0, done.stderr)
        return done.stdout.split()

    def test_a_release_moves_latest_and_mockservers_own_tag(self):
        self.assertEqual(self.tags("9.2.0"), ["9.2.0", "mockserver-9.2.0", "latest"])

    def test_a_pre_release_moves_nothing_else(self):
        self.assertEqual(self.tags("9.2.0-rc.1"), ["9.2.0-rc.1"])

    def test_versions(self):
        for tag, want in (("v9.2.0", "9.2.0"), ("v9.2.0-rc.1", "9.2.0-rc.1")):
            done = run(PUBLISH, "version", tag)
            self.assertEqual((done.returncode, done.stdout.strip()), (0, want), done.stderr)
        for tag in ("9.2.0", "v9.2", "v9.2.0+build", "v09.2.0"):
            self.assertEqual(run(PUBLISH, "version", tag).returncode, 2, tag)


if __name__ == "__main__":
    unittest.main()
