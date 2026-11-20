"""Tests of tools/check-noncargo-licenses.py: the gate fails on a new non-allowlisted npm or Maven
dependency, passes on allowlisted ones, and keeps its exceptions exact."""
import pathlib
import subprocess
import sys
import tempfile
import unittest

TOOL = pathlib.Path(__file__).resolve().parent.parent / "check-noncargo-licenses.py"

NOTICES = """Third-party notices

COUNT packages:

{lines}

----
body
"""


def run(*args):
    p = subprocess.run([sys.executable, str(TOOL), *args], capture_output=True, text=True)
    return p.returncode, p.stdout + p.stderr


class Fixture(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = pathlib.Path(self.tmp.name)
        self.exc = self.dir / "exceptions.txt"
        self.exc.write_text("# none\n")

    def tearDown(self):
        self.tmp.cleanup()

    def npm(self, lines, count=None):
        n = self.dir / "notices.txt"
        n.write_text(NOTICES.format(lines="\n".join(lines)).replace("COUNT", str(count if count is not None else len(lines))))
        return run("--exceptions", str(self.exc), "npm", "--notices", str(n))


class NpmGate(Fixture):
    def test_allowlisted_and_or_expressions_pass(self):
        code, out = self.npm(["a@1.0.0  MIT", "b@2.0.0  (MPL-2.0 OR Apache-2.0)", "c@3.0.0  (Apache-2.0 AND MIT)"])
        self.assertEqual(code, 0, out)

    def test_new_non_allowlisted_package_fails(self):
        code, out = self.npm(["a@1.0.0  MIT", "evil@1.0.0  GPL-3.0-only"])
        self.assertEqual(code, 1)
        self.assertIn("evil@1.0.0", out)

    def test_and_needs_every_side(self):
        code, _ = self.npm(["x@1.0.0  (MIT AND EPL-2.0)"])
        self.assertEqual(code, 1)

    def test_missing_licence_fails(self):
        code, out = self.npm(["x@1.0.0  unspecified in package.json"])
        self.assertEqual(code, 1)
        self.assertIn("x@1.0.0", out)

    def test_exception_is_exact_version_and_licence(self):
        self.exc.write_text("npm x@1.0.0 EPL-2.0 none\n")
        self.assertEqual(self.npm(["x@1.0.0  EPL-2.0"])[0], 0)
        code, out = self.npm(["x@1.0.1  EPL-2.0"])
        self.assertEqual(code, 1)
        self.assertIn("x@1.0.1", out)
        self.assertIn("stale", out)
        self.assertEqual(self.npm(["x@1.0.0  GPL-3.0-only"])[0], 1)

    def test_stale_exception_fails(self):
        self.exc.write_text("npm gone@1.0.0 EPL-2.0 none\n")
        code, out = self.npm(["a@1.0.0  MIT"])
        self.assertEqual(code, 1)
        self.assertIn("stale", out)

    def test_unreadable_summary_exits_2(self):
        self.assertEqual(self.npm(["a@1.0.0  MIT"], count=5)[0], 2)

    def test_committed_notices_pass_with_committed_exceptions(self):
        code, out = run("npm")
        self.assertEqual(code, 0, out)


class MavenGate(Fixture):
    def pom(self, g, a, v, licences, parent=None):
        d = self.dir / "repo" / g.replace(".", "/") / a / v
        d.mkdir(parents=True, exist_ok=True)
        lic = "".join(f"<license><name>{n}</name></license>" for n in licences)
        par = (
            f"<parent><groupId>{parent[0]}</groupId><artifactId>{parent[1]}</artifactId><version>{parent[2]}</version></parent>"
            if parent
            else ""
        )
        licences_xml = f"<licenses>{lic}</licenses>" if licences else ""
        (d / f"{a}-{v}.pom").write_text(f'<project xmlns="http://maven.apache.org/POM/4.0.0">{par}{licences_xml}</project>')

    def maven(self, gavs):
        lst = self.dir / "list.txt"
        lst.write_text("\nThe following files have been resolved:\n" + "".join(f"   {g}\n" for g in gavs))
        return run("--exceptions", str(self.exc), "maven", "--list", str(lst), "--repo", str(self.dir / "repo"))

    def test_allowlisted_pass_and_inherited_from_parent(self):
        self.pom("org.p", "parent", "1", ["The Apache Software License, Version 2.0"])
        self.pom("org.p", "child", "1", [], parent=("org.p", "parent", "1"))
        self.pom("org.q", "mit", "2", ["MIT License"])
        code, out = self.maven(["org.p:child:jar:1:compile -- module x", "org.q:mit:jar:2:runtime -- module y"])
        self.assertEqual(code, 0, out)

    def test_new_non_allowlisted_dependency_fails(self):
        self.pom("org.q", "gpl", "1", ["GNU Lesser General Public License"])
        code, out = self.maven(["org.q:gpl:jar:1:compile -- module x"])
        self.assertEqual(code, 1)
        self.assertIn("org.q:gpl@1", out)

    def test_unknown_licence_name_and_missing_licence_fail(self):
        self.pom("org.q", "odd", "1", ["Some Bespoke Licence"])
        self.pom("org.q", "none", "1", [])
        code, out = self.maven(["org.q:odd:jar:1:compile -- m", "org.q:none:jar:1:compile -- m"])
        self.assertEqual(code, 1)
        self.assertIn("org.q:odd@1", out)
        self.assertIn("org.q:none@1", out)

    def test_test_scope_is_not_read(self):
        self.pom("org.q", "gpl", "1", ["GNU Lesser General Public License"])
        self.pom("org.q", "mit", "1", ["MIT License"])
        code, out = self.maven(["org.q:gpl:jar:1:test -- m", "org.q:mit:jar:1:compile -- m"])
        self.assertEqual(code, 0, out)

    def test_dual_licence_needs_one_allowed(self):
        self.pom("org.q", "dual", "1", ["MIT License", "GNU Lesser General Public License"])
        self.assertEqual(self.maven(["org.q:dual:jar:1:compile -- m"])[0], 0)

    def test_exception_is_exact_version(self):
        self.pom("org.q", "gpl", "1", ["GNU Lesser General Public License"])
        self.pom("org.q", "gpl", "2", ["GNU Lesser General Public License"])
        self.exc.write_text("maven org.q:gpl@1 LGPL-2.1-only none\n")
        self.assertEqual(self.maven(["org.q:gpl:jar:1:compile -- m"])[0], 0)
        self.assertEqual(self.maven(["org.q:gpl:jar:2:compile -- m"])[0], 1)


if __name__ == "__main__":
    unittest.main()
