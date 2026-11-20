#!/usr/bin/env python3
"""Tests of harvest.py's rewrite of B files: a re-harvest keeps what was added to a file by hand.

  python3 conformance/harvest/test_harvest.py      (or: python3 -m unittest discover -s conformance/harvest)

Needs no Maven run and no oracle: the harvest's input is synthesised from the committed scenario files, and so are
the hand-added options (the oracle re-pin left no `diverge` step in B1/B2, so the tests add their
own instead of depending on what the committed files happen to carry).
"""
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import harvest  # noqa: E402

UPSTREAM = os.path.join(harvest.ROOT, "tests", "scenarios", "upstream")
B1 = "B1-HttpStateTest.json"
B2 = "B2-ConfigurationSerializerTest.json"
HAND_AUTHORED = "B2-AbstractSchemaSerializerTest.json"


def load(name):
    with open(os.path.join(UPSTREAM, name), encoding="utf-8") as f:
        return json.load(f)


def strip(document):
    """`document` as a fresh harvest writes it: no hand-added document keys or step options."""
    fresh = {k: v for k, v in document.items() if k in ("source", "properties")}
    fresh["steps"] = [{k: v for k, v in s.items() if k in harvest.HARVESTED_STEP_KEYS} for s in document["steps"]]
    return fresh


def with_hand_options(document, n):
    """`document` with a hand-added `diverge` on its first `n` non-reset steps and an `isolated` document key, as a
    file adapted by hand after recording carries them."""
    document = json.loads(json.dumps(document))
    document.setdefault("isolated", True)
    marked = 0
    for step in document["steps"]:
        if marked < n and step["path"] != "/mockserver/reset":
            step["diverge"] = "test"
            marked += 1
    assert marked == n, f"fewer than {n} non-reset steps"
    return document


def dumped(document):
    return json.dumps(document, indent=1, ensure_ascii=False) + "\n"


class ReharvestB2(unittest.TestCase):
    """End to end through harvest.py's default mode: the recorded calls behind B2-ConfigurationSerializerTest (each
    case's `ConfigurationSerializer.deserialize`/`serialize` input, read back from the committed file) harvested again
    into a directory holding the committed file."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="harvest-319-")
        self.indir, self.out = os.path.join(self.tmp, "in"), os.path.join(self.tmp, "out")
        os.makedirs(self.indir)
        os.makedirs(self.out)
        self.previous = with_hand_options(load(B2), 3)
        with open(os.path.join(self.out, B2), "w", encoding="utf-8") as f:
            f.write(dumped(self.previous))
        shutil.copyfile(os.path.join(UPSTREAM, HAND_AUTHORED), os.path.join(self.out, HAND_AUTHORED))
        lines = {"deserialize": [], "serialize": []}
        for step in self.previous["steps"]:
            if step["path"] == "/mockserver/reset":
                continue
            method, _, rest = step["note"].partition(" (")
            kind = rest.split(")")[0]
            case = {"boundary": "org.mockserver.serialization.ConfigurationSerializer." + kind,
                    "test": "org.mockserver.serialization.ConfigurationSerializerTest#" + method, "input": step.get("body")}
            if kind == "serialize":
                case["class"] = "Configuration"
            lines[kind].append(case)
        for kind, cases in lines.items():
            with open(os.path.join(self.indir, kind + ".jsonl"), "w", encoding="utf-8") as f:
                f.writelines(json.dumps(c, ensure_ascii=False) + "\n" for c in cases)

    def tearDown(self):
        shutil.rmtree(self.tmp)

    def reharvest(self):
        run = subprocess.run([sys.executable, os.path.join(HERE, "harvest.py"), "--in", self.indir, "--out", self.out],
                             capture_output=True, text=True)
        self.assertEqual(run.returncode, 0, run.stderr)
        return run

    def written(self, name):
        with open(os.path.join(self.out, name), encoding="utf-8") as f:
            return f.read()

    def fresh_source(self):
        return f"harvested from mockserver-core {harvest.oracle_revision()} ConfigurationSerializerTest (conformance/harvest)"

    def test_keeps_diverge_steps_and_document_keys(self):
        self.reharvest()
        # byte for byte but the `source`, which names the harvested revision
        self.assertEqual(self.written(B2), dumped(dict(self.previous, source=self.fresh_source())))
        document = json.loads(self.written(B2))
        self.assertTrue(document["isolated"])
        self.assertEqual(sum(1 for s in document["steps"] if "diverge" in s), 3)

    def test_a_fresh_harvest_without_a_previous_file_has_no_diverge(self):
        # the control: the diverge steps come from the previous file, not from the harvest
        os.remove(os.path.join(self.out, B2))
        self.reharvest()
        document = json.loads(self.written(B2))
        self.assertFalse(any("diverge" in s for s in document["steps"]))
        # `isolated` is the harvest's own for a file that changes configuration (PUT /mockserver/configuration)
        expected = strip(dict(self.previous, source=self.fresh_source()))
        self.assertEqual(document, {"source": expected["source"], "isolated": True, "steps": expected["steps"]})

    def test_leaves_hand_authored_files(self):
        self.reharvest()
        with open(os.path.join(UPSTREAM, HAND_AUTHORED), encoding="utf-8") as f:
            self.assertEqual(self.written(HAND_AUTHORED), f.read())


class CarryOver(unittest.TestCase):

    def test_b1_and_b2_round_trip_byte_for_byte(self):
        for name in (B1, B2):
            previous = with_hand_options(load(name), 2)
            self.assertNotEqual(strip(previous), previous)
            self.assertEqual(dumped(harvest.carry_over(previous, strip(previous), name)), dumped(previous))

    def test_b1_diverge_steps_kept(self):
        previous = with_hand_options(load(B1), 2)
        diverging = [(s["case"], s["path"]) for s in previous["steps"] if "diverge" in s]
        self.assertEqual(len(diverging), 2)
        document = harvest.carry_over(previous, strip(previous), B1)
        self.assertEqual([(s["case"], s["path"]) for s in document["steps"] if "diverge" in s], diverging)

    def test_options_of_a_changed_step_are_reported_not_moved(self):
        previous = with_hand_options(load(B1), 1)
        fresh = strip(previous)
        index = next(i for i, s in enumerate(previous["steps"]) if "diverge" in s)
        fresh["steps"][index]["path"] = "/changed"
        warnings = []
        document = harvest.carry_over(previous, fresh, B1, warnings.append)
        self.assertNotIn("diverge", document["steps"][index])
        self.assertEqual(len(warnings), 1)
        self.assertIn(previous["steps"][index]["case"], warnings[0])
        self.assertIn("diverge", warnings[0])

    def test_harvested_keys_come_from_the_fresh_harvest(self):
        previous = {"source": "harvested from x", "steps": [{"method": "PUT", "path": "/a", "body": "old", "case": "c", "mask": []}]}
        fresh = {"source": "harvested from x", "steps": [{"method": "PUT", "path": "/a", "body": "new", "case": "c"}]}
        self.assertEqual(harvest.carry_over(previous, fresh)["steps"],
                         [{"method": "PUT", "path": "/a", "body": "new", "case": "c", "mask": []}])

    def test_a_harvested_mask_adds_to_the_hand_added_one(self):
        hand = {"regex": "\\d{4}", "replace": "<year>"}
        previous = {"source": "harvested from x", "steps": [{"method": "GET", "path": "/a", "case": "c", "mask": [hand]}]}
        fresh = {"source": "harvested from x", "steps": [{"method": "GET", "path": "/a", "case": "c", "mask": [harvest.TEMPLATE_NAME_MASK]}]}
        self.assertEqual(harvest.carry_over(previous, fresh)["steps"][0]["mask"], [hand, harvest.TEMPLATE_NAME_MASK])
        # a re-harvest of a file that already has both writes it unchanged
        previous["steps"][0]["mask"] = [hand, harvest.TEMPLATE_NAME_MASK]
        self.assertEqual(harvest.carry_over(previous, fresh)["steps"][0]["mask"], [hand, harvest.TEMPLATE_NAME_MASK])


class TemplateNameMask(unittest.TestCase):
    """A Velocity case that threw under the Java test answers with a failure that names the template
    (`at t13[line …`), counted on the shared server, so its request step carries the template-name mask."""

    HELPER = {"boundary": "TemplateHelper.call", "test": "org.mockserver.templates.engine.helpers.DateTemplateHelperTest#shouldRejectEmptyDate",
              "helper": "DateTemplateHelper", "method": "parse", "parameterTypes": ["java.lang.String"], "args": [""]}
    TEMPLATE = {"boundary": "TemplateEngine.executeTemplate", "test": "org.mockserver.templates.engine.velocity.VelocityTemplateEngineTest#x",
                "engine": "VelocityTemplateEngine", "template": "#set($x = $dates.parse('yesterday'))", "dto": "org.mockserver.serialization.model.HttpResponseDTO",
                "request": "{\"method\": \"GET\", \"path\": \"/a\"}", "configuration": {}}

    def request(self, steps):
        return next(s for s in steps if not s["path"].startswith("/mockserver"))

    def test_a_helper_that_threw_is_masked(self):
        steps, _ = harvest.convert_helper(dict(self.HELPER, thrown="java.lang.IllegalArgumentException", message="empty"))
        self.assertEqual(self.request(steps)["mask"], [harvest.TEMPLATE_NAME_MASK])

    def test_a_helper_that_returned_is_not(self):
        steps, _ = harvest.convert_helper(dict(self.HELPER, resultType="java.lang.String", result="x"))
        self.assertNotIn("mask", self.request(steps))

    def test_a_velocity_template_that_threw_is_masked(self):
        steps, _ = harvest.convert_template(dict(self.TEMPLATE, thrown="java.lang.RuntimeException", message="failed"))
        self.assertEqual(self.request(steps)["mask"], [harvest.TEMPLATE_NAME_MASK])

    def test_a_mustache_template_that_threw_is_not(self):
        case = dict(self.TEMPLATE, engine="MustacheTemplateEngine", thrown="java.lang.RuntimeException", message="failed")
        steps, _ = harvest.convert_template(case)
        self.assertNotIn("mask", self.request(steps))


class RenderFiles(unittest.TestCase):
    """A narrowed `--kinds render` run (one test class's cases) writes the render templates of the cases
    it converts and removes only the render files its own rewritten scenario files referenced; render files that
    other scenario files use, or that no owned file referenced, stay. With a non-default `--out` the render files go
    under `<out>/files`, never into the committed tests/files."""

    TEMPLATE = "narrowed run {{ request.path }}"

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="harvest-865-")
        self.indir, self.out = os.path.join(self.tmp, "in"), os.path.join(self.tmp, "out")
        os.makedirs(os.path.join(self.indir, "template"))
        os.makedirs(self.out)
        self.name = harvest.hashlib.sha1(self.TEMPLATE.encode()).hexdigest()[:12] + ".mustache"
        case = {"boundary": "TemplateEngine.renderTemplate", "test": "org.mockserver.templates.engine.mustache.NarrowedTest#x",
                "engine": "MustacheTemplateEngine", "template": self.TEMPLATE, "request": "{\"method\": \"GET\", \"path\": \"/a\"}",
                "configuration": {}}
        with open(os.path.join(self.indir, "template", "render.jsonl"), "w", encoding="utf-8") as f:
            f.write(json.dumps(case) + "\n")

    def tearDown(self):
        shutil.rmtree(self.tmp)

    def run_render(self, *extra):
        run = subprocess.run([sys.executable, os.path.join(HERE, "harvest.py"), "--kinds", "render", "--in", self.indir,
                              "--out", self.out, *extra], capture_output=True, text=True)
        self.assertEqual(run.returncode, 0, run.stderr)

    def scenario(self, name, render_files, source="harvested from x"):
        steps = [{"method": "PUT", "path": "/mockserver/expectation", "case": "c" + str(i),
                  "body": {"httpResponse": {"body": {"type": "FILE", "filePath": "{{files}}/harvest/render/" + file}}}}
                 for i, file in enumerate(render_files)]
        with open(os.path.join(self.out, name), "w", encoding="utf-8") as f:
            f.write(dumped({"source": source, "steps": steps}))

    def render_files(self, files):
        return sorted(os.listdir(os.path.join(files, "harvest", "render")))

    def test_a_scratch_out_leaves_the_committed_render_files_alone(self):
        committed = os.path.join(harvest.ROOT, "tests", "files", "harvest", "render")
        before = {name: os.path.getmtime(os.path.join(committed, name)) for name in os.listdir(committed)}
        self.run_render()
        self.assertEqual({name: os.path.getmtime(os.path.join(committed, name)) for name in os.listdir(committed)}, before)
        self.assertEqual(self.render_files(os.path.join(self.out, "files")), [self.name])
        with open(os.path.join(self.out, "files", "harvest", "render", self.name), encoding="utf-8") as f:
            self.assertEqual(f.read(), self.TEMPLATE)

    def test_only_the_rewritten_files_render_files_go(self):
        files = os.path.join(self.tmp, "files")
        render = os.path.join(files, "harvest", "render")
        os.makedirs(render)
        for name in ("old.mustache", "shared.vm", "other.vm", "hand.vm", "loose.vm"):
            with open(os.path.join(render, name), "w", encoding="utf-8") as f:
                f.write(name)
        # rewritten by the run: old.mustache goes, shared.vm stays (a file the run does not own still uses it)
        self.scenario("B3-render-NarrowedTest.json", ["old.mustache", "shared.vm"])
        self.scenario("B3-render-HandTest.json", ["hand.vm", "shared.vm"], source="hand-authored")
        self.scenario("B3-template-OtherTest.json", ["other.vm"])
        self.run_render("--files", files)
        # loose.vm: referenced by no scenario the run rewrote, so not the run's to remove
        self.assertEqual(self.render_files(files), sorted(["hand.vm", "loose.vm", "other.vm", "shared.vm", self.name]))
        with open(os.path.join(self.out, "B3-render-NarrowedTest.json"), encoding="utf-8") as f:
            self.assertIn("harvest/render/" + self.name, f.read())


class NarrowedRunInPlace(RenderFiles):
    """`--classes` names a narrowed run. It converts only those classes' cases and replaces or removes
    only the owned files whose `source` names them, so another class's scenario file and its render files stay; a run
    without it still removes every owned file of the kind that it did not produce."""

    def source(self, simple):
        return f"harvested from mockserver-core {harvest.oracle_revision()} {simple} (conformance/harvest)"

    def setup_two_classes(self):
        files = os.path.join(self.tmp, "files")
        render = os.path.join(files, "harvest", "render")
        os.makedirs(render)
        for name in ("old.mustache", "other.vm"):
            with open(os.path.join(render, name), "w", encoding="utf-8") as f:
                f.write("x")
        self.scenario("B3-render-NarrowedTest.json", ["old.mustache"], source=self.source("NarrowedTest"))
        self.scenario("B3-render-OtherTest.json", ["other.vm"], source=self.source("OtherTest"))
        with open(os.path.join(self.out, "B3-render-OtherTest.json"), "rb") as f:
            self.other = f.read()
        return files

    def test_a_narrowed_run_keeps_the_other_classes_files(self):
        files = self.setup_two_classes()
        self.run_render("--files", files, "--classes", "NarrowedTest")
        self.assertEqual(sorted(os.listdir(self.out)), ["B3-render-NarrowedTest.json", "B3-render-OtherTest.json"])
        with open(os.path.join(self.out, "B3-render-OtherTest.json"), "rb") as f:
            self.assertEqual(f.read(), self.other)
        self.assertEqual(self.render_files(files), sorted(["other.vm", self.name]))

    def test_a_narrowed_run_removes_its_own_class_when_nothing_converts(self):
        files = self.setup_two_classes()
        self.run_render("--files", files, "--classes", "NarrowedTest,GoneTest")
        os.remove(os.path.join(self.indir, "template", "render.jsonl"))
        open(os.path.join(self.indir, "template", "render.jsonl"), "w").close()
        self.run_render("--files", files, "--classes", "NarrowedTest")
        self.assertEqual(sorted(os.listdir(self.out)), ["B3-render-OtherTest.json"])
        self.assertEqual(self.render_files(files), ["other.vm"])

    def test_a_run_without_classes_removes_every_owned_file_it_did_not_produce(self):
        files = self.setup_two_classes()
        self.run_render("--files", files)
        self.assertEqual(sorted(os.listdir(self.out)), ["B3-render-NarrowedTest.json"])
        self.assertEqual(self.render_files(files), [self.name])


class MockServerVersion(unittest.TestCase):
    """The harvest compiles upstream/mockserver's tests (pinned to the oracle's commit) against the
    mockserver jars of pom.xml's `mockserver.version`, so its default is oracle.env's `ORACLE_VERSION` and moves with
    every re-pin."""

    def test_the_pom_default_is_the_oracle_version(self):
        import xml.etree.ElementTree as ET
        ns = {"m": "http://maven.apache.org/POM/4.0.0"}
        pom = ET.parse(os.path.join(HERE, "pom.xml")).getroot()
        with open(os.path.join(harvest.ROOT, "oracle.env"), encoding="utf-8") as f:
            env = dict(line.strip().split("=", 1) for line in f if "=" in line and not line.startswith("#"))
        self.assertEqual(pom.find("m:properties/m:mockserver.version", ns).text, env["ORACLE_VERSION"])


class CassettePaths(unittest.TestCase):
    """A cassette file the harvest's tests wrote under its own `.tmp` directory is harvested under a placeholder
    directory, so a re-harvest on another machine writes no local path."""

    def convert(self, call):
        if "cassette" not in harvest.KINDS:
            harvest.load_kinds()
        case = {"boundary": "CassetteRegistry", "test": "t", "calls": [dict(call, registry=1)]}
        steps, reason = harvest.KINDS["cassette"].convert(case)
        self.assertIsNone(reason)
        return steps[0]

    def test_a_register_of_a_local_absolute_path_is_rewritten(self):
        local = os.path.join(HERE, ".tmp", "cassette.json")
        step = self.convert({"call": "register", "path": local, "expectationCount": 2})
        self.assertEqual(step["body"]["path"], "/tmp/harvest/cassette.json")

    def test_a_remove_of_a_local_absolute_path_is_rewritten(self):
        step = self.convert({"call": "remove", "path": os.path.join(HERE, ".tmp", "cassette.json")})
        self.assertEqual(step["path"], "/mockserver/cassettes?path=%2Ftmp%2Fharvest%2Fcassette.json")

    def test_other_paths_stay(self):
        step = self.convert({"call": "register", "path": ".tmp/n", "expectationCount": 1})
        self.assertEqual(step["body"]["path"], ".tmp/n")


if __name__ == "__main__":
    unittest.main()
