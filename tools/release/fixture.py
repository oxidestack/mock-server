"""A throwaway git history for the tests of `make release-notes`: one commit of every kind the draft treats
differently, after a tagged release whose commits it must leave out.

    python3 tools/release/fixture.py <empty directory> [--untagged]

Every author, committer and date is fixed, so the commit hashes, and the draft's entries that name them, are the same
on every machine. `--untagged` leaves out the tag: the history of a first release.
"""

import os
import re
import subprocess
import sys
import tomllib

# The repository's root: cliff.toml's header is the fixture's CHANGELOG.md, the file the draft is prepended to.
ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

SIGN_OFF = "Signed-off-by: Jane Doe <jane@example.org>"

# (message, the tag put on that commit or None), oldest first. The bodies follow the commit format: the release-note
# block is the body's last paragraph, the footers one trailer block after it.
COMMITS = [
    ("chore: start the public history", None),
    (
        "feat(control): accept an expectation file in YAML\n\n"
        "```release-note\nAn expectation initialisation file may be YAML as well as JSON.\n```",
        "v9.2.0",
    ),
    (
        "feat(k8s-webhook): add a priorityClassName value\n\n"
        "```release-note\nThe webhook's chart takes `priorityClassName` for its pods.\n```",
        None,
    ),
    (
        "fix(forward): retry a request whose connection was reset\n\n"
        "A reset connection failed the forwarded request at once, so a client\n"
        "saw a 502 for a transient fault.\n\n"
        "```release-note\n"
        "A forwarded request whose connection is reset is retried, so a client\n"
        "no longer sees a 502 for a transient fault.\n"
        "```",
        None,
    ),
    (
        "feat(config)!: drop the mockserver.workers alias\n\n"
        "```release-note\n"
        "`mockserver.workers` is no longer read. A deployment that sets it\n"
        "sets `MOCK_SERVER_WORKERS` (or `WORKERS`) to the same value instead.\n"
        "```\n\n"
        "BREAKING-CHANGE: a deployment that sets mockserver.workers must set\n"
        " MOCK_SERVER_WORKERS instead; the value is unchanged.",
        None,
    ),
    (
        "fix(control): close the body file before the matcher reads it\n\n"
        "No release has carried the bug.\n\n"
        "```release-note\nNONE\n```",
        None,
    ),
    ("build(deps): bump tokio from 1.47.1 to 1.48.0", None),
    (
        "perf(templates): compile each Velocity template once\n\n"
        "```release-note\nAn expectation with a Velocity template answers faster and in less memory.\n```",
        None,
    ),
    (
        "docs: describe the mounted initialisation directory\n\n"
        "```release-note\nThe guide says how to load expectations without rebuilding the image.\n```",
        None,
    ),
    (
        "fix: answer 413 when the request body is larger than the limit\n\n"
        "```release-note\nA request body over the size limit is answered 413 instead of 400.\n```",
        None,
    ),
    ("test(matcher): cover the empty body", None),
    # An issue reference is a footer after the block (`Closes: #<n>`), and the entry is drafted.
    (
        "fix(control): name the request's trace in an error answer\n\n"
        "```release-note\nAn error answer names the request's trace_id, as its log line does.\n```\n\n"
        "Closes: #3",
        None,
    ),
    # The same reference as a paragraph before the block: git-cliff's parser starts the footers there (`Token #value`
    # is a footer too), so the block is not in the body and the draft has no entry. The commit gate refuses this one
    # (release-note-place); the fixture holds git-cliff to the behaviour the rule guards against.
    (
        "fix(control): answer 400 for an expectation that is not JSON\n\n"
        "Closes #4\n\n"
        "```release-note\nAn expectation that is not JSON is answered 400 instead of 500.\n```",
        None,
    ),
]


def git(repo, *args, when=None):
    env = {
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "HOME": repo,
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_AUTHOR_NAME": "Jane Doe",
        "GIT_AUTHOR_EMAIL": "jane@example.org",
        "GIT_COMMITTER_NAME": "Jane Doe",
        "GIT_COMMITTER_EMAIL": "jane@example.org",
    }
    if when:
        env["GIT_AUTHOR_DATE"] = env["GIT_COMMITTER_DATE"] = when
    subprocess.run(["git", "-C", repo, *args], env=env, check=True, capture_output=True)


def build(repo, tagged=True):
    """Builds the history in `repo`, an empty directory; its CHANGELOG.md is the repository's head alone (cliff.toml's
    header), without the releases the repository's file has drafted since."""
    git(repo, "init", "-q", "-b", "main")
    with open(os.path.join(ROOT, "cliff.toml"), "rb") as src:
        changelog = tomllib.load(src)["changelog"]["header"]
    for n, (message, tag) in enumerate(COMMITS):
        when = f"2026-01-{n + 1:02d}T12:00:00+00:00"
        name = "CHANGELOG.md" if n == 0 else f"change-{n:02d}.txt"
        with open(os.path.join(repo, name), "w", encoding="utf-8") as out:
            out.write(changelog if n == 0 else f"{n}\n")
        git(repo, "add", name)
        # The sign-off joins a footer block the message's body ends with, as `git commit -s` does.
        footers = "\n\n" in message and re.match(r"[A-Za-z-]+: ", message.rsplit("\n\n", 1)[-1])
        sep = "\n" if footers else "\n\n"
        git(repo, "commit", "-q", "--cleanup=verbatim", "-m", f"{message}{sep}{SIGN_OFF}", when=when)
        if tag and tagged:
            git(repo, "tag", tag, when=when)


if __name__ == "__main__":
    if len(sys.argv) not in (2, 3) or (len(sys.argv) == 3 and sys.argv[2] != "--untagged"):
        sys.exit(__doc__)
    build(sys.argv[1], tagged=len(sys.argv) == 2)
