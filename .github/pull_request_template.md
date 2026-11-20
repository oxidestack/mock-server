<!-- A pull request's description opens with its text, not a heading. -->
<!-- markdownlint-disable-file MD041 -->
<!--
What this changes, and why. Link the issue or discussion it comes from: "Closes: #123" in the commit's footer.
CONTRIBUTING.md says how to build, test and write the commits.
-->

- [ ] Every commit follows
      [the commit-message format](https://github.com/oxidestack/mock-server/blob/main/CONTRIBUTING.md#commit-messages)
      and is signed off (`git commit -s`).
- [ ] A `feat`, `fix`, `perf` or breaking commit carries a `release-note` block.
- [ ] A change in behaviour comes with a scenario recorded from the MockServer image the project is pinned to, or the
      test that failed before it.
- [ ] A difference from MockServer that remains is a row in `docs/divergences.md`.
- [ ] `cargo test` and `make tools-test` pass.
