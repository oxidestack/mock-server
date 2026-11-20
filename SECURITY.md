# Security policy

mock-server stands in for the services a system under test talks to, and it can be exposed to networks, test
suites and clients it does not control, so a vulnerability in it matters. Please report one privately, and give us
the chance to fix it before it is public.

## Reporting a vulnerability

Report it through GitHub's private vulnerability reporting: on the repository's **Security** tab, choose
**Report a vulnerability**, or go straight to
[the form](https://github.com/oxidestack/mock-server/security/advisories/new). Only the maintainers see the report.

**Do not open a public issue, discussion or pull request for a vulnerability.**

What helps us most:

- the version: the image tag or digest, or the commit you built;
- how it is deployed: `docker run`, Docker Compose, Kubernetes or Testcontainers, and the settings you changed
  (properties, environment variables, command-line flags);
- what an attacker sends and what happens: the request, the expectation or the control-plane call that triggers it;
- what it lets an attacker do: read a file, reach the network, run code, exhaust memory or CPU, take down the server.

## What happens next

We answer in the report's thread, confirm the problem or explain why it is not one, and agree with you on a fix and a
date to disclose it. The fix is released with a GitHub security advisory, a CVE where one applies, and an entry in
the release notes; you are credited in the advisory unless you would rather not be.

## Supported versions

Security fixes go into the latest release. Upgrade to it to get them; earlier releases are not patched.

## What is in scope

- The server: its control plane and data plane, its TLS, HTTP/2, HTTP/3, gRPC, DNS and proxy listeners, the callback
  plugins it loads, and the dashboard it serves.
- The container image as published.

mock-server is meant to run in test and development environments. The control plane is not authenticated unless you
configure it to be: exposing it to an untrusted network without that, or loading a callback plugin you did not
write, is a deployment decision rather than a vulnerability. A behaviour that differs from MockServer's is a bug, to
report as one, unless it also breaks a security boundary.

A vulnerability in MockServer itself belongs to the [MockServer project](https://github.com/mock-server/mockserver-monorepo).
If it also affects mock-server, report it here too.
