# Working on fuzz-host

This repository holds tooling that runs on the continuous fuzz host for
[nifeos/nife](https://github.com/nifeos/nife). Some of it runs as root and handles a GitHub App's
private key, so the rules below are stricter than a library's.

## Rules

- nife's [`AGENTS.md`](https://github.com/nifeos/nife/blob/main/AGENTS.md) governs style and conduct
  here by adoption: UTC dates, no em-dashes, no contractions in prose, one purpose per commit with a
  `Co-Authored-By:` trailer, and a pull request an agent writes says so in its first line. Its
  developer-lane rules apply too: claim with a draft pull request, never merge, never poll CI.
- Every name here is provisional, the repository's own included. Say so beside anything you mint.
- Facts true only of one physical machine (a host name, an address, a serial number, a local path)
  stay out of this repository. The maintainers keep them off-tree. Write instructions for any
  reader: "the fuzz host", "your machine".
- No lane opens, reads, copies or looks for a real key or a real token, and no lane runs anything on
  the fuzz host. A person installs what this repository ships. Selftests make their own throwaway
  keys and talk to a local stub, never to GitHub.
- A helper that holds a secret never puts it in argv, in the journal, in an error message or on
  standard output. A selftest proves that for each one.
- Python's standard library and the `openssl` binary are the dependencies. Any other one needs an
  architect's ruling first.

## What gates this repository

`script/test` runs every selftest under `tests/`. `.github/workflows/selftest.yml` runs it on every
pull request and merge group, and the main ruleset requires it.
