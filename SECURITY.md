# Security policy

Report a security problem through GitHub's private vulnerability reporting on the repository it
concerns: the Security tab, "Report a vulnerability".

- A flaw in this repository's own code, for example a way for the mint helper to leak a key or a
  token, or to mint a token wider than it should: report it here, on nifeos/fuzz-host.
- A finding the fuzz host makes in nife (a crash, an escape, a shadow-model mismatch): report it on
  [nifeos/nife](https://github.com/nifeos/nife/security). The host files its own findings there as
  private advisories.

Please do not open a public issue for something you believe is exploitable. A real person reads
each report, not a triage queue.

Most of this code was written by AI agents working in parallel lanes, with one human reviewing
architecture and outcomes. The selftests under `tests/` state what each helper promises; a report
that shows a promise does not hold is also a bug in its test.

## Supported versions

The newest commit on main. The host runs a copy a person installed from it.
