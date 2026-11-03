# fuzz-host

Tooling for the continuous fuzz host: a dedicated machine that fuzzes
[nifeos/nife](https://github.com/nifeos/nife) all the time and reports what it finds.

nife's own tree holds the fuzz drivers and, for now, the supervisor that runs them. This repository
holds the pieces that run on the host but do not belong to the kernel's tree, starting with code
that runs as root. A person installs a root-owned copy of each piece outside any clone, so the
host's unattended update from nife's main branch never replaces it.

The maintainers keep the host's own specification (its name, address and hardware) off-tree.

## Layout

| path | what |
|---|---|
| `script/test` | runs every selftest under `tests/`; CI runs it on every pull request and merge group |
| `tests/` | the selftests; each one needs no network and no real credential |

## Running the tests

```sh
script/test
```

It needs `python3` and `openssl` and nothing else.

## Status

Every name here is provisional, the repository's own included, until the architect's naming pass
rules on it.

## License

MIT OR Apache-2.0, at your option: see `LICENSE-MIT` and `LICENSE-APACHE`.
