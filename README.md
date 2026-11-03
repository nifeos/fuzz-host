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
| `bin/fuzz-token` | mints one narrowed one-hour installation token of the fuzz host's GitHub App per service, from the App's root-only key ([docs/fuzz-token.md](docs/fuzz-token.md), with the install steps); its `reader` profile gives a fix lane, on the machine that launches it, a one-hour token that reads advisories ([docs/fuzz-token-reader.md](docs/fuzz-token-reader.md)) |
| `bin/fuzz-filer` | files one private security advisory on nifeos/nife per held fuzz finding, with the `filer` token ([docs/fuzz-filer.md](docs/fuzz-filer.md), with the install steps) |
| `systemd/` | `fuzz-token@.service` and `fuzz-token@.timer`, one instance per service; `fuzz-filer.service` and `fuzz-filer.timer` |
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
