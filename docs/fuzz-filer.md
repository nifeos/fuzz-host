# fuzz-filer: one private advisory per held finding

*Name: provisional, as are the subcommands, the unit names, the paths `/usr/local/bin/fuzz-filer`
and `/var/lib/fuzz-filer/ledger.tsv`, the finding id's form, the package name `nife`, the range's
form and the advisory's wording.*

nife's continuous fuzz supervisor holds every window that is not clean: a `replay:` line (a
shadow-model mismatch or an escape), a panic, or a guest that ran out its bound. It moves the
window's log into its held directory, `$NIFE_FUZZ_HOME/state/held/`, mode 0700, and writes a row to
`state/windows.tsv`. An architect ruled on 2026-11-01 (UTC) that a plain program on the host, not
an agent, files each held finding as a private security advisory on nifeos/nife, and that a fix lane
reads the advisory and never the held directory. `fuzz-filer` is that program.

## What it does

`fuzz-filer run`, started by `fuzz-filer.timer` every 30 minutes:

1. Reads the `filer` token file that `fuzz-token` writes, `/run/fuzz-token/filer.env`, and refuses
   it before it opens anything else unless it is a regular file (not a link) owned by root, mode
   0440, group `fuzz-token-filer`, recording the permissions `repository_advisories:write` and the
   repositories `nifeos/nife` alone, with at least 10 minutes and at most an hour left. It never
   reads the App key.
2. Takes its ledger's lock, so two runs never overlap.
3. Reads each held log and names the finding by its content: the first 16 hexadecimal digits of the
   SHA-256 of the log. The same log under two names is one finding.
4. For each finding the ledger does not record as filed, reads its window's row from
   `windows.tsv` (driver, commit, class, time) and checks that the log and the row describe the same
   window. A finding that does not agree is refused by id and age, and the others go on.
5. Lists the repository's advisories once and reads each one's `Finding:` line. A finding already
   on GitHub is recorded as filed and never created again. A failed listing files nothing.
6. Creates one draft advisory per remaining finding, writing `pending` to the ledger before the
   call and `filed` with the advisory id after it, and checks that GitHub's answer is a draft that
   names a package and a range.

### The advisory

| field | value |
|---|---|
| summary | `Held fuzz finding <id> (<class>, <driver> driver)`; no seed |
| description | the finding id, class (`held-finding`, `held-crash` or `held-hang`), driver, commit, seed, the time it was held and the one-line replay command |
| package | ecosystem `other`, name `nife` |
| `vulnerable_version_range` | `<= <commit>`, the commit the window ran at |
| `patched_versions` | not set: no fix is known when a finding is filed; the publish milestone sets it |

GitHub refuses to publish an advisory without a package and a range (HTTP 422, "Advisory is not
publishable"); a permission test on 2026-11-03 (UTC) showed create 201, adding a range 200 and
publish 200. The filer therefore files both from the start.

For a `held-finding` the seed is the one on the log's `replay:` line, and the replay command runs
that seed alone. For a crash or a hang, which print no replay line, it is the window's first seed
and the supervisor's count, 1000000. The replay command, run in a checkout of the commit, is:

```sh
NIFE_SYSCALL_FUZZ_SEEDS=<seed>:1 NIFE_TEST_FILTER=seeded_syscalls NIFE_TEST_FILTER_ACROSS_IMAGES=1 cargo xtask test
```

with `NIFE_CONFINED_FUZZ_SEEDS` and `a_confined_fuzzer` for the confined driver.

### The ledger

`/var/lib/fuzz-filer/ledger.tsv`, owned by the account the filer runs as, mode 0600, in a directory
of mode 0700 that systemd's `StateDirectory=` makes. Each line is

```
<utc>	<finding id>	pending|filed	<advisory id or ->
```

and the last line of a finding wins. A line of any other shape stops every run until a person mends
it. The ledger holds no seed, no held log's name and no advisory text. `ledger_state()` in
`bin/fuzz-filer` is the one reader of this format; a program that reads the ledger (the publish
milestone will) imports it rather than parsing the file itself. `fuzz-filer ledger` prints each
finding's id, state, advisory id and age.

The ledger sits outside the held directory, where the proposal put it, because nife's daily report
counts every file under the held directory as a finding; a ledger there would raise that count by
one.

## What it never does

- It never writes a seed, an input, a held log's name, a replay line or an advisory's text to
  standard output, standard error, the journal or the ledger. Its lines name finding ids, ages,
  advisory ids, counts and HTTP statuses. A held log's name carries its window's first seed, so it is
  withheld too. Every line passes through a filter that replaces each seed, name and token the run
  has seen, and an error answer to a create prints only GitHub's field names and error codes,
  because its message may echo the advisory.
- It never files a finding twice: the ledger and the listing both have to miss it.
- It never reads the App key, and it refuses a token of the wrong profile or a stale one before it
  opens the held directory.
- It never follows an HTTP redirect, and it talks to `https://api.github.com` and nothing else,
  except plain http to a literal loopback address, which exists for the selftest's stub. It follows a
  listing's `next` link only back to the same listing.
- It never publishes, edits or closes an advisory. Publishing after a clean rerun is a separate
  milestone.

### Rate

It creates at most 10 advisories a run (`--max`), one a second, and lists at most 50 pages. It stops
the run, exit status 75, when GitHub reports fewer than 100 requests left this hour or answers 403
or 429 for a rate limit; the next run continues where it stopped. An idle run, with nothing to file,
sends no request at all.

### Exit status

0: every finding is filed. 1: something was refused; each refusal is a journal line naming the
finding id and age. 75: a rate limit stopped the run. 3: a refusal of the whole run (the token, the
ledger, the held directory or `windows.tsv`), before anything is sent. 4: an internal error, printed
without its message.

`tests/fuzz-filer-selftest` holds each of these against a synthetic held directory, built in the
test with planted seeds, and a fake GitHub on 127.0.0.1.

## Which account it runs as

Ruled 2026-11-03: the filer keeps `User=lane`, the account that also runs the fuzzed code. That is
the only account that can read the held directory today: the supervisor makes it mode 0700 before
every window, inside the fuzz account's home, which no other account can enter.

**Accepted risk.** The host runs main's code unattended as that account, and the filer token lets
its holder create, edit and publish any advisory on nifeos/nife. So code that reaches main runs as
an account able to read the filer token, and could publish a held finding before its fix. A
published advisory cannot be unpublished. The protection is that main requires pull requests and
checks.

Ruled 2026-11-03: tokens stay at one hour, and no long-lived credential is kept for the filer.

A separate account (for example `fuzz-filer`) would keep the token from the fuzz account; the mint
helper already supports it with no change ([fuzz-token.md](fuzz-token.md#giving-a-profile-its-own-account)).
But that account cannot read the held directory unless the supervisor in nife changes: a held
directory shared with the filer's group, or a hand-off directory the supervisor writes for the
filer alone. Neither is in the proposal. Giving the filer `CAP_DAC_READ_SEARCH` instead would let it
read every file on the host, the App key included, so that is no option.

The filer itself does not care which account runs it: every path is a flag, and the ledger lives in
the unit's own state directory. Should the ruling change, the change here is the unit's `User=` and
`Group=` and the token's reader.

## Install, for a person with root on the fuzz host

Do this after the key is in place and `fuzz-token` is installed (steps P4 and P6 of nife's
`notes/fuzzing/finishing-the-setup.md`), and with the accepted risk above in mind.
Fetch this repository into your own account, not the fuzz account, and review the commit you
install.

```sh
sudo groupadd --system fuzz-token-filer
sudo usermod -a -G fuzz-token-filer lane
git -C ~/fuzz-host fetch origin
git -C ~/fuzz-host checkout --detach <the commit you reviewed>
~/fuzz-host/script/test
sudo install -o root -g root -m 0555 ~/fuzz-host/bin/fuzz-filer /usr/local/bin/fuzz-filer
sudo install -o root -g root -m 0644 ~/fuzz-host/systemd/fuzz-filer.service \
    ~/fuzz-host/systemd/fuzz-filer.timer /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now fuzz-token@filer.timer
sudo systemctl start fuzz-token@filer.service
sudo /usr/local/sbin/fuzz-token check filer
```

`check` must print `repositories: nifeos/nife`, `permissions: repository_advisories:write` and an
expiry about an hour ahead. Then look before filing. The dry run prints finding ids and ages and
sends nothing:

```sh
sudo install -d -o lane -g lane -m 0700 /var/lib/fuzz-filer
sudo -u lane env NIFE_FUZZ_HOME=/home/lane/fuzz /usr/local/bin/fuzz-filer run --dry-run
```

It names one `would file finding <id>` line per held finding, or `none to file`. Then turn it on:

```sh
sudo systemctl enable --now fuzz-filer.timer
sudo systemctl start fuzz-filer.service
```

Verify. After each command, the text after the colon is its expected output:

- `journalctl -u fuzz-filer.service -n 20`: one `filed finding <id> (held <age>) as GHSA-...` line
  per held finding, and no seed, file name or advisory text.
- `sudo -u lane /usr/local/bin/fuzz-filer ledger`: one `filed` line per held finding.
- <https://github.com/nifeos/nife/security/advisories>: one draft per held finding, made by
  `nife-fuzz[bot]`.
- `sudo systemctl start fuzz-filer.service` again, then the journal: `none to file`.
- `systemctl list-timers fuzz-filer.timer`: the next run within 30 minutes.

If a run fails, `journalctl -u fuzz-filer.service -n 20` names the refusal: the token file (its
owner, mode, group, profile or age), the ledger, a finding by id, or an HTTP status.

## Update or remove

To update, review the new commit and repeat the `checkout`, `script/test` and both `install` lines,
then `sudo systemctl daemon-reload`. To stop filing, `sudo systemctl disable --now
fuzz-filer.timer`. The ledger stays in `/var/lib/fuzz-filer`; keep it, or a later run relies on the
listing alone to avoid filing twice.

## BUGS

- The filer runs as the fuzz account, an accepted risk (above).
- No one has run it against GitHub or under systemd yet. `systemd-analyze verify` passes on the
  units; the first install confirms the hardening lines leave it working, and the first real create
  confirms that GitHub accepts `<= <commit>` as a range for the ecosystem `other` (unverified; a
  refusal is a 422 that names the field, and the finding stays pending).
- The count of a crash or hang window, 1000000, is copied from the supervisor's `ask`, because the
  supervisor records it in no row and no log line. If the supervisor changes it, this copy is wrong.
- The replay command is written from the supervisor's build steps; no fix lane has run one yet.
- `windows.tsv` sits outside the held directory and the fuzz account reads it; a held row's first
  seed plus its seed count is the held seed. Moving held rows under the held directory is a change
  to nife's supervisor, not to this program.
- The fuzz account can plant a log in its own held directory, and the filer files it as a private
  draft. That reaches no one outside the repository's security managers.
- Python cannot wipe memory, so the token stays in the process's heap until it exits.
