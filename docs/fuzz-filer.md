# fuzz-filer: one private advisory per held finding

*Name: provisional, as are the subcommands, the unit names, the paths `/usr/local/bin/fuzz-filer`,
`/var/lib/fuzz-filer/ledger.tsv`, `/usr/local/etc/fuzz-filer/rules.tsv` and `state/archived/`, the
finding id's form, the package name `nife`, the range's form, the advisory's wording, the kinds, and
the rules' actions and scopes.*

nife's continuous fuzz supervisor holds every window that is not clean: a `replay:` line (a
shadow-model mismatch or an escape), a panic, a guest whose own tick budget ran out, or a guest that
ran out its bound. It moves the
window's log into its held directory, `$NIFE_FUZZ_HOME/state/held/`, mode 0700, and writes a row to
`state/windows.tsv`. An architect ruled on 2026-11-01 (UTC) that a plain program on the host, not
an agent, files each held finding as a private security advisory on nifeos/nife, and that a fix lane
reads the advisory and never the held directory. `fuzz-filer` is that program.

The supervisor also replays a red shard of nife's CI fuzz job (`continuous-fuzz.sh --replay`) and
holds a reproduction the same way, with the slot `replay` in its row. The filer files it like any
held window. A clean replay's `replay-clean` row is neither a finding nor a refusal. The selftest
holds both.

## What it does

`fuzz-filer run`, started by `fuzz-filer.timer` every 30 minutes:

1. Reads the `filer` token file that `fuzz-token` writes, `/run/fuzz-token/filer.env`, and refuses
   it before it opens anything else unless it is a regular file (not a link) owned by root, mode
   0440, group `fuzz-token-filer`, recording the permissions `repository_advisories:write` and the
   repositories `nifeos/nife` alone, with at least 10 minutes and at most an hour left. It never
   reads the App key.
2. Reads the rules file, `/usr/local/etc/fuzz-filer/rules.tsv` (see [Rules](#rules)), and refuses
   the run if it is missing, is not root's, is writable by group or other, is a link, or holds a
   line it cannot read. Then it takes its ledger's lock, so two runs never overlap.
3. Reads each held log and names the finding by its content: the first 16 hexadecimal digits of the
   SHA-256 of the log. The same log under two names is one finding.
4. Groups the findings by cause. A log's signature is its driver, its class, the source file of its
   panic (without the line number) and the panic's message with its volatile parts replaced by
   placeholders (see [Normalization](#normalization)); the signature's short form is the first 12
   hexadecimal digits of the SHA-256 of those four fields.
   A log with no panic line falls back to its first line that names a panic or carries a replay
   command. A hang has neither, so in their place it takes the last line the guest printed (lines
   the host itself writes into the log, and nife's thread dump, are skipped), normalized the same
   way: hangs that stopped in different places stay different causes, and hangs that stopped at one
   place with different numbers are one. Only the oldest log of a signature is filed; the rest are counted in the ledger
   and not filed. A signature the ledger or an advisory already covers is not filed again. The
   filer prints signature short forms, kinds and counts, never the file or the message.
4b. Gives each log a kind and each cause a disposition, below ([Kinds](#kinds)): filed, parked, or
   suppressed by a rule. A parked or suppressed cause is printed as one line by signature, kind and
   count, and nothing is sent for it.
4a. For each cause not yet covered, reads its window's row from
   `windows.tsv` (driver, commit, class, time) and checks that the log and the row describe the same
   window. A finding that does not agree is refused, and the others go on. The oldest five
   refusals of each reason are printed by id and age; past five, one line gives the reason, its
   count and the ages of its oldest and newest. See [Joining a log to its row](#joining-a-log-to-its-row).
5. Lists the repository's advisories once and reads each one's `Finding:` line. A finding already
   on GitHub is recorded as filed and never created again, and its whole cause counts as covered. A failed listing files nothing.
6. Creates one draft advisory per remaining cause, at most `--max` a run, writing `pending` to the ledger before the
   call and `filed` with the advisory id after it, and checks that GitHub's answer is a draft that
   names a package and a range.

### Normalization

The message of one cause changes in every log: seeds, steps, actor numbers, the tick budget's
measurements, Debug values, addresses. Before it is hashed, in this order:

1. the `(replay: ...)` suffix is removed;
2. the whole Display of nife's `EveryCoreTickBudget`, `<ms> ms of the counter[ (the backstop)];
   ticks taken of <n> on each core: core <c> <n> ...`, becomes `<budget>`, so the milliseconds,
   whether the backstop decided, the budget and the number of online cores never split a cause;
3. each bracketed list, nested or not, becomes `[list]`;
4. each braced Debug body, nested or not, becomes `{..}`, and the type name before it stays;
5. each hexadecimal number, with `0x` or bare (six digits or more, with a digit and a letter), becomes
   `<hex>`;
6. each decimal number not glued to a letter becomes `<n>` (`u64` stays).

Every word stays, so two wait sites, two panics and two Debug variants (`Some(Parked)`, `None`)
stay apart. The thread dump that nife prints after a budget expiry's panic is on later lines and
never enters the message.

### Kinds

| kind | a log of it | filed |
|---|---|---|
| `replay` | a `held-finding` (a `replay:` line) that is not budget expiry | yes |
| `panic` | a `held-crash`, or a `held-hang` that panicked before its bound ran out | yes |
| `budget` | a `held-budget-expired` row (the guest's tick budget ran out), or any other class whose message is the seeded drivers' tick budget giving up (the text of nife's `EveryCoreTickBudget`, for rows written before that class existed) | parked |
| `hang` | a `held-hang` with no panic and no replay line | parked |

A parked cause is never filed on its own. A guest that runs out its bound with no panic, and a wait
that ran out of ticks, are as likely the host as the kernel, and a hang's last line is a weak
signature. Each run prints every parked cause by signature, kind and count, and the logs stay in
the held directory, so the daily report keeps counting them, until a person writes a rule: `file`
to file it, or `suppress` to set it aside.

### Joining a log to its row

A held log is named `<YYYYMMDDTHHMMSSZ>-<first seed>.log`, the UTC time its window started and its
first seed. Its row is a line of `windows.tsv` of eight tab-separated fields (`utc`, `driver`,
`slot`, `first`, `ran`, `ms`, `status`, `commit`) whose `first` equals the name's seed and whose
`status` is a `held-` class. The time is not part of the join. The filer refuses a log when:

- no such row exists (`windows.tsv holds no held row for it`): the row was never written, was
  removed, or `windows.tsv` was replaced or truncated since the log was held;
- two rows for it disagree on driver, commit or class;
- its row's class is not one this filer knows (`held-finding`, `held-crash`, `held-hang`,
  `held-budget-expired`), which means the supervisor is newer than the installed filer;
- its log and its row name different windows, or its replay line does not fit its row.

### Rules

The rules are a reviewed file in this repository, `etc/fuzz-filer/rules.tsv`, installed root-owned
at `/usr/local/etc/fuzz-filer/rules.tsv`. A rule changes only through a pull request here and a
person's install, so each one has a reviewer, a commit and a reason in git. One rule a line, five
fields separated by tabs:

```
<signature short form>	suppress|file	<scope>	<YYYY-MM-DD>	<reason>
```

- `suppress`: the cause is never filed, its logs never cover a cause, and `fuzz-filer archive`
  moves them out of the held directory. For a false positive whose fix has landed, or an
  infrastructure failure.
- `file`: a parked cause (budget or hang) is filed like any other.
- The scope says which logs of the signature the rule covers: `started-before=<UTC>` (logs whose
  window started before then, read from the log's name), or `commits=<commit>[,<commit>...]` (logs
  whose window ran at one of them, read from `windows.tsv`). `file` may also say `any`. A
  suppression cannot: it always ends, so a log of the same signature from a later window is a new
  cause. For a false positive, `started-before=` is the time the host took the fix, and a later log
  of that shape is filed, because it is not the false positive.
- The date is the day the rule was written, and the reason says why, and names what fixed it, if
  anything.
- A suppression wins over a `file` rule for the same log.

The file is public. A rule names a signature's short form, a scope and a reason, and nothing a held
log holds: no seed, message, source file or input. A cause that may be a real finding never gets a
suppress rule; that is what its advisory is for. To write one, run the dry run on the host, which
prints each cause's short form, kind and count, and open a pull request here with the rule. After it
merges, install the file (below), then archive.

### Archive

`fuzz-filer archive` moves every held log a suppress rule covers, each copy under every name, from
`state/held/` to `state/archived/<signature>/` (mode 0700, made if missing) under the same name, so
nife's daily report, which counts the held directory, stops counting it. `--dry-run` prints what
would move and moves nothing. It never overwrites an archived log, reads no token, sends nothing and
writes no ledger. It also names each rule that matches no held log, so a person can retire it.

A person runs it as the fuzz account (below). `fuzz-filer.service` never does: its `ProtectHome=read-only`
keeps the timer from writing the fuzz account's home, and archiving there would need that relaxed.
To bring an archived log back, move it back into `state/held/` and drop the rule.

### The advisory

| field | value |
|---|---|
| summary | `Held fuzz finding <id> (<class>, <driver> driver)`; no seed |
| description | the finding id, class (`held-finding`, `held-crash`, `held-hang` or `held-budget-expired`), driver, commit, seed, the time it was held and the one-line replay command |
| package | ecosystem `other`, name `nife` |
| `vulnerable_version_range` | `<= <commit>`, the commit the window ran at |
| `patched_versions` | not set: no fix is known when a finding is filed; the publish milestone sets it |

GitHub refuses to publish an advisory without a package and a range (HTTP 422, "Advisory is not
publishable"); a permission test on 2026-11-03 (UTC) showed create 201, adding a range 200 and
publish 200. The filer therefore files both from the start.

For a `held-finding`, and a `held-budget-expired` log that has a `replay:` line, the seed is the one
on that line, and the replay command runs that seed alone. For a crash, a hang, or a
`held-budget-expired` log with no replay line, it is the window's first seed and the supervisor's
count, 1000000. The replay command, run in a checkout of the commit, is:

```sh
NIFE_SYSCALL_FUZZ_SEEDS=<seed>:1 NIFE_TEST_FILTER=seeded_syscalls NIFE_TEST_FILTER_ACROSS_IMAGES=1 cargo xtask test
```

with `NIFE_CONFINED_FUZZ_SEEDS` and `a_confined_fuzzer` for the confined driver.

### The ledger

`/var/lib/fuzz-filer/ledger.tsv`, owned by the account the filer runs as, mode 0600, in a directory
of mode 0700 that systemd's `StateDirectory=` makes. Each line is

```
<utc>	<finding id>	pending|filed	<advisory id or ->	<signature short form>
<utc>	<signature short form>	cause	<advisory id>	<later logs>	<newest commit>
```

The first form is a finding; its fifth field is optional, because a ledger written before signatures
has four. The second is one cause: its advisory, how many later logs share its signature, and the
commit of the newest of them. The last line of a finding, and of a cause, wins. A line of any other shape stops every run until a person mends
it. The ledger holds no seed, no held log's name and no advisory text. `ledger_state()` in
`bin/fuzz-filer` is the one reader of this format; a program that reads the ledger (the publish
milestone will) imports it rather than parsing the file itself. `fuzz-filer ledger` prints each
finding's id, state, advisory id and age.

The ledger sits outside the held directory, where the proposal put it, because nife's daily report
counts every file under the held directory as a finding; a ledger there would raise that count by
one.

## What it never does

- It never writes a seed, an input, a held log's name, a replay line or an advisory's text to
  standard output, standard error, the journal or the ledger. Its lines name finding ids, ages, held class names,
  advisory ids, counts and HTTP statuses. A held log's name carries its window's first seed, so it is
  withheld too. Every line passes through a filter that replaces each seed, name and token the run
  has seen, and an error answer to a create prints only GitHub's field names and error codes,
  because its message may echo the advisory.
- It never files a finding twice: the ledger and the listing both have to miss it. Nor does it file
  a second advisory for a cause: the advisory body gains no detail for that, and the signature never
  appears in it.
- It never reads the App key, and it refuses a token of the wrong profile or a stale one before it
  opens the held directory.
- It never follows an HTTP redirect, and it talks to `https://api.github.com` and nothing else,
  except plain http to a literal loopback address, which exists for the selftest's stub. It follows a
  listing's `next` link only back to the same listing.
- It never publishes, edits or closes an advisory. A person publishes each advisory after its fix, on a
  separate machine.

### Rate

It creates at most 10 advisories a run (`--max`), one a second, and lists at most 50 pages.
`--max` may be from 1 to 25 and nothing else, so no run, the first included, creates more than 25.
The timer starts a run every 30 minutes, so a backlog of causes is filed at most 10 a run. It stops
the run, exit status 75, when GitHub reports fewer than 100 requests left this hour or answers 403
or 429 for a rate limit; the next run continues where it stopped. An idle run, with nothing to file,
sends no request at all.

### Exit status

0: every finding is filed (parked and suppressed causes are not refusals). 1: something was
refused; the oldest five refusals of each reason are journal lines naming the finding id and age,
and past five, one line counts the reason's findings. 75: a rate limit stopped the run. 3: a refusal of the whole run (the token, the
rules, the ledger, the held directory or `windows.tsv`), before anything is sent. 4: an internal error, printed
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

Do this after the key is in place and `fuzz-token` is installed (steps P5, "Generate the `nife-fuzz` key and place it on the fuzz
host", and P6, "Install the mint helper and its publish token", of nife's
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
expiry about an hour ahead. `sha256sum /usr/local/bin/fuzz-filer ~/fuzz-host/bin/fuzz-filer` must
print one digest twice: the installed filer is the reviewed one. Then install the rules and look
before filing:

```sh
sudo install -d -o root -g root -m 0755 /usr/local/etc/fuzz-filer
sudo install -o root -g root -m 0644 ~/fuzz-host/etc/fuzz-filer/rules.tsv /usr/local/etc/fuzz-filer/
sudo -u lane env NIFE_FUZZ_HOME=/home/lane/fuzz /usr/local/bin/fuzz-filer run --dry-run
```

The dry run reads no token, sends nothing and writes nothing: no ledger, no lock, no directory. A
ledger or ledger directory that does not exist yet reads as empty, and it can run at any time,
beside the timer. It prints one `would file finding <id> (held <age>) for cause <signature> (<kind>,
<count> held logs)` line per cause it would file, one `cause <signature> (<kind>): <count> held logs`
line per parked or suppressed cause and per filed cause of more than one log, the refusals counted
per reason, each rule that matches no held log, and a tally of held logs, causes, filed, parked,
suppressed and refused. A dry run that prints `would file finding <id> (held <age>)` with nothing
after it, and no `cause` line, is an older filer than this one: compare the installed binary with
the reviewed commit's (below). Write any rule those lines call for (see [Rules](#rules)), install it, and archive
what it suppresses:

```sh
sudo -u lane env NIFE_FUZZ_HOME=/home/lane/fuzz /usr/local/bin/fuzz-filer archive --dry-run
sudo -u lane env NIFE_FUZZ_HOME=/home/lane/fuzz /usr/local/bin/fuzz-filer archive
```

Then turn it on:

```sh
sudo systemctl enable --now fuzz-filer.timer
sudo systemctl start fuzz-filer.service
```

Verify. After each command, the text after the colon is its expected output:

- `journalctl -u fuzz-filer.service -n 20`: one `filed finding <id> (held <age>) as GHSA-... for
  cause <signature> (<count> held logs)` line per cause the dry run named, at most 10 a run, and no
  seed, file name or advisory text.
- `sudo -u lane /usr/local/bin/fuzz-filer ledger`: one `filed` line and one `cause` line per filed
  cause.
- <https://github.com/nifeos/nife/security/advisories>: one draft per filed cause, made by
  `nife-fuzz[bot]`.
- `sudo systemctl start fuzz-filer.service` again, then the journal: `none to file`, once every
  cause is filed.
- `systemctl list-timers fuzz-filer.timer`: the next run within 30 minutes.

If a run fails, `journalctl -u fuzz-filer.service -n 20` names the refusal: the token file (its
owner, mode, group, profile or age), the ledger, a finding by id, or an HTTP status.

## Update or remove

To update, review the new commit and repeat the `checkout`, `script/test` and every `install` line
(the binary, the units and the rules), then `sudo systemctl daemon-reload`, and check with
`sha256sum` that the installed binary is the reviewed one. After a rules change,
run `archive` as above. To stop filing, `sudo systemctl disable --now
fuzz-filer.timer`. The ledger stays in `/var/lib/fuzz-filer`; keep it, or a later run relies on the
listing alone to avoid filing twice.

## BUGS

- The filer runs as the fuzz account, an accepted risk (above).
- A filed cause covers every later log of its signature, even after its fix, so a regression of the
  same shape is counted toward the old advisory and not filed; the cause line's newest commit shows
  it. A suppression does not uncover a cause that is already filed.
- Budget expiry in a row written before `held-budget-expired` is recognized by the text of nife's
  `EveryCoreTickBudget`, copied into the filer. If nife rewords it, such a row is filed as a replay
  or a panic.
- A hang's cause is the guest's last line alone; two hangs at one place whose last lines differ in
  words are two parked causes.
- Words stay in a signature, Debug type and variant names included, so a wait site whose message
  prints `Some(Parked)` in one log and `None` in another is two causes.
- A change to the normalization re-keys the causes whose messages it touches. A filed finding still
  covers the cause of its own log while that log is held; a ledger cause line under the old key
  covers nothing new.
- Archiving is a person's step: the unit cannot write the fuzz account's home.
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
