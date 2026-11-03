# fuzz-token: one narrowed token per service, from the App key

*Name: provisional, as are the profile names `publish` and `filer`, the unit names and the paths
`/usr/local/sbin/fuzz-token` and `/run/fuzz-token`.*

The fuzz host acts on nifeos/nife as the `nife-fuzz` GitHub App (App ID 5571801, installation ID
177641059; neither is secret). The App's private key sits on the host at
`/etc/nife-fuzz/nife-fuzz.private-key.pem`, readable by root alone. `fuzz-token` turns that key into
one-hour installation tokens, one per service, each holding less than the App does:

| profile | permissions | default reader | default group | for |
|---|---|---|---|---|
| `publish` | Contents write | `lane` | `fuzz-token-publish` | the daily fuzz release |
| `filer` | Repository security advisories write | `lane` | `fuzz-token-filer` | the finding filer |

GitHub adds Metadata read to every token. Each token reaches nifeos/nife alone. When GitHub's answer
grants anything more, or lists any other repository, `fuzz-token` revokes the token and writes
nothing.

**The split narrows each token; it does not isolate one profile from another.** Both profiles
default to the reader `lane`, the account the fuzz services run as today, so that account holds both
tokens, and code running as it can do what either token allows. Isolation between profiles begins
when each profile's service runs under its own account; [Giving a profile its own
account](#giving-a-profile-its-own-account) below is the change, and it needs no change to the
helper.

`fuzz-token mint <profile>` writes `/run/fuzz-token/<profile>.env`, owned by root and by the
profile's group, mode 0440:

```sh
GH_TOKEN=...
GH_TOKEN_EXPIRES_AT=2026-11-03T14:00:00Z
GH_TOKEN_PERMISSIONS=contents:write
GH_TOKEN_REPOSITORIES=nifeos/nife
```

The group must hold the reader and no other account, as a listed member or as anyone's primary
group, under its own name or any other group entry that shares its gid, and its gid must map back to
its name, or the helper refuses. When the reader or its group stops passing, the helper removes the
profile's existing token file and revokes the token in it, so a file made for the old group does
not stay readable. The token directory must carry no POSIX ACL. The reader can read the file and can neither change its mode nor
rewrite it, and the directory is root's, so a file systemd parses as root stays root's. A shell can
source it, and systemd's `EnvironmentFile=` reads it as root before the service drops to its own
user, so `gh` in the service finds `GH_TOKEN` in its environment. `fuzz-token@<profile>.timer`
mints a fresh token every 20 minutes, so the file always holds one with at least 40 minutes left.
`/run` lives in memory, and the timer mints again a minute after each boot.

## What it never does

- It never prints, logs or stores the key. The key leaves the process only on a pipe to `openssl`,
  which signs the JSON Web Token.
- It never puts the key or a token in an argument list, on standard output, on standard error, in
  the journal or in an error message. The token file is the one place a token is written.
- It refuses a key file that is a link or not a regular file, is not owned by root, or has any mode
  but 0400, and a key directory that is a link or is not owned by root with mode 0700, before it
  reads a byte.
- It refuses a token GitHub grants wider or narrower than asked, for another repository, without an
  expiry, or of an unexpected shape, and revokes it. It refuses every HTTP redirect. It talks to
  `https://api.github.com` and nothing else, except plain http to a literal loopback address, which
  exists for the selftest's stub.
- It runs `/usr/bin/openssl` with `PATH=/usr/bin:/bin` and nothing else in its environment, and
  Python with `-IS`, so neither the caller's environment nor site packages reach it.
- It runs from a root-owned copy outside any clone. The host's update from nife's main never
  replaces it, and neither does any change to this repository until a person installs it.

`tests/fuzz-token-selftest` holds each of these against a throwaway key and a local stub of GitHub.

## Install, for a person with root on the fuzz host

Do this after the key is in place (step P4 of nife's `notes/fuzzing/finishing-the-setup.md`). Fetch
this repository into your own account, not the fuzz account, and review the commit you install.

```sh
sudo groupadd --system fuzz-token-publish
sudo usermod -a -G fuzz-token-publish lane
git clone https://github.com/nifeos/fuzz-host.git ~/fuzz-host
git -C ~/fuzz-host checkout --detach <the commit you reviewed>
~/fuzz-host/script/test
sudo install -o root -g root -m 0555 ~/fuzz-host/bin/fuzz-token /usr/local/sbin/fuzz-token
sudo install -o root -g root -m 0644 ~/fuzz-host/systemd/fuzz-token@.service \
    ~/fuzz-host/systemd/fuzz-token@.timer /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now fuzz-token@publish.timer
sudo systemctl start fuzz-token@publish.service
```

`script/test` needs `python3` and `openssl`, and runs against a throwaway key, never the real one.

Verify. After each command, the text after the colon is its expected output:

- `getent group fuzz-token-publish`: the group with `lane` as its only member.
- `sudo stat -c '%U %G %a' /run/fuzz-token /run/fuzz-token/publish.env`: `root root 711`, then
  `root fuzz-token-publish 440`.
- `sudo /usr/local/sbin/fuzz-token check publish`: a `repositories: nifeos/nife` line, an
  `expires:` line about an hour ahead, and exit status 0. It never prints the token. It fails
  unless the file is a regular file owned by root, with the group `fuzz-token-publish`, mode 0440
  and no POSIX ACL, and prints an `acl:` line when it finds one.
- `systemctl list-timers 'fuzz-token@*'`: the next run within 20 minutes.

If `check` lists any repository besides nifeos/nife, `mint` would already have refused it, so the
App's installation changed between the two: set it back to Only select repositories, nifeos/nife
alone, on the installation's settings page. If `mint` fails, `journalctl -u
fuzz-token@publish.service -n 20` names the refusal: the key's owner or mode, an HTTP status from
GitHub, a token wider than asked, or a group that holds more than its reader.

Install the filer's timer the same way, with the group `fuzz-token-filer`, when the filer itself is
installed. A profile whose service is not installed needs no timer.

A service that reads the file directly, rather than through `EnvironmentFile=`, picks up a new
group membership only when it restarts.

## Giving a service its token

A oneshot service reads the file through a drop-in (`sudo systemctl edit <service>`), and asks for a
fresh mint before each start:

```ini
[Unit]
Wants=fuzz-token@publish.service
After=fuzz-token@publish.service

[Service]
EnvironmentFile=/run/fuzz-token/publish.env
```

A long-running service rereads the file before each call instead, because its environment holds the
token it started with.

## Giving a profile its own account

Make the account and its group, then give the profile's unit a drop-in that names them. For the
filer under an account `fuzz-filer`:

```sh
sudo useradd --system --no-create-home --shell /usr/sbin/nologin fuzz-filer
sudo groupadd --system fuzz-token-filer
sudo usermod -a -G fuzz-token-filer fuzz-filer
sudo systemctl edit fuzz-token@filer.service
```

```ini
[Service]
ExecStart=
ExecStart=/usr/local/sbin/fuzz-token mint filer --reader fuzz-filer --group fuzz-token-filer
```

The filer's own unit then runs as `User=fuzz-filer`. The account names here are examples, and
which accounts the host runs is the maintainers' choice.

## Update or remove

To update, review the new commit and repeat the `checkout`, `script/test` and both `install` lines,
then `sudo systemctl daemon-reload`. To stop minting, `sudo systemctl disable --now
'fuzz-token@*.timer'` and `sudo rm -r /run/fuzz-token`; each token already minted lapses within the
hour. Suspending the App's installation stops every token at once.

## BUGS

- No one has run the units under systemd yet; `systemd-analyze verify` passes on them, and the
  selftest runs the helper itself. The first install confirms the hardening lines (for example
  `SystemCallFilter=@system-service`) leave it working.
- Python cannot wipe memory, so the key and the token stay in the helper's heap until it exits, a
  few seconds after it starts.
- Both profiles default to the reader `lane`, so until a profile gets its own account the split
  isolates nothing between profiles (see above).
- A token already minted stays valid for up to an hour after its reader no longer needs it.
- The group check reads the group and account databases through NSS, and some ways into a group
  never appear there. It cannot see:
  - members of a directory service (LDAP, SSSD) whose enumeration is switched off, so
    `getgrall` and `getpwall` do not list them;
  - a systemd unit whose `Group=` or `SupplementaryGroups=` grants the gid, which needs no
    `/etc/group` entry at all;
  - a password on the group in `/etc/gshadow`, which lets anyone who knows it join with `newgrp`.

  On the fuzz host, keep the groups local, give no unit but the reader's the token's group, and
  leave the group's gshadow password field as `!`.
