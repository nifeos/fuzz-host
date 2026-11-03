# fuzz-token: one narrowed token per service, from the App key

*Name: provisional, as are the profile names `publish` and `filer`, the unit names and the paths
`/usr/local/sbin/fuzz-token` and `/run/fuzz-token`.*

The fuzz host acts on nifeos/nife as the `nife-fuzz` GitHub App (App ID 5571801, installation ID
177641059; neither is secret). The App's private key sits on the host at
`/etc/nife-fuzz/nife-fuzz.private-key.pem`, readable by root alone. `fuzz-token` turns that key into
one-hour installation tokens, one per service, each holding less than the App does:

| profile | permissions | reader | for |
|---|---|---|---|
| `publish` | Contents write | `lane` | the daily fuzz release |
| `filer` | Repository security advisories write | `lane` | the finding filer |

GitHub adds Metadata read to every token. Each token reaches nifeos/nife alone. When GitHub's answer
grants anything more, or lists any other repository, `fuzz-token` revokes the token and writes
nothing.

`fuzz-token mint <profile>` writes `/run/fuzz-token/<profile>.env`, owned by the reader, mode 0400:

```sh
GH_TOKEN=...
GH_TOKEN_EXPIRES_AT=2026-11-03T14:00:00Z
GH_TOKEN_PERMISSIONS=contents:write
GH_TOKEN_REPOSITORIES=nifeos/nife
```

A shell can source it, and systemd's `EnvironmentFile=` reads it as root before the service drops
to its own user, so `gh` in the service finds `GH_TOKEN` in its environment. `fuzz-token@<profile>.timer`
mints a fresh token every 20 minutes, so the file always holds one with at least 40 minutes left.
`/run` lives in memory, and the timer mints again a minute after each boot.

## What it never does

- It never prints, logs or stores the key. The key leaves the process only on a pipe to `openssl`,
  which signs the JSON Web Token.
- It never puts the key or a token in an argument list, on standard output, on standard error, in
  the journal or in an error message. The token file is the one place a token is written.
- It refuses a key file that is a link, is not owned by root, or has any mode but 0400, and a key
  directory that is not owned by root with mode 0700, before it reads a byte.
- It runs from a root-owned copy outside any clone. The host's update from nife's main never
  replaces it, and neither does any change to this repository until a person installs it.

`tests/fuzz-token-selftest` holds each of these against a throwaway key and a local stub of GitHub.

## Install, for a person with root on the fuzz host

Do this after the key is in place (step P4 of nife's `notes/fuzzing/finishing-the-setup.md`). Fetch
this repository into your own account, not the fuzz account, and review the commit you install.

```sh
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

- `sudo stat -c '%U %a' /run/fuzz-token /run/fuzz-token/publish.env`: `root 711`, then `lane 400`.
- `sudo /usr/local/sbin/fuzz-token check publish`: a `repositories: nifeos/nife` line, an
  `expires:` line about an hour ahead, and exit status 0. It never prints the token.
- `systemctl list-timers 'fuzz-token@*'`: the next run within 20 minutes.

If `check` lists any repository besides nifeos/nife, `mint` would already have refused it, so the
App's installation changed between the two: set it back to Only select repositories, nifeos/nife
alone, on the installation's settings page. If `mint` fails, `journalctl -u
fuzz-token@publish.service -n 20` names the refusal: the key's owner or mode, an HTTP status from
GitHub, or a token wider than asked.

Install the filer's timer the same way, `fuzz-token@filer.timer`, when the filer itself is
installed. A profile whose service is not installed needs no timer.

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
- Both profiles default to the reader `lane`, the account the fuzz services run as today. A filer
  that runs under its own account passes `--reader` through a drop-in on `fuzz-token@filer.service`.
- A token already minted stays valid for up to an hour after its reader no longer needs it.
