# fuzz-token reader: a one-hour advisory token for a fix lane

*Name: provisional, as are the profile name `reader`, the subcommand `issue`, the flag `--fresh`,
the key path `/etc/nife-fuzz-reader/nife-fuzz-reader.private-key.pem` and the sudoers file name
`fuzz-token-reader`.*

A held finding reaches the lane that fixes it only as a private security advisory on nifeos/nife.
The lane reads that advisory with a token of the `nife-fuzz-reader` GitHub App (App ID 5571868,
installation ID 177642435; neither is secret), which holds Repository security advisories read and
nothing else. The App's key sits on the machine that launches fix lanes, in a file only root can
read. It never sits on the fuzz host and never enters a lane's environment.

`fuzz-token` turns that key into a token. The reader is its third profile, beside `publish` and
`filer` ([fuzz-token.md](fuzz-token.md)): the same code signs the JSON Web Token, makes the
exchange, checks the answer and revokes a token it refuses. The profile names the App, and the App
names its id, its installation and its key path.

| profile | App | permissions | reaches |
|---|---|---|---|
| `reader` | `nife-fuzz-reader` | Repository security advisories read | nifeos/nife alone |

GitHub adds Metadata read to every token. If GitHub grants anything else, write in place of read,
or another repository, the helper revokes the token and prints nothing on standard output.

## How a lane gets its token

A lane runs as an unprivileged account and cannot read the key. It asks root for a token through
one sudo rule, which names one command with its arguments fixed:

```sh
NIFE_ADVISORY_READER_TOKEN="$(sudo -n /usr/local/sbin/fuzz-token issue reader)" script/read-advisory <id>
```

`issue reader` mints a token and writes it, alone on one line, to standard output, which the shell
captures into `NIFE_ADVISORY_READER_TOKEN` for that one command. That is the variable nife's
`script/read-advisory` reads; the script hands it to `gh` as `GH_TOKEN` itself. Standard error gets one line naming the caller, the
permission, the repository and the expiry, never the token. The token lives one hour; a lane that
needs the advisory again asks again. Nothing stores it: no file, no log, no environment beyond the
one command.

`issue`:

- refuses when standard output is a terminal, so the token never lands on a screen or in a
  terminal's scrollback;
- refuses every profile but `reader`, so the sudo rule cannot be stretched to a fuzz host token;
- refuses `--key`, `--api` and `--openssl` when run under sudo, a second line behind the rule,
  which already admits no arguments beyond `issue reader`;
- clears its environment before it mints, so no proxy, certificate path or temporary directory
  from the caller reaches it;
- revokes the token when it cannot write it, for example when the reader of the pipe has gone.

A lane's own discipline does the rest: it never echoes `NIFE_ADVISORY_READER_TOKEN`, never runs the line under
`set -x`, and never writes the output of the command substitution anywhere but the variable.

## Choosing the channel

Ruled 2026-11-03: fix lanes get the reader token through a sudo rule naming exactly `fuzz-token issue
reader`, which is channel 1 below. Tokens stay at one hour and no long-lived credential is kept.
The single exception to the repository's rule that a helper never prints a secret is this one
command, and `AGENTS.md` names it.

Every channel below keeps the key in root's file and in the helper's memory for a few seconds. They
differ in where the token lives and who can take one. The choice
below is ruled.

1. **A narrow sudo rule and a token on standard output (chosen).** The token exists only when a
   lane asks for it, travels on a pipe to that lane, and is held by nothing afterwards. sudo
   records each request in the system log with the account and the command, so there is a trace of
   when tokens were taken. It needs no daemon, so it works the same on Linux and macOS. It costs a
   root code path that the lane account can start: the helper runs Python with `-IS`, takes no
   argument the rule does not fix, and clears its environment. It is also the one place a
   `fuzz-host` helper puts a secret on standard output, which the repository's rules otherwise
   forbid; the 2026-11-03 ruling accepts that exception.
2. **A root timer writing a token file the lane account can read.** This is `fuzz-token mint
   reader --reader <account> --group fuzz-token-reader`, the fuzz host's own channel, and it works
   today with no new code. No sudo rule and no secret on standard output. But the token exists all
   the time, whether or not a fix lane is running, so any process of the lane account can read every
   advisory at any hour, and nothing records who read the file. It also needs systemd, or a launchd
   job that no one has written, on the machine that launches lanes.
3. **A root service on a local socket.** A daemon holds the key and answers a request on a Unix
   socket whose permissions admit the lane account. It gives on-demand tokens like the sudo rule,
   with the caller's uid from the socket. It is a long-running root process with a parser facing an
   unprivileged account, and new code in a repository whose rules prefer the smallest root
   surface.
4. **The launcher passes the token into the lane at launch.** The person or session that launches a
   fix lane runs `issue` itself and puts the token in the lane's environment. The proposal names
   this shape, but the token then sits in the lane's whole environment for its life, which the
   proposal also forbids, and it is stale after an hour while a lane may run for several.

Channel 1 was chosen because it is the narrowest standing exposure (nothing exists until a lane asks)
and it leaves a trace. Channel 2 stays the
fallback and needs nothing but its install steps.

**What this does not isolate.** Ruled 2026-11-03: any lane on the machine may take a reader token,
and the split of accounts is revisited after the first fix lane runs. Every lane runs as the same account, so any lane on the machine can
ask for a reader token, not only the fix lane for one advisory, and the token reads every advisory
on nifeos/nife. The protection is that the key stays root's and the token lives an hour. It also
holds only if the lane account cannot become root another way: an account with general sudo
rights, or a cached sudo credential, can read the key directly. Run lanes under an account with no
other sudo rule.

## Install, for a person with root on the machine that launches fix lanes

Do this after `fuzz-token` itself merges, and before the key is placed. Fetch this repository into
your own account and review the commit you install.

```sh
git clone https://github.com/nifeos/fuzz-host.git ~/fuzz-host
git -C ~/fuzz-host checkout --detach <the commit you reviewed>
~/fuzz-host/script/test
sudo install -d -o root -g 0 -m 0755 /usr/local/sbin
sudo install -o root -g 0 -m 0555 ~/fuzz-host/bin/fuzz-token /usr/local/sbin/fuzz-token
sudo install -d -o root -g 0 -m 0700 /etc/nife-fuzz-reader
```

`script/test` needs `python3` and `openssl`, runs against a throwaway key, and talks to a stub on
the loopback address, never to GitHub. Run it as yourself, not as root.

The helper runs as root on request of the lane account, so the account must not be able to replace
it. `/usr/local/sbin` and each directory above it must be owned by root and writable by no one else:
`ls -ld /usr /usr/local /usr/local/sbin` shows `root` as owner and no `w` in the group or other
columns. On a macOS host where a package manager made `/usr/local` its user's, install the helper
somewhere root owns instead, and use that path in the rule below.

### Place the key

1. At <https://github.com/organizations/nifeos/settings/apps/nife-fuzz-reader>, under Credentials,
   Key pairs, generate a private key. Note the SHA256 fingerprint GitHub shows beside it. Run
   `chmod 600` on the download at once.
2. Move it into place and remove the download:

   ```sh
   sudo install -o root -g 0 -m 0400 ~/Downloads/nife-fuzz-reader.<date>.private-key.pem \
       /etc/nife-fuzz-reader/nife-fuzz-reader.private-key.pem
   rm -P ~/Downloads/nife-fuzz-reader.<date>.private-key.pem   # macOS; on Linux: shred -u
   ```

   Empty the trash if the browser or a file manager put a copy there.
3. Verify without showing the key:

   - `sudo ls -ln /etc/nife-fuzz-reader/nife-fuzz-reader.private-key.pem`: `-r--------`, owner `0`.
   - `sudo openssl pkey -in /etc/nife-fuzz-reader/nife-fuzz-reader.private-key.pem -pubout
     -outform DER | openssl sha256 -binary | openssl base64`: the fingerprint from step 1, without
     its `SHA256:` prefix.

Never put this key anywhere else, the fuzz host and a lane's environment included.

### Write the sudo rule

Name the account lanes run as in place of `<lane account>`:

```sh
sudo visudo -f /etc/sudoers.d/fuzz-token-reader
```

```
# fuzz-token-reader: fix lanes may ask for one nife-fuzz-reader token, and nothing else.
Defaults!/usr/local/sbin/fuzz-token env_reset
Defaults!/usr/local/sbin/fuzz-token !log_output, !log_input
<lane account> ALL=(root) NOPASSWD: /usr/local/sbin/fuzz-token issue reader
```

A rule that lists arguments matches those arguments exactly, so the account can run `issue reader`
and no other form: not `mint`, not `check`, not another profile, not a flag. The second line keeps
classic sudo's input and output logging, where a host turns it on, from recording the token; macOS
and most Linux distributions ship classic sudo. sudo-rs, the default on recent Ubuntu, has no such
logging and refuses the setting as unknown, so leave that line out there. `visudo` refuses a file
with a syntax error, which is how you find out which one you have. Do not widen the rule with a
wildcard.

### Verify

After each command, the text after the colon is its expected output:

- `sudo -l -U <lane account>`: the one `NOPASSWD: /usr/local/sbin/fuzz-token issue reader` line, and
  no rule that grants anything more.
- `sudo /usr/local/sbin/fuzz-token check reader --fresh`, as yourself: `app: nife-fuzz-reader (App
  ID 5571868, installation 177642435)`, `permissions: metadata:read,repository_advisories:read`,
  `repositories: nifeos/nife`, an `expires:` line about an hour ahead, `revoked: yes`, and exit
  status 0. It mints a token, asks GitHub which repositories it reaches, revokes it, and never
  prints it. It fails unless the list is exactly nifeos/nife and the revocation succeeded; the mint
  itself refuses any permission but advisories read.
- As the lane account, `sudo -n /usr/local/sbin/fuzz-token issue reader | wc -c`: a number near 41
  (the token and its newline), and one `issued one reader token` line on standard error.
- As the lane account, `sudo -n /usr/local/sbin/fuzz-token issue reader`, with nothing after it: a
  refusal, because standard output is a terminal.
- As the lane account, `cat /etc/nife-fuzz-reader/nife-fuzz-reader.private-key.pem`: permission
  denied.

If `check` lists another repository, open the installation's settings page,
<https://github.com/organizations/nifeos/settings/installations/177642435>, and set Only select
repositories to nifeos/nife alone. If the mint refuses a permission, the App's permissions changed:
set them back to Repository security advisories, Read-only, on the App's settings page.

### Update or remove

To update, review the new commit and repeat the `checkout`, `script/test` and the `install` of
`bin/fuzz-token`. To stop issuing tokens, `sudo rm /etc/sudoers.d/fuzz-token-reader`; a token
already issued lapses within the hour. Suspending the App's installation stops every token at once.
To retire the key, delete it on the App's settings page and `sudo rm -P` (or `shred -u`) the file.

## BUGS

- No one has run `issue` under a real sudo rule or `check --fresh` against GitHub. The selftest runs
  the helper as sudo would, with `SUDO_UID` set and no flags, against a stub. The first install
  confirms the rule, the `Defaults` line and both commands.
- Both forms of the rule pass `visudo -c` (classic sudo 1.9 with both `Defaults` lines, sudo-rs
  0.2 without the second), but neither has run. Two things wait for the first install: that sudo-rs
  matches the listed arguments exactly as classic sudo does, and that each sudo hands the helper a
  pipe, not a pseudo-terminal, for standard output when the caller's standard output is a pipe.
  If a sudo gave it a terminal, `issue` would refuse every request and the channel would not work
  until the rule or the helper changed.
- Nothing has run the helper on macOS. It needs `/usr/bin/python3` (the Command Line Tools provide
  it) and `/usr/bin/openssl`, which is LibreSSL there; the selftest has run only on Linux.
- The POSIX ACL check reads Linux's `system.posix_acl_*` attributes. macOS keeps its ACLs where
  `listxattr` does not show them, so on macOS the helper cannot see an ACL on the key or its
  directory: check with `ls -lde /etc/nife-fuzz-reader` and `sudo ls -le` on the key that no ACL
  line follows.
- Any lane on the machine can take a reader token, since every lane runs as one account, and the
  token reads every advisory on nifeos/nife (see above).
- A lane can ask as often as it likes. Each request mints a new token, and GitHub's rate limit on
  the App is the only bound.
- Python cannot wipe memory, so the key and the token stay in the helper's heap until it exits, a
  few seconds after it starts.
