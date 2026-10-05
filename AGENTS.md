# Notes for an AI agent

1. **Working on the code** (a bug, a test, a contribution): read `CONTRIBUTING.md`
   and the README's build section. Running `KLAR_ACCEPT_MODEL_LICENSE=1 make model`
   for your own development is the person you work for accepting
   `LICENSE-MODEL.md`; say so to them once. The rest of this file is not for you.
2. **Installing Klar on someone's mail server**: read on, all of it, before
   running anything. The facts below point at their owners (`install.sh`,
   `stalwart/README.md`, `LICENSE-MODEL.md`); when one of those disagrees with
   this file, it wins.

## The licence decision is the operator's

1. **Never set `KLAR_ACCEPT_MODEL_LICENSE=1` on your own.** The installer will not
   fetch the model without it, and setting it is the operator accepting
   `LICENSE-MODEL.md`.
2. **Show the operator the terms first.** The model is CC-BY-NC-4.0 with
   attribution to Klar:
   - free: a personal or family home server, a hobby project, academic research;
   - paid: filtering a company's mail (its own staff and a trial included), a paid
     service, or any use primarily for commercial advantage (a one-person business
     is commercial);
   - unsure: they write to hello@klar.im before deploying.
3. **Set it only after they say their use fits.**

## Before installing

1. **Requirements are in the README's install section** (`stalwart/README.md`,
   "Install"): Linux with systemd, root, the architecture and glibc floor it
   names, about 700 MB of free RAM, a Stalwart 0.16 server the operator
   administers, past its setup wizard (a server still in bootstrap mode answers
   every admin call "forbidden").
2. **`install.sh` checks some of these, not all.** It refuses a non-Linux host,
   a non-root run, a host without systemd, an unsupported architecture, a missing
   tool and binaries that do not run (the glibc floor), each with a message.
   It does NOT check RAM or the Stalwart version: check those yourself
   (`free -m`, `stalwart-cli --version` or the admin UI).
3. **Older or containerised hosts use the container**, and then the steps below
   change: follow `stalwart/README.md`'s container section, take `apply.py` and
   `sieve_activate.py` from this repository's `stalwart/scripts/`, and use the
   milter address that section gives (Stalwart in a container cannot reach the
   host's 127.0.0.1).

## Install

1. **The command**, once the operator accepted the licence (variables go after
   `sudo`, where `sh` sees them):

   ```sh
   curl -fsSL https://raw.githubusercontent.com/klar-im/engine/main/install.sh | sudo KLAR_ACCEPT_MODEL_LICENSE=1 sh
   ```

   For Postfix: `... | sudo KLAR_ACCEPT_MODEL_LICENSE=1 KLAR_MTA=postfix sh`. The
   MTA choice is first-install only; the config is never overwritten after.
2. **Re-running it upgrades in place** and keeps `/etc/klar/klar-milterd.toml`.
3. **Verify it yourself, do not trust the "ready" line alone:** `systemctl
   is-active klar-milterd` says `active`, and `/readyz` answers on the config's
   `health_listen` (default `127.0.0.1:8892`). Something else already answering
   on that port (an old container) would make the installer's check pass.

## Wire it into Stalwart

1. **The installer prints an `apply.py` line without `--shadow`; do not run it
   as printed.** Without `--shadow`, `apply.py` switches Stalwart's own filter
   off. Unless the operator chose that, start with `--shadow --dry-run`, show
   them the plan, then run it without `--dry-run`.
2. **Know what even `--shadow` changes:** Klar decides and files from the first
   message (Stalwart's verdict is only recorded beside it), and DMARC
   verification is set to strict on port 25, so a message failing DMARC under a
   `p=reject` policy is refused at SMTP time. Tell the operator both.
3. **Passwords stay out of command lines and history.** Have the operator type
   them, or read them silently:

   ```sh
   export STALWART_URL=http://127.0.0.1:8080 STALWART_USER=admin
   read -rs STALWART_PASSWORD && export STALWART_PASSWORD
   python3 /opt/klar/share/stalwart/scripts/apply.py --milter-host 127.0.0.1 --milter-port 8891 --shadow --dry-run
   ```

4. **Filing is per mailbox, with that account's own password**, not the admin's
   (`sieve_activate.py` reads the same variable, so set it per account in a
   subshell). Ask which mailboxes people read; a trap or abuse@ mailbox stays
   headers-only.

   ```sh
   ( read -rs STALWART_PASSWORD && export STALWART_PASSWORD && \
     python3 /opt/klar/share/stalwart/scripts/sieve_activate.py --url https://mail.example.com --user alice@example.com )
   ```

5. **An account with its own Sieve script is refused**, and the refusal prints the
   two lines (`require` and `include`) its owner adds by hand.

## Do not

1. **Accept the model licence** for the operator.
2. **Switch Stalwart's filter off** (`apply.py` without `--shadow`) unless the
   operator chose it.
3. **Put a password** in a file, an argument, a shell history or a log.
4. **Expose the milter port (8891) to the internet.** Bind it where Stalwart can
   reach it, as the README's container section says, and no wider.
