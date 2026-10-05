# Klar for Stalwart

Run the Klar spam engine on a [Stalwart](https://stalw.art) mail server, in
place of Stalwart's built-in rule filter. Stalwart hands every inbound message
to `klar-milterd` over the milter protocol, the engine classifies it on your
box (nothing leaves the server), and a per-mailbox Sieve rule files on the
verdict.

![Stalwart hands the message to klar-milterd at DATA; the engine classifies it on your box; the milter adds X-Klar headers; the account's Sieve files on them. Stalwart's own filter keeps scoring and its verdict is recorded, never acted on. The milter keeps no message, only metadata in its event store.](docs/klar-stalwart.png)

Klar decides. In shadow mode, Stalwart's own verdict is written into every
message and never acted on.

## Why the built-in filter has to stop deciding

Stalwart runs its own spam filter **before** the milters and records the
outcome as a per-recipient flag that decides Junk filing at delivery
(`crates/smtp/src/inbound/data.rs`: filter, flag, `run_milters`, in that
order, at `:531`/`:566`/`:602` in 0.16.18 and `:525`/`:559`/`:595` in
0.16.22; `crates/email/src/message/ingest.rs:357` files on the flag in both).
A header the milter adds cannot clear that flag, so with both deciding, a
message the built-in filter flagged and Klar read as regular would still go to
Junk. Turning it off is the whole
point, not a side effect. (Since 0.16.22 a user Sieve `fileinto` also clears
the flag, `crates/email/src/sieve/ingest.rs`; the shipped `klar.sieve` files spam
and marketing and lets regular mail fall through to the implicit keep, so it
does not rely on that.)

## Install

You need a Stalwart 0.16 server you administer (`stalwart-cli` with admin
credentials) and a Linux host for the milter. Everything is idempotent; run it
again and it changes nothing. A brand-new Stalwart is in bootstrap mode until
its setup wizard has run (every management call answers "forbidden: The
server is in bootstrap mode"); finish the wizard in the WebUI first, or do
what the E2E does and `stalwart-cli update Bootstrap singleton` with your
hostname and domain, then restart.

### 1. The milter

One command on the host, Linux x86_64 or arm64 with systemd:

```bash
curl -fsSL https://raw.githubusercontent.com/klar-im/engine/main/install.sh | sudo KLAR_ACCEPT_MODEL_LICENSE=1 sh
```

It downloads the latest release's prebuilt tarball for your architecture and
checks its sha256, installs the daemon and its bundled libraries into
`/opt/klar/bin` (glibc 2.35 or newer on x86_64: Debian 12, Ubuntu 22.04 and
later; 2.39 on arm64: Debian 13, Ubuntu 24.04; older hosts use the container
below), this directory's scripts, config and Sieve into
`/opt/klar/share/stalwart`, creates the `klarmilter` user, writes
`/etc/klar/klar-milterd.toml` from `config/klar-milterd.toml` if there is
none, fetches the model into `/var/lib/klar/model`, enables and starts the
`klar-milterd` unit, and waits for `/readyz`. It needs `curl`, `python3` and
`sha256sum`. Run it again to upgrade: your config is kept and model files that
already match are not downloaded again. `KLAR_VERSION=v0.2.0` pins a release.
The binaries are built by this repo's CI from the tagged tree; `install.sh` is
at the repo root if you want to read it first.

Or build from source on the host (Ubuntu/Debian shown; `make setup` prints the
package list for others):

```bash
git clone https://github.com/klar-im/engine && cd engine
sudo apt-get install -y libmilter-dev libsqlite3-dev
make setup && make build
sudo postfix/scripts/install.sh /opt/klar                 # binary + libraries in /opt/klar/bin
sudo useradd --system --no-create-home --shell /usr/sbin/nologin klarmilter
sudo mkdir -p /var/lib/klar /etc/klar && sudo chown klarmilter:klarmilter /var/lib/klar
sudo KLAR_ACCEPT_MODEL_LICENSE=1 postfix/scripts/fetch_model.sh /var/lib/klar/model
sudo cp stalwart/config/klar-milterd.toml /etc/klar/
sudo cp postfix/packaging/klar-milterd.service /etc/systemd/system/
sudo systemctl enable --now klar-milterd
curl -fsS http://127.0.0.1:8892/readyz                     # "ok" once the model is loaded
```

Or the container, built from the same tree by this repo's CI for linux/amd64
and linux/arm64 (docker pulls the right one); it fetches the same model into
its volume on first start and carries no weights itself:

```bash
docker run -d --name klar-milterd --restart unless-stopped -e KLAR_ACCEPT_MODEL_LICENSE=1 \
  -v klar-data:/var/lib/klar -p 127.0.0.1:8891:8891 -p 127.0.0.1:8892:8892 \
  ghcr.io/klar-im/klar-milterd:latest
```

The ports are bound to loopback for a Stalwart on the same host. When Stalwart
runs in a container too, put both on one Docker network instead and pass
`--milter-host klar-milterd` to `apply.py`; never publish 8891 to the internet.
`postfix/docker/Dockerfile` builds the same image locally.

The model is licensed separately from the code (`LICENSE-MODEL.md`:
CC-BY-NC-4.0, free for non-commercial use with attribution, a paid licence for
commercial use). `fetch_model.sh` refuses to download it until
`KLAR_ACCEPT_MODEL_LICENSE=1` says you have read that.

`stalwart/config/klar-milterd.toml` is the milter's config for this
deployment. Two settings differ from a Postfix install and both matter:

- `auth_results = "ignore"`. The engine reads `Authentication-Results` and
  trusts the topmost one when told to. Stalwart adds its own after the milters
  have run (`data.rs`, the queued prefix), so what a milter sees at DATA is
  the message as the sender delivered it. `ignore` drops every such header
  before the engine parses the message. Do not set `trust-topmost` behind
  Stalwart; a failing DMARC is enforced by Stalwart itself
  (`dmarcVerify = strict`, below).
- `listen`. `127.0.0.1` when Stalwart is on the same host. In a container or
  another network namespace, bind an address Stalwart can reach
  (`inet:8891@0.0.0.0`); the Dockerfile does this.

Sizing: about 700 MB of RSS with the model loaded, one classification at a
time. Speed is the CPU's (the release carries llama.cpp's CPU backends only,
no GPU backend): on a 2-vCPU VPS (AMD EPYC 7281, shared with the mail server
and a website) the median is 6 s per message and the 90th percentile 12 s,
measured over a day of real mail. For scale, the same model on an Apple M1
Pro's CPU with Metal off took about 200 ms a message (8,200 messages, the
2026-09-13 release evaluation). Stalwart waits 60 s for the milter (`timeoutData`) and delivers unclassified past that, never defers.
`postfix/README.md` has the detail; the milter is the same daemon Postfix
users run.

### 2. The Stalwart side

`stalwart/scripts/apply.py` declares four objects through `stalwart-cli` and
reloads settings once if anything changed:

| Object | What it sets | Fragment |
|---|---|---|
| `MtaMilter` | klar-milterd at `--milter-host:--milter-port`, DATA stage, `enable = is_empty(authenticated_as)` (inbound only, never your users' own submissions), `tempFailOnError false` (a milter outage delivers unclassified; it never defers mail) | `config/mta-milter.json` |
| `SenderAuth` | `dmarcVerify = strict` on port 25: a message failing DMARC under a `p=reject` policy is refused at SMTP time. Stalwart keeps verifying; only its *filing* stops | `config/sender-auth.json` |
| `SieveUserScript` | the global user script `klar` (the filing rules, `sieve/klar.sieve`) | |
| `MtaStageData` | `enableSpamFilter = false`: the built-in filter no longer runs, so `X-Spam-Result` disappears. An `X-Spam-Status: No` still appears on every message: ingest writes it from a per-recipient flag that nothing sets any more (`crates/email/src/message/ingest.rs`, under the global `spam-filter.enable`). Informational; it is not the classifier | `config/stage-data.json` |

```bash
export STALWART_URL=http://127.0.0.1:8080 STALWART_USER=admin STALWART_PASSWORD=...   # as for stalwart-cli
python3 stalwart/scripts/apply.py --milter-host 127.0.0.1 --milter-port 8891           # --dry-run to see the plan
```

The installer put the same script at `/opt/klar/share/stalwart/scripts/apply.py`
(and `sieve_activate.py` beside it, for step 3); it reads the config and Sieve
next to it, so either path applies the same objects.

`STALWART_CLI=/path/to/stalwart-cli` if it is not on `PATH`. A milter has no
name in Stalwart, so its endpoint is its identity: when the milter moves (a
container's new address), re-run with `--milter-id <id>` naming the object to
re-point; without it the run refuses to add a second milter beside one it
cannot account for, and prints the ids. The same in the
WebUI, if you prefer clicking: Settings › MTA › Filters › Milters (add one),
Settings › Spam filter › General (disable), Settings › MTA › Authentication
(DMARC strict), Settings › Sieve › User scripts (paste `sieve/klar.sieve` as
`klar`).

### 3. The mailboxes that should file

Filing happens in each account's active Sieve script, because that is where
Stalwart files. `sieve_activate.py` installs a one-line
`include :global "klar"` and activates it, over JMAP for Sieve (RFC 9661),
with the **account's** credentials:

```bash
STALWART_PASSWORD='alice-pw' python3 stalwart/scripts/sieve_activate.py --url https://mail.example.com --user alice@example.com
```

An account that already runs a Sieve script of its own is refused (exit 3):
JMAP allows one active script per account, so activating ours would switch
theirs off. The refusal prints the two lines (`require ["include"];` and
`include :global "klar";`) to add to that script instead.

Do this for the mailboxes people read. Do **not** do it for a mailbox whose
contents are the point (a spam trap, an abuse@ or a corpus mailbox): it gets
`X-Klar-*` headers on every message and nothing moves, which is exactly the
value of a trap that also records a verdict. Users can also paste
`sieve/klar.sieve` into their own filters through the webmail or ManageSieve;
the global script only saves everyone from doing that.

Rules are updated by re-running `apply.py` after editing `sieve/klar.sieve`;
the per-account include never changes. The spam label wins: a message labelled
spam goes to Junk even when its class is marketing. `fileinto :specialuse
"junk"` finds the Junk folder whatever it is called ("Junk Mail", "Spam");
note the spelling: Stalwart matches the bare role name, and RFC 8579's
`"\Junk"` fails the lookup silently and creates a second folder.

## Shadow mode: keep Stalwart's opinion, drop its decision

`apply.py --shadow` leaves Stalwart's filter running and adds one tag,
`KLAR_SHADOW`, at -100 to every message, so the total can never reach the junk
threshold (5): Stalwart writes `X-Spam-Result` with every rule it fired but
files nothing, while the milter decides. `X-Spam-Result` minus `KLAR_SHADOW`
is what Stalwart would have done to each message.

Two ways to use it. As a **comparison window** when migrating: run shadow for
a fortnight, count the disagreements, then re-run `apply.py` without
`--shadow` to remove the tag and rule and turn the filter off. Or **keep it**:
every message then carries two independent verdicts, Klar's deciding and
Stalwart's recorded, and a filter you can compare yourself against on your
own mail is worth the few milliseconds its rules cost.

## Try it in one command

`stalwart/docker-compose.yml` runs upstream's Stalwart image beside the milter
built from this tree; `stalwart/scripts/test_e2e.sh` (or `make stalwart/test`)
creates a domain and two accounts, applies both modes, sends a GTUBE, a ham and
a forged-`Authentication-Results` phish over SMTP, and reads back over JMAP
where each landed and with which headers.

## Files

```
stalwart/
  config/klar-milterd.toml     the milter's config for this deployment
  config/mta-milter.json       MtaMilter object (hostname/port substituted by apply.py)
  config/stage-data.json       MtaStageData patch: enableSpamFilter false
  config/sender-auth.json      SenderAuth patch: dmarcVerify strict on :25
  config/shadow.json           the KLAR_SHADOW tag + rule for --shadow
  sieve/klar.sieve             the filing rules, published as global script "klar"
  scripts/apply.py             declare it all through stalwart-cli, idempotent
  scripts/sieve_activate.py    activate the include on one account (JMAP for Sieve)
  scripts/test_e2e.sh          the compose E2E
  docker-compose.yml           Stalwart + klar-milterd
  tests/                       apply.py against a fake stalwart-cli
```

Licence: the code is AGPLv3 (`LICENSE`), the model CC-BY-NC-4.0
(`LICENSE-MODEL.md`). Issues and pull requests at
[github.com/klar-im/engine](https://github.com/klar-im/engine).
