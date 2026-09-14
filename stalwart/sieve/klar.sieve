# Klar filing rules for Stalwart, as a per-account Sieve script.
#
# klar-milterd stamps X-Klar-Label (spam|regular) and X-Klar-Class
# (regular|marketing|gibberish|spam) on every message Stalwart runs through it
# (stalwart/config/mta-milter.json). Stalwart's own junk decision is a flag its
# built-in filter sets before milters run, so a header cannot un-junk anything
# and filing on the milter's verdict has to happen where Stalwart files per
# account: the account's active Sieve script, run at delivery
# (crates/email/src/sieve/ingest.rs). This is that script.
#
# The spam LABEL wins: a spam-labelled message goes to Junk even if its class
# was marketing. Same rules, byte for byte, as postfix/packaging/klar.sieve for
# Dovecot; only the mailbox addressing differs. `:specialuse` finds the Junk
# folder whatever it is called ("Junk", "Junk Mail", "Spam") and falls back to
# creating the named one, so no per-account folder naming is assumed.
#
# The special-use value is "junk", not RFC 8579's "\Junk": Stalwart 0.16.18
# matches the role name without the backslash (crates/types/src/special_use.rs
# SpecialUse::parse), and with "\\Junk" the lookup fails silently and :create
# makes a second folder called "Junk" beside the real one. Observed on klar.im
# on 2026-09-13; this script is Stalwart's, so it speaks Stalwart's spelling.
#
# Install: stalwart/scripts/apply.py publishes it as the global user script
# "klar"; stalwart/scripts/sieve_activate.py activates a one-line
# `include :global "klar"` on each mailbox that should file (never on a
# collection mailbox whose contents are the point). Or paste it into the
# account's own filters over ManageSieve / the webmail.

require ["fileinto", "special-use", "mailbox"];

if header :is "X-Klar-Label" "spam" {
    fileinto :specialuse "junk" :create "Junk";
} elsif header :is "X-Klar-Class" "marketing" {
    fileinto :create "Marketing";
}
