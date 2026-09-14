#pragma once
#include <cstdint>
#include <ctime>
#include <mutex>
#include <string>
#include <vector>

#include "ip_blocklist.h"

namespace klar {

struct Config;

// The operator's own relay hops, as CIDRs (TASK-387).
//
// WHY THIS EXISTS: a milter behind a relay never sees the internet. Our own
// staging MX is exactly that shape — Stalwart owns :25 and relays into the
// Postfix pod, so xxfi_connect reports the podman bridge gateway (10.88.0.1) and
// the DROP check is inert. The true origin is then only in the Received chain.
//
// TRUST MODEL, which is the whole point: Received lines are prepended, so the
// topmost was written by US and records the relay. That line vouches for the
// relay; the relay's own line then vouches for what IT saw. Walking down while
// each recorded peer is trusted, the FIRST untrusted address was written by a
// host we trust — so it is a fact, not a claim. Everything BELOW it is
// attacker-writable and must never be read. An empty trusted set disables the
// walk entirely: with no relay configured the connecting address is the origin,
// and headers would add nothing but forgery surface.
class TrustedRelays {
public:
    // Returns false and sets *err on an unparseable entry.
    bool load(const std::vector<std::string>& cidrs, std::string* err);
    bool contains(const std::string& ip) const;
    bool empty() const { return v4_.empty() && v6_.empty(); }
    size_t size() const { return v4_.size() + v6_.size(); }

private:
    struct R4 { uint32_t lo, hi; };
    struct R6 { uint64_t lo_hi, lo_lo, hi_hi, hi_lo; };
    std::vector<R4> v4_;
    std::vector<R6> v6_;
};

// The origin address to check against DROP, given what the MTA observed and the
// message's Received lines in header order (topmost first).
//
// Returns `connect_ip` unless it is a trusted relay, in which case it walks the
// chain per the trust model above. Returns "" when no usable origin exists (no
// relay configured and no connect IP, or every hop is trusted/private).
std::string resolve_origin_ip(const std::string& connect_ip,
                              const std::vector<std::string>& received,
                              const TrustedRelays& trusted);

// The address a single Received line records as its peer: the first bracketed or
// parenthesised globally-routable literal. "" if the line has none. Exposed for
// testing.
std::string received_hop_ip(const std::string& received_line);

// The milter's Spamhaus DROP netblock lookup (TASK-113).
//
// Deliberately NOT part of ModelRuntime, despite loading next to the model: its
// lifecycle is independent (a cron refreshes it, model releases do not), so
// gating it on a model load would disable it whenever the model failed, and
// sharing the classify mutex would make a /metrics scrape wait behind a ~600ms
// inference to read a number that only changes on SIGHUP.
//
// Its own mutex is uncontended: lookups are microseconds, writes happen on
// startup and SIGHUP only.
class OriginIpBlocklist {
public:
    // A reload keeps the previous list when the new artifact will not parse — an
    // operator mid-rsync must not lose the signal — so "kept the old list" has to
    // be distinguishable from "refreshed", or a cron writing garbage looks
    // healthy until the staleness gauge trips days later.
    enum class Reload { Disabled, Loaded, Failed };

    // Load (or re-load) from cfg.ip_blocklist_path. Never throws, never fatal:
    // an absent list disables one signal, it must not stop a mail server.
    Reload load(const Config& cfg);

    // True if `ip` (the address the MTA OBSERVED connecting, never one read from
    // a Received header — see decision_layer.h) sits in a DROP netblock.
    bool contains(const std::string& ip) const;

    // Loaded range count, 0 when the signal is off.
    size_t size() const;

    // True when a list IS loaded but is older than ip_blocklist_max_age_days.
    // Absent is not stale, it is off.
    bool stale() const;

    // "ranges=N" or "ranges=N STALE", for the startup and SIGHUP log lines.
    std::string status() const;

private:
    mutable std::mutex mutex_;
    spam_engine::IpBlocklist list_;
    int max_age_days_ = 0;
};

} // namespace klar
