#!/usr/bin/env python3
"""
Train the classifier head from IMAP mailboxes.

Reads messages from INBOX (label=regular) and Junk (label=spam),
feeds them to the engine's batch training API, and saves updated weights.

This is the simplest auto-learning approach: the user's mailbox folders
ARE the ground truth. Moving messages to/from Junk is the feedback signal.

Usage:
    train_from_imap.py --model-dir <path> --imap-host <host> --imap-port <port>
                       --user <user> --password <pw>
                       [--max-per-folder N] [--learning-rate F] [--dry-run]
"""

import argparse
import ctypes
import ctypes.util
import email
import imaplib
import os
import sys


# ---- Engine C API bindings ----

def load_engine_lib():
    """Load the spam engine shared libraries (base + training)."""
    base_lib = None
    train_lib = None

    for path in [
        "libspam_engine_c_api.so",
        os.path.join(os.environ.get("ENGINE_LIB_DIR", ""), "libspam_engine_c_api.so"),
    ]:
        try:
            base_lib = ctypes.CDLL(path)
            break
        except OSError:
            continue

    if base_lib is None:
        raise RuntimeError(
            "Cannot load libspam_engine_c_api.so. "
            "Set LD_LIBRARY_PATH or ENGINE_LIB_DIR."
        )

    # Training API is in a separate library
    for path in [
        "libspam_engine_training_c_api.so",
        os.path.join(os.environ.get("ENGINE_LIB_DIR", ""), "libspam_engine_training_c_api.so"),
    ]:
        try:
            train_lib = ctypes.CDLL(path)
            break
        except OSError:
            continue

    if train_lib is None:
        raise RuntimeError(
            "Cannot load libspam_engine_training_c_api.so. "
            "Set LD_LIBRARY_PATH or ENGINE_LIB_DIR."
        )

    return base_lib, train_lib


class EngineAPI:
    """Wrapper holding both base and training library references."""
    def __init__(self, base_lib, train_lib):
        self.base = base_lib
        self.train = train_lib
        self._setup()

    def _setup(self):
        b, t = self.base, self.train

        b.spam_engine_create.restype = ctypes.c_void_p
        b.spam_engine_create.argtypes = []

        b.spam_engine_load.restype = ctypes.c_int
        b.spam_engine_load.argtypes = [
            ctypes.c_void_p, ctypes.c_char_p, ctypes.c_float, ctypes.c_char_p
        ]

        b.spam_engine_destroy.restype = None
        b.spam_engine_destroy.argtypes = [ctypes.c_void_p]

        b.spam_engine_get_last_error.restype = ctypes.c_char_p
        b.spam_engine_get_last_error.argtypes = [ctypes.c_void_p]

        t.spam_engine_add_training_sample.restype = ctypes.c_int
        t.spam_engine_add_training_sample.argtypes = [
            ctypes.c_void_p, ctypes.c_char_p, ctypes.c_size_t,
            ctypes.c_char_p, ctypes.c_char_p,  # sender_name, sender_email
            ctypes.c_int,
        ]

        t.spam_engine_train_incremental.restype = ctypes.c_int
        t.spam_engine_train_incremental.argtypes = [
            ctypes.c_void_p,
            ctypes.POINTER(ctypes.c_float),
            ctypes.POINTER(ctypes.c_size_t),
        ]

        t.spam_engine_save.restype = ctypes.c_int
        t.spam_engine_save.argtypes = [ctypes.c_void_p, ctypes.c_char_p]


# Labels: 0=gibberish, 1=marketing, 2=regular, 3=spam
LABEL_REGULAR = 2
LABEL_SPAM = 3


def fetch_messages(host, port, user, password, folder, max_messages):
    """Fetch raw RFC822 messages from an IMAP folder."""
    conn = imaplib.IMAP4(host, port)
    conn.login(user, password)
    status, _ = conn.select(folder, readonly=True)
    if status != "OK":
        conn.logout()
        return []

    status, data = conn.search(None, "ALL")
    if status != "OK" or not data[0]:
        conn.logout()
        return []

    msg_nums = data[0].split()
    # Take the most recent N messages
    if len(msg_nums) > max_messages:
        msg_nums = msg_nums[-max_messages:]

    messages = []
    for num in msg_nums:
        status, raw = conn.fetch(num, "(RFC822)")
        if status == "OK":
            messages.append(raw[0][1])

    conn.logout()
    return messages


def main():
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--model-dir", required=True,
                        help="Path to model directory")
    parser.add_argument("--imap-host", required=True)
    parser.add_argument("--imap-port", type=int, default=143)
    parser.add_argument("--user", required=True)
    parser.add_argument("--password", required=True)
    parser.add_argument("--max-per-folder", type=int, default=100,
                        help="Max messages to fetch per folder")
    parser.add_argument("--learning-rate", type=float, default=0.001)
    parser.add_argument("--save-path", default="",
                        help="Path to save updated weights (default: overwrite model-dir)")
    parser.add_argument("--dry-run", action="store_true",
                        help="Fetch messages but don't train")
    args = parser.parse_args()

    # Fetch messages from IMAP
    print(f"Fetching from {args.imap_host}:{args.imap_port} as {args.user}...")

    ham_messages = fetch_messages(
        args.imap_host, args.imap_port, args.user, args.password,
        "INBOX", args.max_per_folder)
    print(f"  INBOX: {len(ham_messages)} messages")

    spam_messages = fetch_messages(
        args.imap_host, args.imap_port, args.user, args.password,
        "Junk", args.max_per_folder)
    print(f"  Junk:  {len(spam_messages)} messages")

    total = len(ham_messages) + len(spam_messages)
    if total == 0:
        print("No messages to train on.")
        return 0

    if args.dry_run:
        print(f"Dry run: would train on {total} messages")
        return 0

    # Load engine
    print(f"Loading engine from {args.model_dir}...")
    base_lib, train_lib = load_engine_lib()
    api = EngineAPI(base_lib, train_lib)
    handle = api.base.spam_engine_create()
    if not handle:
        print("ERROR: Failed to create engine handle")
        return 1

    status = api.base.spam_engine_load(
        handle,
        args.model_dir.encode(),
        ctypes.c_float(args.learning_rate),
        None,  # ftrl_path
    )
    if status != 0:
        err = api.base.spam_engine_get_last_error(handle)
        print(f"ERROR: Failed to load model: {err.decode() if err else 'unknown'}")
        api.base.spam_engine_destroy(handle)
        return 1

    print("Engine loaded. Queuing training samples...")

    # Queue ham samples. sender_name/sender_email are passed as NULL —
    # train_rfc822 falls back to the parsed From header internally, which
    # is what we want for IMAP-fetched messages (no MUA-supplied sender).
    for raw in ham_messages:
        api.train.spam_engine_add_training_sample(
            handle, raw, len(raw), None, None, LABEL_REGULAR)

    # Queue spam samples
    for raw in spam_messages:
        api.train.spam_engine_add_training_sample(
            handle, raw, len(raw), None, None, LABEL_SPAM)

    print(f"Queued {total} samples. Training...")

    # Train
    avg_loss = ctypes.c_float(0)
    trained_count = ctypes.c_size_t(0)
    status = api.train.spam_engine_train_incremental(
        handle,
        ctypes.byref(avg_loss),
        ctypes.byref(trained_count),
    )

    if status != 0:
        err = api.base.spam_engine_get_last_error(handle)
        print(f"ERROR: Training failed: {err.decode() if err else 'unknown'}")
        api.base.spam_engine_destroy(handle)
        return 1

    print(f"Trained on {trained_count.value} samples, avg loss: {avg_loss.value:.6f}")

    # Save
    save_path = args.save_path or args.model_dir
    print(f"Saving weights to {save_path}...")
    status = api.train.spam_engine_save(handle, save_path.encode())
    if status != 0:
        err = api.base.spam_engine_get_last_error(handle)
        print(f"ERROR: Failed to save: {err.decode() if err else 'unknown'}")
        api.base.spam_engine_destroy(handle)
        return 1

    print("Done. Model weights updated.")
    api.base.spam_engine_destroy(handle)
    return 0


if __name__ == "__main__":
    sys.exit(main())
