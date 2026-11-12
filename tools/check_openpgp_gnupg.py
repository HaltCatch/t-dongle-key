#!/usr/bin/env python3
"""Verify synthetic data with three exact card keys; never provision or reset keys."""
import argparse
import getpass
import os
import subprocess
import tempfile
from pathlib import Path


def call(*args, input=None, **kwargs):
    result = subprocess.run(args, input=input, timeout=30, capture_output=True, **kwargs)
    if result.returncode:
        raise RuntimeError(result.stderr.decode(errors="replace"))
    return result.stdout


def check_bindings(rows, agent_info, serial, fingerprints, curves=("ed25519", "cv25519", "ed25519")):
    """Reject local keys, stale shadow keys and a different card or slot."""
    errors = [line for line in agent_info.splitlines() if line.startswith("ERR ")]
    if errors:
        raise RuntimeError("GnuPG smart-card connection failed: " + "; ".join(errors))
    if f"S SERIALNO {serial}" not in agent_info.splitlines():
        raise RuntimeError("Connected card serial does not match")
    record = None
    fingerprint = None
    bound = set()
    for row in rows.splitlines():
        fields = row.split(":")
        if fields[0] in ("sec", "ssb"):
            record = fields
            fingerprint = None
        elif fields[0] == "fpr":
            fingerprint = fields[9]
        elif fields[0] == "grp" and fingerprint in fingerprints:
            if record is None or len(record) < 17 or record[14] != serial:
                raise RuntimeError("Test key is local or bound to a different card")
            slot = fingerprints.index(fingerprint) + 1
            curve = curves[slot - 1]
            if record[16] != curve:
                raise RuntimeError(f"Slot {slot} requires {curve}")
            expected = f"S KEYINFO {fields[9]} T {serial} OPENPGP.{slot} "
            if not any(line.startswith(expected) for line in agent_info.splitlines()):
                raise RuntimeError(f"Test key is not bound to OPENPGP.{slot}")
            bound.add(fingerprint)
    if bound != set(fingerprints):
        raise RuntimeError("Missing one or more exact test-key bindings")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--homedir", type=Path, required=True)
    parser.add_argument("--serial", required=True, help="Full OpenPGP card AID/serial")
    parser.add_argument("--fingerprints", nargs=3, required=True, metavar=("SIGN", "DECRYPT", "AUTH"))
    parser.add_argument("--curves", nargs=3, default=("ed25519", "cv25519", "ed25519"),
                        metavar=("SIGN", "DECRYPT", "AUTH"), help="Expected GnuPG curve names for the three slots")
    parser.add_argument("--pin-fd", type=int, help="Read the existing PIN from this descriptor; otherwise prompt locally")
    args = parser.parse_args()
    home = args.homedir.resolve()
    if not home.is_dir():
        parser.error("Use an existing isolated GnuPG home containing the test public keys and card stubs")
    serial = args.serial.upper()
    if not serial or len(serial) % 2 or any(char not in "0123456789ABCDEF" for char in serial):
        parser.error("Provide the complete hexadecimal OpenPGP card serial")
    fingerprints = [value.upper() for value in args.fingerprints]
    if len(set(fingerprints)) != 3 or any(
        len(value) != 40 or any(char not in "0123456789ABCDEF" for char in value)
        for value in fingerprints
    ):
        parser.error("Provide three distinct full SHA-1 OpenPGP fingerprints")
    os.environ["GNUPGHOME"] = str(home)
    info = call("gpg-connect-agent", f"SCD SERIALNO --demand={serial} openpgp", "KEYINFO --list", "/bye").decode()
    rows = call("gpg", "--batch", "--with-colons", "--with-keygrip", "--list-secret-keys", fingerprints[0]).decode()
    check_bindings(rows, info, serial, fingerprints, args.curves)
    print("PASS exact test fingerprints bound to expected card slots; no host-key fallback", flush=True)
    if args.pin_fd is None:
        pin_bytes = (getpass.getpass("OpenPGP test-card PIN: ") + "\n").encode()
    else:
        with os.fdopen(os.dup(args.pin_fd), "rb") as pin_input:
            pin_bytes = pin_input.readline(256)
        if not pin_bytes.strip():
            parser.error("Empty PIN input")
    signing, decryption, authentication = fingerprints
    with tempfile.TemporaryDirectory(dir=home) as temp:
        work = Path(temp)
        message = work / "message"
        message.write_bytes(b"T-Dongle isolated validation\n" + os.urandom(128))
        signature = work / "signature.gpg"
        encrypted = work / "encrypted.gpg"
        pin = ["--pinentry-mode", "loopback", "--passphrase-fd", "0"]
        call("gpg", "--batch", *pin, "--local-user", signing + "!", "--output", str(signature), "--detach-sign", str(message), input=pin_bytes)
        result = call("gpg", "--batch", "--status-fd", "1", "--verify", str(signature), str(message))
        if ("VALIDSIG " + signing).encode() not in result:
            raise RuntimeError("Unexpected signing fingerprint")
        print(f"PASS OpenPGP.1 {args.curves[0]} card signature and verification", flush=True)
        call("gpg", "--batch", "--trust-model", "always", "--recipient", decryption + "!", "--output", str(encrypted), "--encrypt", str(message))
        if call("gpg", "--batch", *pin, "--decrypt", str(encrypted), input=pin_bytes) != message.read_bytes():
            raise RuntimeError("Decrypted plaintext differs")
        print(f"PASS OpenPGP.2 {args.curves[1]} card decryption; identical plaintext", flush=True)
        public = work / "auth.pub"
        public.write_bytes(call("gpg", "--batch", "--export-ssh-key", authentication + "!"))
        allowed = work / "allowed"
        allowed.write_bytes(b"tdongle " + public.read_bytes())
        env = os.environ | {"SSH_AUTH_SOCK": call("gpgconf", "--list-dirs", "agent-ssh-socket").decode().strip()}
        call("ssh-keygen", "-Y", "sign", "-f", str(public), "-n", "tdongle-test", str(message), env=env)
        result = call("ssh-keygen", "-Y", "verify", "-f", str(allowed), "-I", "tdongle", "-n", "tdongle-test", "-s", str(message) + ".sig", input=message.read_bytes())
        if b'Good "tdongle-test" signature' not in result:
            raise RuntimeError("SSH authentication signature verification failed")
        print(f"PASS OpenPGP.3 {args.curves[2]} GnuPG SSH agent authentication and verification", flush=True)


if __name__ == "__main__":
    main()
