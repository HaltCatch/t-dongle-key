"""Update only the T-Dongle application after verifying an encrypted backup."""
import argparse
import ctypes
from ctypes import wintypes
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile


def protect_windows(data):
    class Blob(ctypes.Structure):
        _fields_ = [("size", wintypes.DWORD), ("data", ctypes.POINTER(ctypes.c_ubyte))]
    storage = (ctypes.c_ubyte * len(data)).from_buffer_copy(data)
    source, target = Blob(len(data), storage), Blob()
    crypt = ctypes.WinDLL("crypt32", use_last_error=True)
    crypt.CryptProtectData.argtypes = [ctypes.POINTER(Blob), wintypes.LPCWSTR,
        ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(Blob)]
    crypt.CryptProtectData.restype = wintypes.BOOL
    if not crypt.CryptProtectData(ctypes.byref(source), "T-Dongle pre-update flash",
                                  None, None, None, 1, ctypes.byref(target)):
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        return ctypes.string_at(target.data, target.size)
    finally:
        free = ctypes.WinDLL("kernel32").LocalFree
        free.argtypes = [ctypes.c_void_p]
        free(target.data)


def unprotect_windows(data):
    """Recover a current-user DPAPI backup in memory, without a plaintext file."""
    class Blob(ctypes.Structure):
        _fields_ = [("size", wintypes.DWORD), ("data", ctypes.POINTER(ctypes.c_ubyte))]
    storage = (ctypes.c_ubyte * len(data)).from_buffer_copy(data)
    source, target = Blob(len(data), storage), Blob()
    crypt = ctypes.WinDLL("crypt32", use_last_error=True)
    crypt.CryptUnprotectData.argtypes = [ctypes.POINTER(Blob), ctypes.c_void_p,
        ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(Blob)]
    crypt.CryptUnprotectData.restype = wintypes.BOOL
    if not crypt.CryptUnprotectData(ctypes.byref(source), None, None, None, None, 1, ctypes.byref(target)):
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        return ctypes.string_at(target.data, target.size)
    finally:
        free = ctypes.WinDLL("kernel32").LocalFree
        free.argtypes = [ctypes.c_void_p]
        free(target.data)


def age_backup(identity):
    recipients = subprocess.run(
        ["age-keygen", "-y", str(identity)], check=True, capture_output=True, text=True
    ).stdout.splitlines()
    if not recipients:
        raise ValueError("The age identity has no recipients")
    encrypt = ["age"]
    for recipient in recipients:
        encrypt.extend(("-r", recipient))
    decrypt = ["age", "-d", "-i", str(identity)]

    def run(command, data):
        return subprocess.run(command, input=data, stdout=subprocess.PIPE, check=True).stdout

    return lambda data: run(encrypt, data), lambda data: run(decrypt, data)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", required=True)
    parser.add_argument("--expected-mac", required=True, help="Previously identified T-Dongle MAC")
    parser.add_argument("--build", type=Path, required=True)
    parser.add_argument("--backup", type=Path, required=True, help="New encrypted backup path")
    parser.add_argument("--age-identity", type=Path, help="Existing age identity file for encryption and recovery")
    parser.add_argument("--stub", action=argparse.BooleanOptionalAction, default=os.name != "nt",
                        help="Use the RAM flasher for fast transfers (default on macOS/Linux, off on Windows)")
    parser.add_argument("--factory-reset", action="store_true", help="Erase ordinary flash and restore bootloader, partitions and app after verified backup")
    parser.add_argument("--confirm-erase", help="For factory recovery repeat the expected device MAC")
    args = parser.parse_args()
    if args.factory_reset and args.confirm_erase != args.expected_mac:
        parser.error("Factory recovery requires --confirm-erase matching --expected-mac")
    metadata_path = args.backup.with_suffix(".json")
    if args.backup == metadata_path:
        parser.error("Use a backup filename ending in .dpapi or .age, separate from the JSON metadata")
    if args.backup.exists() or metadata_path.exists():
        parser.error("Backup path already exists")
    if args.age_identity is not None:
        if not args.age_identity.is_file():
            parser.error("The age identity must be an existing file")
        try:
            protect, unprotect = age_backup(args.age_identity)
        except FileNotFoundError:
            parser.error("Install age and age-keygen before using --age-identity")
        backup_format = "age"
    elif os.name == "nt":
        protect, unprotect = protect_windows, unprotect_windows
        backup_format = "Windows DPAPI current-user"
    else:
        parser.error("Specify --age-identity on macOS or Linux")
    layout = json.loads((args.build / "flasher_args.json").read_text())
    if layout["extra_esptool_args"]["chip"] != "esp32s3":
        parser.error("Unexpected build chip")
    offset = int(layout["app"]["offset"], 0)
    app = args.build / layout["app"]["file"]
    partition = args.build / layout["partition-table"]["file"]
    if offset != 0x10000 or not 0 < app.stat().st_size <= 0x1e0000:
        parser.error("Application would exceed the established partition")
    if int(layout["partition-table"]["offset"], 0) != 0x8000:
        parser.error("Unexpected partition table offset")

    recovery_images = []
    if args.factory_reset:
        # Validate every input before connecting, backing up, or erasing.
        for name, address, limit in (("bootloader", 0, 0x8000),
                                      ("partition-table", 0x8000, 0x1000),
                                      ("app", 0x10000, 0x1e0000)):
            entry = layout.get(name, {})
            if int(entry.get("offset", "-1"), 0) != address:
                parser.error(f"Unexpected recovery {name} offset")
            filename = args.build / entry["file"]
            if not filename.is_file() or not 0 < filename.stat().st_size <= limit:
                parser.error(f"Missing or oversized recovery image: {filename}")
            recovery_images.extend((hex(address), filename))

    def esptool(*command, reset=False, initial=False):
        # Keep the ROM fallback for the observed Windows USB issue; normal
        # macOS/Linux transfers use esptool's RAM flasher without flash changes.
        invocation = [sys.executable, "-m", "esptool", *([] if args.stub else ["--no-stub"]),
                      "--chip", "esp32s3", "--port", args.port,
                      "--baud", "460800", "--before", "default-reset" if initial else "no-reset", "--after",
                      "hard-reset" if reset else "no-reset", *map(str, command)]
        result = subprocess.run(invocation, capture_output=True, text=True)
        print(result.stdout, end="")
        if result.returncode:
            raise RuntimeError(result.stderr or "esptool failed")
        return result.stdout

    mac = args.expected_mac.lower().replace("-", ":")
    if not re.fullmatch(r"(?:[0-9a-f]{2}:){5}[0-9a-f]{2}", mac):
        parser.error("Invalid --expected-mac")
    identity = esptool("read-mac", initial=True)
    if not re.search(rf"^(?:BASE )?MAC:\s*{re.escape(mac)}\s*$", identity, re.IGNORECASE | re.MULTILINE):
        raise RuntimeError("MAC mismatch; no flash changes made")
    flash_id = esptool("flash-id")
    capacity = re.search(r"^Detected flash size:[ \t]*(4|8|16)[ \t]*MB[ \t]*$", flash_id, re.IGNORECASE | re.MULTILINE)
    if capacity is None:
        raise RuntimeError("Unsupported or unknown physical flash size; no flash changes made")
    flash_size = f"{capacity[1]}MB"
    flash_bytes = int(capacity[1]) * 1024 * 1024

    args.backup.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="tdongle-backup-") as directory:
        temporary = Path(directory)

        def read_flash(address, size, filename):
            path = temporary / filename
            esptool("read-flash", "--no-progress", "--flash-size", flash_size, hex(address), hex(size), path)
            data = path.read_bytes()
            if len(data) != size:
                raise RuntimeError(f"Short or oversized flash read at {address:#x}")
            return data

        expected_partition = partition.read_bytes()
        if not expected_partition or (not args.factory_reset and
            not read_flash(0x8000, 0x1000, "partition.bin").startswith(expected_partition)):
            raise RuntimeError("Device partition table differs; no flash changes made")
        before = read_flash(0, flash_bytes, "before.bin")
        encrypted = protect(before)
        # A complete encrypted backup is durable before the first write.
        with args.backup.open("xb") as output:
            output.write(encrypted)
            output.flush()
            os.fsync(output.fileno())
        if unprotect(args.backup.read_bytes()) != before:
            raise RuntimeError("Encrypted backup recovery verification failed; no flash changes made")
        metadata = {"mac": mac, "format": backup_format, "backup_recovery_verified": True,
                    "flash_bytes": flash_bytes,
                    "flash_sha256": hashlib.sha256(before).hexdigest(),
                    "app_sha256": hashlib.sha256(app.read_bytes()).hexdigest(),
                    "userdata_sha256": hashlib.sha256(before[0x200000:0x300000]).hexdigest()}
        with metadata_path.open("x") as output:
            output.write(json.dumps(metadata, indent=2) + "\n")
        if args.factory_reset:
            esptool("erase-flash")
            esptool("write-flash", "--flash-size", flash_size, *recovery_images)
            esptool("verify-flash", "--flash-size", flash_size, *recovery_images)
            if read_flash(0x200000, 0x100000, "after-data.bin") != b"\xff" * 0x100000:
                raise RuntimeError("Factory recovery data area is not erased; keep device in download mode")
            metadata["userdata_verified_erased"] = True
        else:
            esptool("write-flash", hex(offset), app)
            esptool("verify-flash", hex(offset), app)
            if read_flash(0x200000, 0x100000, "after-data.bin") != before[0x200000:0x300000]:
                raise RuntimeError("User-data verification failed; keep device in download mode and restore backup")
            metadata["userdata_verified_unchanged"] = True
        metadata_path.write_text(json.dumps(metadata, indent=2) + "\n")
        esptool("read-mac", reset=True)
    print("PASS: firmware verified; encrypted backup saved; credential partition " +
          ("erased by explicit factory recovery" if args.factory_reset else "unchanged"))


if __name__ == "__main__":
    main()
