#!/usr/bin/env python3
"""Load an ESP32-S3 SD audit into RAM and collect its USB serial report."""
import argparse
import sys
import time
from pathlib import Path

import esptool
from esptool import cmds


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", required=True)
    parser.add_argument("--mac", required=True, help="Expected chip MAC, colon separated")
    parser.add_argument("image", type=Path, help="RAM audit binary")
    args = parser.parse_args()
    expected = bytes.fromhex(args.mac.replace(":", ""))
    if len(expected) != 6:
        parser.error("expected a six-byte MAC")

    image = args.image.read_bytes()
    with esptool.detect_chip(args.port) as esp:
        if esp.CHIP_NAME != "ESP32-S3" or bytes(esp.read_mac("BASE_MAC")) != expected:
            sys.exit("Unexpected device; diagnostic not loaded")
        cmds.load_ram(esp, image)
        esp._port.timeout = 0.5
        deadline = time.monotonic() + 30
        report = False
        passed = False
        while time.monotonic() < deadline:
            line = esp._port.readline().decode("utf-8", errors="replace").rstrip()
            if line == "TDONGLE_SD_AUDIT_BEGIN":
                report = True
            if not report or not line:
                continue
            print(line, flush=True)
            if line.startswith("AUDIT PASS "):
                passed = True
            if line == "TDONGLE_SD_AUDIT_END":
                if not passed:
                    sys.exit("SD writer audit failed")
                return
    sys.exit("No complete SD audit report")


if __name__ == "__main__":
    main()
