"""Check the app updater's write guards without opening a serial port."""
import contextlib
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import flash_app


class AppUpdate(unittest.TestCase):
    def setUp(self):
        stack = contextlib.ExitStack()
        self.addCleanup(stack.close)
        directory = stack.enter_context(tempfile.TemporaryDirectory())
        self.root = Path(directory)
        self.backup = self.root / "backup.age"
        self.metadata = self.backup.with_suffix(".json")
        self.partition = b"partition fixture"
        (self.root / "partitions.bin").write_bytes(self.partition)
        (self.root / "app.bin").write_bytes(b"application fixture")
        (self.root / "identity.txt").touch()
        (self.root / "flasher_args.json").write_text(json.dumps({
            "extra_esptool_args": {"chip": "esp32s3"},
            "app": {"offset": "0x10000", "file": "app.bin"},
            "partition-table": {"offset": "0x8000", "file": "partitions.bin"},
        }))
        stack.enter_context(patch.object(sys, "argv", [
            "flash_app.py", "--port", "fake", "--expected-mac", "00:11:22:33:44:55",
            "--build", directory, "--backup", str(self.backup),
            "--age-identity", str(self.root / "identity.txt"),
        ]))
        stack.enter_context(contextlib.redirect_stdout(io.StringIO()))
        self.commands = []
        self.read_size_delta = 0
        self.flash_mib = 4
        self.corrupt_userdata = False
        self.erased = False
        self.expected_mac = "00:11:22:33:44:55"
        stack.enter_context(patch.object(flash_app.subprocess, "run", side_effect=self.esptool))
        self.recover = stack.enter_context(patch.object(
            flash_app, "age_backup",
            return_value=(lambda data: b"fixture:" + data, lambda data: data.removeprefix(b"fixture:")),
        ))

    def esptool(self, invocation, **kwargs):
        command, *arguments = invocation[invocation.index("--after") + 2:]
        self.commands.append(command)
        stdout = ""
        if command == "read-mac":
            stdout = f"MAC:                {self.expected_mac}\n"
        elif command == "flash-id":
            stdout = f"Detected flash size: {self.flash_mib}MB\n"
        elif command == "read-flash":
            address, size, filename = arguments[-3:]
            self.assertEqual(arguments[arguments.index("--flash-size") + 1], f"{self.flash_mib}MB")
            data = bytes(int(size, 16))
            if address == "0x8000":
                data = self.partition + data[len(self.partition):]
            elif address == "0x0":
                self.assertEqual(int(size, 16), self.flash_mib * 1024 * 1024)
                data = data[:len(data) + self.read_size_delta]
            elif self.erased:
                data = b"\xff" * len(data)
            elif self.corrupt_userdata:
                data = b"x" + data[1:]
            Path(filename).write_bytes(data)
        elif command == "erase-flash":
            self.assertTrue(json.loads(self.metadata.read_text())["backup_recovery_verified"])
            self.erased = True
        elif command == "verify-flash" and self.erased:
            self.assertEqual(arguments[:2], ["--flash-size", f"{self.flash_mib}MB"])
        elif command == "write-flash":
            if self.erased:
                self.assertEqual(arguments, ["--flash-size", f"{self.flash_mib}MB", "0x0", str(self.root / "boot.bin"), "0x8000", str(self.root / "partitions.bin"), "0x10000", str(self.root / "app.bin")])
            else:
                self.assertEqual(arguments, ["0x10000", str(self.root / "app.bin")])
            self.assertTrue(self.backup.is_file())
            self.assertTrue(json.loads(self.metadata.read_text())["backup_recovery_verified"])
        return flash_app.subprocess.CompletedProcess(invocation, 0, stdout, "")

    def test_verified_backup_before_write_and_userdata_before_reset(self):
        flash_app.main()
        self.assertEqual(self.commands, [
            "read-mac", "flash-id", "read-flash", "read-flash", "write-flash",
            "verify-flash", "read-flash", "read-mac",
        ])
        self.assertTrue(json.loads(self.metadata.read_text())["userdata_verified_unchanged"])

    def test_recovery_requires_explicit_identity_confirmation_before_access(self):
        sys.argv.append("--factory-reset")
        with self.assertRaises(SystemExit):
            flash_app.main()
        self.assertEqual(self.commands, [])

    def test_missing_recovery_image_prevents_access_and_erase(self):
        sys.argv.extend(("--factory-reset", "--confirm-erase", "00:11:22:33:44:55"))
        with self.assertRaises(SystemExit):
            flash_app.main()
        self.assertEqual(self.commands, [])

    def recovery_fixture(self):
        (self.root / "boot.bin").write_bytes(b"boot fixture")
        path = self.root / "flasher_args.json"
        layout = json.loads(path.read_text())
        layout["bootloader"] = {"offset": "0x0", "file": "boot.bin"}
        path.write_text(json.dumps(layout))
        sys.argv.extend(("--factory-reset", "--confirm-erase", "00:11:22:33:44:55"))

    def test_recovery_checks_backup_then_erases_and_verifies_data(self):
        self.recovery_fixture()
        flash_app.main()
        self.assertLess(self.commands.index("erase-flash"), self.commands.index("write-flash"))
        self.assertTrue(json.loads(self.metadata.read_text())["userdata_verified_erased"])

    def test_wrong_device_prevents_recovery_erase(self):
        self.recovery_fixture()
        self.expected_mac = "00:11:22:33:44:66"
        with self.assertRaisesRegex(RuntimeError, "MAC mismatch"):
            flash_app.main()
        self.assertEqual(self.commands, ["read-mac"])
        self.assertFalse(self.backup.exists())

    def test_short_full_read_prevents_write(self):
        self.read_size_delta = -1
        with self.assertRaisesRegex(RuntimeError, "Short or oversized flash read"):
            flash_app.main()
        self.assertNotIn("write-flash", self.commands)
        self.assertFalse(self.backup.exists())

    def test_detected_16_mib_flash_is_backed_up_in_full(self):
        self.flash_mib = 16
        flash_app.main()
        self.assertEqual(json.loads(self.metadata.read_text())["flash_bytes"], 16 * 1024 * 1024)
        self.assertEqual(self.backup.stat().st_size, len(b"fixture:") + 16 * 1024 * 1024)

    def test_unsupported_flash_size_prevents_write(self):
        self.flash_mib = 2
        with self.assertRaisesRegex(RuntimeError, "Unsupported or unknown physical flash size"):
            flash_app.main()
        self.assertEqual(self.commands, ["read-mac", "flash-id"])

    def test_failed_recovery_prevents_write(self):
        self.recover.return_value = (lambda data: data, lambda data: b"corrupt")
        with self.assertRaisesRegex(RuntimeError, "recovery verification failed"):
            flash_app.main()
        self.assertNotIn("write-flash", self.commands)

    def test_changed_credentials_prevent_reset(self):
        self.corrupt_userdata = True
        with self.assertRaisesRegex(RuntimeError, "User-data verification failed"):
            flash_app.main()
        self.assertEqual(self.commands.count("read-mac"), 1)
        self.assertNotIn("userdata_verified_unchanged", json.loads(self.metadata.read_text()))


if __name__ == "__main__":
    unittest.main(verbosity=2)
