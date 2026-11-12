"""Exercise the real combined firmware over loopback, never enumerate USB devices."""
import contextlib
import hashlib
import os
from pathlib import Path
import select
import socket
import statistics
import subprocess
import tempfile
import threading
import time
import unittest

from fido2.ctap2 import Ctap2

BINARY = Path(os.environ.get("TDONGLE_SIM_BINARY", "build-desktop/pico_fido2")).resolve()


def receive(sock, size):
    result = b""
    while len(result) < size:
        part = sock.recv(size - len(result))
        if not part:
            raise EOFError("simulator closed connection")
        result += part
    return result


def packet(sock, data, fragmented=False):
    frame = len(data).to_bytes(2, "big") + data
    if fragmented:
        # The old transport assumed recv(2) and recv(payload) returned everything.
        for size in [1, 1, 3, 7, 11, len(frame)]:
            if frame:
                sock.sendall(frame[:size])
                frame = frame[size:]
                time.sleep(0.002)
    else:
        sock.sendall(frame)


def response(sock):
    return receive(sock, int.from_bytes(receive(sock, 2), "big"))


class HidTcp:
    capabilities = 4  # CTAPHID_CAPABILITY_CBOR

    def __init__(self, fragmented=False):
        self.sock = socket.create_connection(("127.0.0.1", 35962), timeout=5)
        self.cid = b"\xff" * 4
        self.fragmented = fragmented
        nonce = os.urandom(8)
        self.send(6, nonce)
        command, data = self.read()
        assert command == 6 and data[:8] == nonce
        self.cid = data[8:12]

    def send(self, command, data=b""):
        packet(self.sock, (self.cid + bytes([int(command) | 0x80]) +
               len(data).to_bytes(2, "big") + data[:57]).ljust(64, b"\0"), self.fragmented)
        for sequence, offset in enumerate(range(57, len(data), 59)):
            packet(self.sock, (self.cid + bytes([sequence]) + data[offset:offset + 59]).ljust(64, b"\0"), self.fragmented)

    def read(self):
        first = response(self.sock)
        assert len(first) == 64 and first[:4] == self.cid
        command = first[4] & 0x7f
        size = int.from_bytes(first[5:7], "big")
        data = first[7:]
        sequence = 0
        while len(data) < size:
            continuation = response(self.sock)
            assert len(continuation) == 64 and continuation[:4] == self.cid
            assert continuation[4] == sequence
            sequence += 1
            data += continuation[5:]
        return command, data[:size]

    def call(self, command, data=b"", event=None, on_keepalive=None):
        self.send(command, data)
        while True:
            result_command, result = self.read()
            if result_command == 0x3b:
                if on_keepalive:
                    on_keepalive(result[0])
                if event and event.is_set():
                    self.send(0x11)
                continue
            if result_command == 0x3f:
                raise RuntimeError("CTAPHID error: " + result.hex())
            assert result_command == int(command)
            return result

    def close(self):
        self.sock.close()


class CardTcp:
    def __init__(self):
        self.sock = socket.create_connection(("127.0.0.1", 35963), timeout=5)

    def exchange(self, data, fragmented=False):
        packet(self.sock, data, fragmented)
        answer = response(self.sock)
        # ISO 7816 GET RESPONSE continuation uses the real firmware APDU path.
        content = b""
        while answer[-2] == 0x61:
            content += answer[:-2]
            packet(self.sock, b"\x00\xc0\x00\x00" + answer[-1:])
            answer = response(self.sock)
        return content + answer

    def select(self, aid):
        aid = bytes.fromhex(aid)
        answer = self.exchange(b"\x00\xa4\x04\x00" + bytes([len(aid)]) + aid, True)
        assert answer[-2:] == b"\x90\x00", answer.hex()
        return answer[:-2]

    def close(self):
        self.sock.close()


@contextlib.contextmanager
def emulator(state_directory, auto_touch=True):
    # Refuse to accidentally connect tests to another simulator instance.
    for port in [35962, 35963]:
        with socket.socket() as check:
            check.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            check.bind(("127.0.0.1", port))
    env = os.environ | {
        "PICOKEYS_EMULATION_CCID_LISTEN": "1",
        "TDONGLE_EMUL_AUTO_TOUCH": "1" if auto_touch else "0",
    }
    with tempfile.TemporaryDirectory(prefix="tdongle-emulator-log-") as directory:
        log_path = Path(directory) / "simulator.log"
        with log_path.open("wb") as log:
            process = subprocess.Popen([str(BINARY), "--headless", "--state-dir", state_directory],
                                       env=env, stdout=log, stderr=subprocess.STDOUT)
        try:
            # The startup message follows both listen() calls. A TCP probe
            # can still occupy the HID accept queue when the first test connects.
            for _ in range(200):
                if process.poll() is not None:
                    raise RuntimeError(log_path.read_text(errors="replace")[-4000:])
                if b"Emulation on loopback: FIDO 35962, CCID 35963;" in log_path.read_bytes():
                    break
                time.sleep(0.025)
            else:
                raise TimeoutError("native firmware did not start")
            try:
                yield log_path
                assert process.poll() is None, "simulator crashed during test"
            except Exception:
                print(log_path.read_text(errors="replace")[-4000:])
                raise
        finally:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()


class ProtocolRegression(unittest.TestCase):
    def test_reopening_flash_preserves_last_byte(self):
        with tempfile.TemporaryDirectory() as state:
            image = Path(state) / "memory.flash"
            data = bytearray(8 * 1024 * 1024)
            data[-1] = 0x5a  # Reserved trailer, outside filesystem records.
            image.write_bytes(data)
            with emulator(state), contextlib.closing(HidTcp()) as hid:
                self.assertEqual(hid.call(1, b"flash reopened"), b"flash reopened")
            self.assertEqual(image.read_bytes()[-1], 0x5a)

    def test_ctap_registration_authentication_and_persistence(self):
        self.check_fido_credential(-7)

    def test_ed25519_registration_authentication_and_persistence(self):
        self.check_fido_credential(-8)

    def check_fido_credential(self, algorithm):
        with tempfile.TemporaryDirectory(prefix="tdongle-test-") as directory:
            rp = {"id": "simulator-test.example.invalid", "name": "Simulator regression"}
            challenge = hashlib.sha256(b"test-only-client-data").digest()
            with emulator(directory):
                device = HidTcp(fragmented=True)
                self.assertEqual(device.call(1, bytes(range(256)) * 2), bytes(range(256)) * 2)
                ctap = Ctap2(device)
                self.assertIn("FIDO_2_0", ctap.info.versions)
                self.assertIn(algorithm, [item["alg"] for item in ctap.info.algorithms])
                result = ctap.make_credential(challenge, rp, {"id": b"test-user", "name": "test-user"},
                                              [{"type": "public-key", "alg": algorithm}], options={"rk": True})
                credential = result.auth_data.credential_data
                self.assertEqual(credential.public_key[3], algorithm)
                self.assertTrue(result.auth_data.flags & 1)
                assertion = ctap.get_assertion(rp["id"], challenge,
                                               [{"type": "public-key", "id": credential.credential_id}])
                credential.public_key.verify(bytes(assertion.auth_data) + challenge, assertion.signature)
                count = assertion.auth_data.counter
                device.close()
                time.sleep(0.1)  # Let the same flash writer used by the firmware finish.
            with emulator(directory):
                device = HidTcp()
                assertion = Ctap2(device).get_assertion(rp["id"], challenge,
                            [{"type": "public-key", "id": credential.credential_id}])
                credential.public_key.verify(bytes(assertion.auth_data) + challenge, assertion.signature)
                self.assertGreater(assertion.auth_data.counter, count)
                device.close()

    def test_combined_card_applications_and_apdu_stress(self):
        with tempfile.TemporaryDirectory(prefix="tdongle-card-") as directory, emulator(directory):
            card = CardTcp()
            for aid in ["a000000308000010000100", "a0000005272101", "a0000005272001", "d27600012401"]:
                card.select(aid)
            answer = card.exchange(bytes.fromhex("00ca006e00"))
            self.assertEqual(answer[-2:], b"\x90\x00")
            self.assertGreater(len(answer), 200)
            elapsed = []
            for _ in range(200):
                start = time.monotonic()
                self.assertEqual(card.exchange(bytes.fromhex("00ca006e00")), answer)
                elapsed.append((time.monotonic() - start) * 1000)
            print(f"\nAPDU >200 bytes: 200 exchanges; median {statistics.median(elapsed):.2f} ms; max {max(elapsed):.2f} ms")
            card.close()

    def test_invalid_and_fragmented_frames_do_not_crash(self):
        with tempfile.TemporaryDirectory(prefix="tdongle-frame-") as directory, emulator(directory):
            for size in [0, 65, 65535]:
                with socket.create_connection(("127.0.0.1", 35962), timeout=5) as sock:
                    sock.sendall(size.to_bytes(2, "big") + b"x" * min(size, 65))
                time.sleep(0.02)
                device = HidTcp(fragmented=True)
                self.assertIn("FIDO_2_0", Ctap2(device).info.versions)
                device.close()
            with contextlib.closing(HidTcp()) as device:
                with self.assertRaisesRegex(RuntimeError, "CTAPHID error: 03"):
                    device.call(1, bytes(4096))
                self.assertEqual(device.call(1, b"ready"), b"ready")

    def wait_for_presence(self, device):
        device.send(0x10, b"\x0b")  # authenticatorSelection
        for _ in range(20):
            command, data = device.read()
            self.assertEqual(command, 0x3b)
            if data == b"\x02":  # UPNEEDED, after initial PROCESSING keepalive
                return
        self.fail("Selection never asked for a button press")

    def cancel_presence(self, device):
        device.send(0x11)
        for _ in range(20):
            command, data = device.read()
            if command != 0x3b:
                self.assertEqual((command, data), (0x10, b"\x2d"))
                return
        self.fail("Selection never returned KEEPALIVE_CANCEL")

    def test_user_presence_waits_and_cancel_completes(self):
        with tempfile.TemporaryDirectory(prefix="tdongle-presence-") as directory, \
             emulator(directory, auto_touch=False) as log:
            with contextlib.closing(HidTcp()) as device:
                self.wait_for_presence(device)
                self.cancel_presence(device)
            events = [line for line in log.read_text().splitlines() if line.startswith("USER_PRESENCE:")]
            self.assertEqual(events, ["USER_PRESENCE: waiting", "USER_PRESENCE: cancelled"])

    def test_ccid_waits_until_fido_releases_shared_apdu_state(self):
        with tempfile.TemporaryDirectory(prefix="tdongle-overlap-") as directory, emulator(directory, auto_touch=False):
            with contextlib.closing(HidTcp()) as device, contextlib.closing(CardTcp()) as card:
                self.wait_for_presence(device)
                packet(card.sock, bytes.fromhex("00a4040006d27600012401"))
                self.assertFalse(select.select([card.sock], [], [], 0.05)[0])
                self.cancel_presence(device)
                self.assertEqual(response(card.sock)[-2:], b"\x90\0")
                self.assertEqual(card.exchange(bytes.fromhex("00ca006e00"))[-2:], b"\x90\0")
                payload = bytes(range(256)) * 4
                self.assertEqual(device.call(1, payload), payload)

    def test_reconnect_after_disconnect_during_touch_wait(self):
        with tempfile.TemporaryDirectory(prefix="tdongle-reconnect-") as directory, emulator(directory, auto_touch=False):
            with contextlib.closing(HidTcp()) as device:
                self.wait_for_presence(device)
            with contextlib.closing(HidTcp()) as reconnected:
                self.assertEqual(reconnected.call(1, b"ready"), b"ready")
                self.wait_for_presence(reconnected)
                self.cancel_presence(reconnected)


if __name__ == "__main__":
    unittest.main(verbosity=2)
