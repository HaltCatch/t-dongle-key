"""Exercise competing CTAPHID channels on one real simulator transport."""
import os
import tempfile
import time
import unittest
from contextlib import closing

from test_emulation import HidTcp, emulator, packet, response


def frame(cid, command, data=b"", size=None):
    return (cid + bytes([command | 0x80]) +
            (len(data) if size is None else size).to_bytes(2, "big") + data).ljust(64, b"\0")


class HidTransactionRegression(unittest.TestCase):
    def test_next_request_is_retained_while_long_response_drains(self):
        with tempfile.TemporaryDirectory() as state, emulator(state), closing(HidTcp()) as d:
            data = os.urandom(1024)
            other = b"BCDE"
            frames = [frame(d.cid, 1, data[:57], len(data))]
            frames += [(d.cid + bytes([i]) + data[p:p+59]).ljust(64, b"\0")
                       for i, p in enumerate(range(57, len(data), 59))]
            frames += [frame(other, 1, b"next client")]
            d.sock.sendall(b"".join(len(f).to_bytes(2, "big") + f for f in frames))
            self.assertEqual(d.read(), (1, data))
            self.assertEqual(self.read_frame(d), (other, 0x81, b"next client"))

    def test_cancel_before_presence_event_is_not_lost(self):
        with tempfile.TemporaryDirectory() as state, emulator(state, auto_touch=False), closing(HidTcp()) as d:
            # One TCP write gives the dispatcher both reports before it polls
            # the worker's user-presence event.
            frames = (frame(d.cid, 0x10, b"\x0b"), frame(d.cid, 0x11))
            d.sock.sendall(b"".join(len(f).to_bytes(2, "big") + f for f in frames))
            started = time.monotonic()
            while True:
                command, data = d.read()
                if command != 0x3b:
                    self.assertEqual((command, data), (0x10, b"\x2d"))
                    break
            self.assertLess(time.monotonic() - started, 2)
            self.assertEqual(d.call(1, b"recovered"), b"recovered")

    def read_frame(self, device):
        data = response(device.sock)
        self.assertEqual(len(data), 64)
        return data[:4], data[4], data[7:7 + int.from_bytes(data[5:7], "big")]

    def wait_for_touch(self, device):
        device.send(0x10, b"\x0b")
        for _ in range(12):
            cid, command, data = self.read_frame(device)
            self.assertEqual(cid, device.cid)
            self.assertEqual(command, 0xbb)
            if data == b"\x02":
                return
        self.fail("No presence request")

    def test_foreign_request_during_presence_preserves_owner_and_cancel(self):
        with tempfile.TemporaryDirectory() as state, emulator(state, auto_touch=False), closing(HidTcp()) as d:
            self.wait_for_touch(d)
            other = b"\x42\x43\x44\x45"
            packet(d.sock, frame(other, 0x10, b"\x04"))
            for _ in range(12):
                cid, command, data = self.read_frame(d)
                if cid == other:
                    self.assertEqual((command, data), (0xbf, b"\x06"))
                    break
                self.assertEqual((cid, command), (d.cid, 0xbb))
            else:
                self.fail("Competing CID was not rejected")
            d.send(0x11)
            for _ in range(12):
                cid, command, data = self.read_frame(d)
                self.assertEqual(cid, d.cid)
                if command != 0xbb:
                    self.assertEqual((command, data), (0x90, b"\x2d"))
                    break
            else:
                self.fail("Original request did not cancel")
            self.assertEqual(d.call(1, b"recovered"), b"recovered")

    def test_fragmented_receive_cannot_be_stolen_after_100ms(self):
        with tempfile.TemporaryDirectory() as state, emulator(state), closing(HidTcp()) as d:
            payload = os.urandom(100)
            packet(d.sock, frame(d.cid, 1, payload[:57], len(payload)))
            time.sleep(0.15)  # Below the 500 ms CTAPHID packet timeout.
            other = b"\x42\x43\x44\x45"
            packet(d.sock, frame(other, 1, b"intruder"))
            self.assertEqual(self.read_frame(d), (other, 0xbf, b"\x06"))
            packet(d.sock, (d.cid + b"\0" + payload[57:]).ljust(64, b"\0"))
            self.assertEqual(d.read(), (1, payload))
            self.assertEqual(d.call(1, b"recovered"), b"recovered")

    def test_same_channel_init_unwinds_waiting_worker(self):
        with tempfile.TemporaryDirectory() as state, emulator(state, auto_touch=False), closing(HidTcp()) as d:
            self.wait_for_touch(d)
            nonce = os.urandom(8)
            d.send(6, nonce)
            for _ in range(15):
                cid, command, data = self.read_frame(d)
                self.assertEqual(cid, d.cid)
                if command == 0x86:
                    self.assertEqual(data[:8], nonce)
                    self.assertEqual(data[8:12], d.cid)
                    break
                self.assertIn(command, (0xbb, 0x90))
            else:
                self.fail("INIT did not resynchronize")
            self.assertEqual(d.call(1, b"recovered"), b"recovered")

    def test_bad_sequence_aborts_assembly_and_releases_channel(self):
        with tempfile.TemporaryDirectory() as state, emulator(state), closing(HidTcp()) as d:
            packet(d.sock, frame(d.cid, 1, b"x" * 57, 100))
            packet(d.sock, (d.cid + b"\x01" + b"x" * 43).ljust(64, b"\0"))
            self.assertEqual(self.read_frame(d), (d.cid, 0xbf, b"\x04"))
            d.cid = b"BCDE"
            self.assertEqual(d.call(1, b"released"), b"released")

    def test_init_requires_exact_nonce_length(self):
        with tempfile.TemporaryDirectory() as state, emulator(state), closing(HidTcp()) as d:
            for size in (0, 7, 9, 58):
                with self.subTest(size=size):
                    packet(d.sock, frame(d.cid, 6, b"x" * min(size, 57), size))
                    self.assertEqual(self.read_frame(d), (d.cid, 0xbf, b"\x03"))
            self.assertEqual(d.call(1, b"recovered"), b"recovered")

    def test_fragment_timeout_and_same_channel_restart(self):
        with tempfile.TemporaryDirectory() as state, emulator(state), closing(HidTcp()) as d:
            packet(d.sock, frame(d.cid, 1, b"x" * 57, 100))
            self.assertEqual(self.read_frame(d), (d.cid, 0xbf, b"\x05"))
            packet(d.sock, frame(d.cid, 1, b"x" * 57, 100))
            nonce = os.urandom(8)
            answer = d.call(6, nonce)
            self.assertEqual(answer[:8], nonce)
            self.assertEqual(d.call(1, b"recovered"), b"recovered")


if __name__ == "__main__":
    unittest.main()
