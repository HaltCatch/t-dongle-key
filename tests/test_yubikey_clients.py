"""Run official client parsers over loopback: ykman script -f -s tests FILE."""
import tempfile
import socket
import struct
import threading
import time
from concurrent.futures import ThreadPoolExecutor
import os
import hmac
import io
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
from contextlib import redirect_stdout
import unittest
from contextlib import closing

from yubikit.core import TRANSPORT, Tlv
from yubikit.core.smartcard import SmartCardConnection
from yubikit.oath import OathSession
from yubikit.openpgp import OpenPgpSession
from yubikit.openpgp import KEY_REF, KEY_STATUS
from yubikit.openpgp import PIN_POLICY as PGP_PIN_POLICY, UIF, DO
from ykman.openpgp import get_openpgp_info
from ykman.piv import pivman_set_mgm_key, get_pivman_protected_data, get_pivman_data
from yubikit.core import InvalidPinError, TimeoutError as YubiKitTimeoutError
from yubikit.core.smartcard import ApduError, SW
from yubikit.oath import CredentialData, OATH_TYPE, HASH_ALGORITHM
from yubikit.piv import DEFAULT_MANAGEMENT_KEY, MANAGEMENT_KEY_TYPE
from yubikit.piv import PivSession
from yubikit.piv import SLOT, OBJECT_ID, KEY_TYPE
from yubikit.piv import PIN_POLICY as PIV_PIN_POLICY, TOUCH_POLICY
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec, padding, ed25519, ed448
from yubikit.core.otp import OtpConnection, CommandRejectedError
from yubikit.yubiotp import YubiOtpSession, HmacSha1SlotConfiguration, SLOT as OTP_SLOT
from test_emulation import CardTcp, HidTcp, emulator, packet, response
from fido2.ctap2 import Ctap2
from test_openpgp_isolation import configure, exercise, apdu


class LoopbackCard(SmartCardConnection):
    def __init__(self):
        self.card = CardTcp()

    @property
    def transport(self):
        return TRANSPORT.USB

    def send_and_receive(self, apdu):
        reply = self.card.exchange(apdu)
        return reply[:-2], int.from_bytes(reply[-2:], "big")

    def close(self):
        self.card.close()


class LoopbackOtp(OtpConnection):
    def __init__(self):
        self.sock = socket.create_connection(("127.0.0.1", 35964), timeout=10)

    def send(self, data):
        packet(self.sock, data)
        assert response(self.sock) == b""

    def receive(self):
        packet(self.sock, b"\0")
        return response(self.sock)

    def close(self):
        self.sock.close()


def exercise_client_settings(connect):
    """Changes disposable test-card settings, checks fresh sessions, then restores.

    `connect` must select the caller's isolated simulator or explicitly disposable
    physical card. Never invoke this against an ordinary personal security key.
    """
    def check(value, message):
        if not value:
            raise AssertionError(message)

    secret = os.urandom(20)
    original = "client-settings-test"
    renamed = "client-settings-renamed"
    with closing(connect()) as conn:
        oath = OathSession(conn)
        check(not any(c.name in (original, renamed) for c in oath.list_credentials()), "fixture already exists")
        data = CredentialData(original, OATH_TYPE.TOTP, HASH_ALGORITHM.SHA256, secret, 8, 30)
        cred = oath.put_credential(data)
        code = oath.calculate_code(cred, 1234567890)
        digest = hmac.digest(secret, (1234567890 // 30).to_bytes(8, "big"), "sha256")
        off = digest[-1] & 15
        check(code.value == f"{(int.from_bytes(digest[off:off+4], 'big') & 0x7fffffff) % 100000000:08d}", "TOTP mismatch")
        new_id = oath.rename_credential(cred.id, renamed)
        check(any(c.id == new_id and c.name == renamed for c in oath.list_credentials()), "rename not stored")
        oath.set_key(oath.derive_key("temporary client password"))
    with closing(connect()) as conn:
        oath = OathSession(conn)
        check(oath.locked, "OATH password did not lock fresh session")
        try:
            oath.validate(oath.derive_key("incorrect client password"))
        except ApduError:
            pass
        else:
            raise AssertionError("OATH accepted incorrect password")
        oath.validate(oath.derive_key("temporary client password"))
        check(any(c.name == renamed for c in oath.list_credentials()), "unlock lost credential")
        oath.unset_key()
        oath.delete_credential(new_id)
    with closing(connect()) as conn:
        oath = OathSession(conn)
        check(not oath.locked, "OATH password not removed")
        check(not any(c.name == renamed for c in oath.list_credentials()), "delete not stored")
    print("PASS OATH SHA256/8-digit TOTP, rename, password lock/reject/unlock/remove, delete", flush=True)

    temporary_key = os.urandom(24)
    with closing(connect()) as conn:
        piv = PivSession(conn)
        piv.change_pin("123456", "654321")
        piv.change_puk("12345678", "87654321")
    with closing(connect()) as conn:
        piv = PivSession(conn)
        try:
            piv.verify_pin("123456")
        except InvalidPinError:
            pass
        else:
            raise AssertionError("PIV accepted old PIN")
        piv.verify_pin("654321")
        piv.authenticate(DEFAULT_MANAGEMENT_KEY)
        piv.set_management_key(MANAGEMENT_KEY_TYPE.AES192, temporary_key)
    with closing(connect()) as conn:
        piv = PivSession(conn)
        piv.authenticate(temporary_key)
        piv.set_management_key(MANAGEMENT_KEY_TYPE.AES192, DEFAULT_MANAGEMENT_KEY)
        piv.unblock_pin("87654321", "123456")
        piv.change_puk("87654321", "12345678")
        piv.verify_pin("123456")
    print("PASS PIV PIN/PUK change, old PIN rejected, management key change/auth/restore, unblock", flush=True)

    with closing(connect()) as conn:
        pgp = OpenPgpSession(conn)
        pgp.change_pin("123456", "654321")
        pgp.change_admin("12345678", "87654321")
    with closing(connect()) as conn:
        pgp = OpenPgpSession(conn)
        pgp.verify_pin("654321")
        pgp.verify_admin("87654321")
        old_policy = pgp.get_pin_status().pin_policy_user
        pgp.set_signature_pin_policy(PGP_PIN_POLICY.ALWAYS)
        check(pgp.get_pin_status().pin_policy_user == PGP_PIN_POLICY.ALWAYS, "signature policy not stored")
        pgp.set_signature_pin_policy(old_policy)
        pgp.set_reset_code("temporary reset code")
        pgp.reset_pin("123456", "temporary reset code")
        pgp.verify_admin("87654321")
        pgp.put_data(DO.RESETTING_CODE, b"")
        for ref in (KEY_REF.SIG, KEY_REF.DEC, KEY_REF.AUT):
            pgp.set_uif(ref, UIF.ON)
            check(pgp.get_uif(ref) == UIF.ON, "touch policy not stored")
            pgp.set_uif(ref, UIF.OFF)
        pgp.change_admin("87654321", "12345678")
        pgp.verify_pin("123456")
    print("PASS OpenPGP user/admin PIN, reset code/unblock, signature PIN policy, three touch policies restored", flush=True)


def exercise_protected_management_key(connect):
    key = os.urandom(24)
    with closing(connect()) as conn:
        piv = PivSession(conn)
        piv.verify_pin("123456")
        piv.authenticate(DEFAULT_MANAGEMENT_KEY)
        pivman_set_mgm_key(piv, key, MANAGEMENT_KEY_TYPE.AES192, store_on_device=True)
    try:
        with closing(connect()) as conn:
            piv = PivSession(conn)
            if not get_pivman_data(piv).has_stored_key:
                raise AssertionError("protected-key metadata missing")
            try:
                get_pivman_protected_data(piv)
            except ApduError as error:
                if error.sw != SW.SECURITY_CONDITION_NOT_SATISFIED:
                    raise
            else:
                raise AssertionError("management key readable without PIN")
            piv.verify_pin("123456")
            if get_pivman_protected_data(piv).key != key:
                raise AssertionError("PIN-authorized read returned wrong management key")
    finally:
        with closing(connect()) as conn:
            piv = PivSession(conn)
            piv.verify_pin("123456")
            piv.authenticate(key)
            pivman_set_mgm_key(piv, DEFAULT_MANAGEMENT_KEY, MANAGEMENT_KEY_TYPE.AES192, store_on_device=False)
    with closing(connect()) as conn:
        piv = PivSession(conn)
        if get_pivman_data(piv).has_stored_key:
            raise AssertionError("protected-key metadata not removed")
        piv.verify_pin("123456")
        if get_pivman_protected_data(piv).key is not None:
            raise AssertionError("old protected key not removed")
        piv.authenticate(DEFAULT_MANAGEMENT_KEY)
    print("PASS PIN-protected management key store, unauthenticated denial, PIN read, cleanup", flush=True)


class OfficialClientRegression(unittest.TestCase):
    def test_card_warm_reset_clears_verified_pin(self):
        with tempfile.TemporaryDirectory() as state, emulator(state), closing(LoopbackCard()) as conn:
            piv = PivSession(conn)
            piv.authenticate(DEFAULT_MANAGEMENT_KEY)
            piv.put_object(OBJECT_ID.PRINTED, b"private object")
            piv.verify_pin("123456")
            self.assertEqual(piv.get_object(OBJECT_ID.PRINTED), b"private object")
            for control in (1, 2, 0):
                packet(conn.card.sock, bytes([control]))
                piv = PivSession(conn)
                with self.assertRaises(ApduError) as error:
                    piv.get_object(OBJECT_ID.PRINTED)
                self.assertEqual(error.exception.sw, SW.SECURITY_CONDITION_NOT_SATISFIED)
                piv.verify_pin("123456")
                self.assertEqual(piv.get_object(OBJECT_ID.PRINTED), b"private object")

    def test_usb_reset_revokes_session_and_unwinds_each_transport(self):
        for transport in ("hid", "otp", "ccid"):
            with self.subTest(transport=transport), tempfile.TemporaryDirectory() as state, \
                 emulator(state, auto_touch=False) as log, closing(LoopbackCard()) as card:
                piv = PivSession(card)
                piv.authenticate(DEFAULT_MANAGEMENT_KEY)
                piv.put_object(OBJECT_ID.PRINTED, b"preserve reset object")
                piv.verify_pin("123456")
                self.assertEqual(piv.get_object(OBJECT_ID.PRINTED), b"preserve reset object")
                secret = os.urandom(20)
                config = YubiOtpSession(card)
                config.put_configuration(OTP_SLOT.TWO, HmacSha1SlotConfiguration(secret).require_touch(True))
                piv = PivSession(card)
                piv.authenticate(DEFAULT_MANAGEMENT_KEY)
                public = piv.generate_key(SLOT.SIGNATURE, KEY_TYPE.ECCP256, touch_policy=TOUCH_POLICY.ALWAYS)
                piv.verify_pin("123456")
                with closing(HidTcp()) as hid, closing(LoopbackOtp()) as otp, ThreadPoolExecutor(max_workers=1) as pool:
                    if transport == "hid":
                        hid.send(0x10, b"\x0b")
                        pending = None
                    elif transport == "otp":
                        pending = pool.submit(YubiOtpSession(otp).calculate_hmac_sha1, OTP_SLOT.TWO, b"bus reset")
                    else:
                        pending = pool.submit(piv.sign, SLOT.SIGNATURE, KEY_TYPE.ECCP256, b"bus reset", hashes.SHA256())
                    deadline = time.monotonic() + 4
                    while b"USER_PRESENCE: waiting" not in log.read_bytes():
                        self.assertLess(time.monotonic(), deadline)
                        time.sleep(0.01)
                    # Replacing the OTP socket models a separate host reset
                    # controller; ordinary HID/PCSC connection closes do not.
                    with closing(LoopbackOtp()) as reset:
                        packet(reset.sock, b"\x02")
                        self.assertEqual(response(reset.sock), b"")
                    if pending:
                        with self.assertRaises((EOFError, OSError, YubiKitTimeoutError)):
                            pending.result(timeout=4)
                    time.sleep(0.1)
                with closing(LoopbackCard()) as recovered, closing(HidTcp()) as hid:
                    piv = PivSession(recovered)
                    with self.assertRaises(ApduError):
                        piv.get_object(OBJECT_ID.PRINTED)
                    piv.verify_pin("123456")
                    self.assertEqual(piv.get_object(OBJECT_ID.PRINTED), b"preserve reset object")
                    self.assertEqual(piv.get_slot_metadata(SLOT.SIGNATURE).public_key.public_numbers(), public.public_numbers())
                    self.assertEqual(hid.call(1, b"after bus reset"), b"after bus reset")
                    self.assertIn(b"USER_PRESENCE: cancelled", log.read_bytes())
                    self.assertNotIn(b"USER_PRESENCE: confirmed", log.read_bytes())

    def test_piv_attestation_repeated_generation_and_certificate_recovery(self):
        with tempfile.TemporaryDirectory() as state:
            with emulator(state), closing(LoopbackCard()) as card:
                # Prime generation has variable cost, especially under ASan.
                # Raw loopback APDUs have no CCID time-extension packets.
                card.card.sock.settimeout(30)
                piv = PivSession(card)
                piv.authenticate(DEFAULT_MANAGEMENT_KEY)
                root = piv.get_certificate(SLOT.ATTESTATION)
                for kind in (KEY_TYPE.ECCP256, KEY_TYPE.ECCP384, KEY_TYPE.RSA2048, KEY_TYPE.RSA3072):
                    slot = SLOT.RETIRED18 if kind == KEY_TYPE.ECCP384 else SLOT.RETIRED20
                    public = piv.generate_key(slot, kind)
                    for _ in range(3):
                        proof = piv.attest_key(slot)
                        root.public_key().verify(proof.signature, proof.tbs_certificate_bytes,
                            ec.ECDSA(proof.signature_hash_algorithm))
                        self.assertEqual(proof.public_key().public_numbers(), public.public_numbers())
                        encoded = proof.extensions.get_extension_for_oid(
                            x509.ObjectIdentifier("1.3.6.1.4.1.41482.3.7")).value.value
                        policy = proof.extensions.get_extension_for_oid(
                            x509.ObjectIdentifier("1.3.6.1.4.1.41482.3.8")).value.value
                        self.assertEqual(len(policy), 2)
                        serial = Tlv(encoded)
                        self.assertEqual(serial.tag, 2)
                        raw_serial, sw = card.send_and_receive(bytes.fromhex("00f80000"))
                        self.assertEqual(sw, SW.OK)
                        self.assertEqual(int.from_bytes(serial.value, "big"), int.from_bytes(raw_serial, "big"))
                time.sleep(0.1)
            # Inject an absent certificate into this disposable desktop flash,
            # without changing its attestation private-key records.
            image = Path(state) / "memory.flash"
            flash = bytearray(image.read_bytes())
            changed = 0
            for head in (len(flash) - 16, len(flash) - 16 - 16384 - 12):
                pointer = struct.unpack_from("<Q", flash, head)[0]
                seen = set()
                while pointer:
                    self.assertNotIn(pointer, seen)
                    seen.add(pointer)
                    following, _, fid, size = struct.unpack_from("<QQHH", flash, pointer)
                    if fid == 0xff01:
                        self.assertNotEqual(size, 0xffff)
                        struct.pack_into("<H", flash, pointer + 18, 0)
                        changed += 1
                    pointer = following
            self.assertGreater(changed, 0)
            image.write_bytes(flash)
            with emulator(state), closing(LoopbackCard()) as card:
                piv = PivSession(card)
                recovered = piv.get_certificate(SLOT.ATTESTATION)
                self.assertEqual(root.public_key().public_numbers(), recovered.public_key().public_numbers())
                proof = piv.attest_key(SLOT.RETIRED20)
                recovered.public_key().verify(proof.signature, proof.tbs_certificate_bytes,
                    ec.ECDSA(proof.signature_hash_algorithm))

    def test_piv_reset_preserves_other_applications_across_restart(self):
        secret = os.urandom(20)
        rp = "piv-reset-isolation.example.invalid"
        with tempfile.TemporaryDirectory() as state:
            with emulator(state), closing(LoopbackCard()) as card, closing(HidTcp()) as hid:
                public = configure(card.card)
                YubiOtpSession(card).put_configuration(OTP_SLOT.TWO, HmacSha1SlotConfiguration(secret))
                OathSession(card).put_credential(CredentialData("preserved", OATH_TYPE.TOTP, HASH_ALGORITHM.SHA1, secret))
                credential = Ctap2(hid).make_credential(os.urandom(32), {"id": rp},
                    {"id": b"piv-reset"}, [{"type": "public-key", "alg": -7}],
                    options={"rk": True}).auth_data.credential_data
                piv = PivSession(card)
                piv.authenticate(DEFAULT_MANAGEMENT_KEY)
                piv.put_key(SLOT.KEY_MANAGEMENT, ec.generate_private_key(ec.SECP256R1()))
                attestation = piv.get_certificate(SLOT.ATTESTATION).public_bytes(serialization.Encoding.DER)
                piv.reset()
                piv.verify_pin("123456")
                piv.authenticate(DEFAULT_MANAGEMENT_KEY)
                self.assertTrue(piv.get_management_key_metadata().default_value)
                self.assertEqual(piv.get_certificate(SLOT.ATTESTATION).public_bytes(serialization.Encoding.DER), attestation)
                # A readable certificate alone does not prove its private key survived.
                generated = piv.generate_key(SLOT.RETIRED20, KEY_TYPE.ECCP256)
                proof = piv.attest_key(SLOT.RETIRED20)
                root = piv.get_certificate(SLOT.ATTESTATION)
                root.public_key().verify(proof.signature, proof.tbs_certificate_bytes,
                                         ec.ECDSA(proof.signature_hash_algorithm))
                self.assertEqual(proof.public_key().public_numbers(), generated.public_numbers())
                piv.delete_key(SLOT.RETIRED20)
                with self.assertRaises(ApduError):
                    piv.get_slot_metadata(SLOT.KEY_MANAGEMENT)
                exercise(card.card, public, 1)
                self.assertEqual([c.name for c in OathSession(card).list_credentials()], ["preserved"])
                self.assertEqual(YubiOtpSession(card).calculate_hmac_sha1(OTP_SLOT.TWO, b"after reset"),
                                 hmac.digest(secret, b"after reset", "sha1"))
                assertion = Ctap2(hid).get_assertion(rp, b"a" * 32,
                    [{"type": "public-key", "id": credential.credential_id}], options={"up": False})
                credential.public_key.verify(bytes(assertion.auth_data) + b"a" * 32, assertion.signature)
            with emulator(state), closing(LoopbackCard()) as card, closing(HidTcp()) as hid:
                exercise(card.card, public, 1)
                self.assertEqual([c.name for c in OathSession(card).list_credentials()], ["preserved"])
                self.assertEqual(YubiOtpSession(card).calculate_hmac_sha1(OTP_SLOT.TWO, b"after reboot"),
                                 hmac.digest(secret, b"after reboot", "sha1"))
                assertion = Ctap2(hid).get_assertion(rp, b"b" * 32,
                    [{"type": "public-key", "id": credential.credential_id}], options={"up": False})
                credential.public_key.verify(bytes(assertion.auth_data) + b"b" * 32, assertion.signature)

    def test_hid_busy_and_ccid_queue_preserve_otp_confirmation(self):
        with tempfile.TemporaryDirectory() as state, emulator(state, auto_touch=False) as log, \
             closing(LoopbackCard()) as card, closing(LoopbackOtp()) as otp, closing(HidTcp()) as hid:
            secret = os.urandom(20)
            YubiOtpSession(card).put_configuration(
                OTP_SLOT.TWO, HmacSha1SlotConfiguration(secret).require_touch(True))
            oath = OathSession(card)
            credential = oath.put_credential(CredentialData(
                "queued while OTP waits", OATH_TYPE.TOTP, HASH_ALGORITHM.SHA1, secret))
            otp_session = YubiOtpSession(otp)
            echo_payload = os.urandom(Ctap2(hid).info.max_msg_size)
            cancel = threading.Event()
            with ThreadPoolExecutor(max_workers=3) as pool:
                waiting = pool.submit(otp_session.calculate_hmac_sha1,
                                      OTP_SLOT.TWO, b"wait", event=cancel)
                try:
                    deadline = time.monotonic() + 3
                    while b"USER_PRESENCE: waiting" not in log.read_bytes():
                        self.assertLess(time.monotonic(), deadline)
                        time.sleep(0.01)
                    fido = pool.submit(hid.call, 1, echo_payload)
                    code = pool.submit(oath.calculate_code, credential, 1234567890)
                    time.sleep(0.1)
                    with self.assertRaisesRegex(RuntimeError, "CTAPHID error: 06"):
                        fido.result(timeout=1)
                    with self.assertRaisesRegex(RuntimeError, "CTAPHID error: 06"):
                        Ctap2(hid).get_info()
                    hid.send(0x11)  # No active HID command: must not cancel OTP.
                    time.sleep(0.05)
                    self.assertFalse(waiting.done(), "HID busy reply completed the active OTP request")
                    self.assertFalse(code.done(), "CCID replaced the active OTP command")
                finally:
                    cancel.set()
                with self.assertRaises(YubiKitTimeoutError):
                    waiting.result(timeout=5)
                deadline = time.monotonic() + 2
                while b"USER_PRESENCE: cancelled" not in log.read_bytes():
                    self.assertLess(time.monotonic(), deadline)
                    time.sleep(0.01)
                self.assertEqual(hid.call(1, echo_payload), echo_payload)
                self.assertTrue(Ctap2(hid).get_info().versions)
                digest = hmac.digest(secret, (1234567890 // 30).to_bytes(8, "big"), "sha1")
                offset = digest[-1] & 15
                expected = f"{(int.from_bytes(digest[offset:offset+4], 'big') & 0x7fffffff) % 1000000:06d}"
                self.assertEqual(code.result(timeout=5).value, expected)
            self.assertIn(b"USER_PRESENCE: cancelled", log.read_bytes())
            YubiOtpSession(card).put_configuration(OTP_SLOT.TWO, HmacSha1SlotConfiguration(secret))
            self.assertEqual(otp_session.calculate_hmac_sha1(OTP_SLOT.TWO, b"recovered"),
                             hmac.digest(secret, b"recovered", "sha1"))

    def test_official_otp_slot_swap_and_access_control(self):
        for connection in (LoopbackCard, LoopbackOtp):
            with self.subTest(transport=connection.__name__), tempfile.TemporaryDirectory() as state:
                secret = os.urandom(20)
                challenge = b"slot swap regression"
                expected = hmac.digest(secret, challenge, "sha1")
                with emulator(state), closing(connection()) as conn:
                    session = YubiOtpSession(conn)
                    session.put_configuration(OTP_SLOT.TWO, HmacSha1SlotConfiguration(secret))
                    for populated in (OTP_SLOT.ONE, OTP_SLOT.TWO):
                        session.swap_slots()
                        status = session.get_config_state()
                        self.assertEqual(status.is_configured(OTP_SLOT.ONE), populated == OTP_SLOT.ONE)
                        self.assertEqual(status.is_configured(OTP_SLOT.TWO), populated == OTP_SLOT.TWO)
                        self.assertEqual(session.calculate_hmac_sha1(populated, challenge), expected)
                with emulator(state), closing(connection()) as conn:
                    session = YubiOtpSession(conn)
                    self.assertEqual(session.calculate_hmac_sha1(OTP_SLOT.TWO, challenge), expected)
                    session.put_configuration(OTP_SLOT.TWO, HmacSha1SlotConfiguration(secret), acc_code=b"123456")
                    with self.assertRaises((ApduError, CommandRejectedError)):
                        session.swap_slots()
                    # Reopen after the rejected update; neither slot may move.
                with emulator(state), closing(connection()) as conn:
                    session = YubiOtpSession(conn)
                    self.assertFalse(session.get_config_state().is_configured(OTP_SLOT.ONE))
                    self.assertTrue(session.get_config_state().is_configured(OTP_SLOT.TWO))
                    self.assertEqual(session.calculate_hmac_sha1(OTP_SLOT.TWO, challenge), expected)

    def test_edwards_fixed_width_seeds_and_native_client_import(self):
        with tempfile.TemporaryDirectory() as state, emulator(state), closing(LoopbackCard()) as card:
            for cls, size, attr in ((ed25519.Ed25519PrivateKey, 32, "162b06010401da470f01"),
                                    (ed448.Ed448PrivateKey, 57, "162b6571")):
                for seed in (bytes(size), bytes(range(size - 1)) + b"\0", b"\x01" + bytes(size - 1)):
                    with self.subTest(curve=cls.__name__, seed=seed.hex()):
                        private = cls.from_private_bytes(seed)
                        session = OpenPgpSession(card)
                        session.verify_admin("12345678")
                        if size == 32:
                            # Official client must accept the advertised algorithm table.
                            session.put_key(KEY_REF.SIG, private)
                        else:
                            # Yubico's client does not support Ed448; test the card protocol.
                            apdu(card.card, "00da00c1", bytes.fromhex(attr), False)
                            template = b"\xb6\0" + bytes(Tlv(0x7f48, bytes([0x92, size]))) + bytes(Tlv(0x5f48, seed))
                            apdu(card.card, "00db3fff", bytes(Tlv(0x4d, template)), False)
                        public = Tlv.parse_dict(Tlv.unpack(0x7f49, apdu(card.card, "00478100", b"\xb6\0")))[0x86]
                        self.assertEqual(public, private.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw))
                        apdu(card.card, "00200081", b"123456", False)
                        message = b"fixed synthetic seed regression"
                        private.public_key().verify(apdu(card.card, "002a9e9a", message), message)

    def test_openpgp_p384_three_slots_and_advertised_ecdh(self):
        keys = {ref: ec.generate_private_key(ec.SECP384R1()) for ref in (KEY_REF.SIG, KEY_REF.DEC, KEY_REF.AUT)}
        with tempfile.TemporaryDirectory() as state:
            for boot in range(2):
                with emulator(state), closing(LoopbackCard()) as card:
                    session = OpenPgpSession(card)
                    table = session.get_algorithm_information()
                    signing = {a.oid for a in table[KEY_REF.SIG] if a.algorithm_id == 19}
                    agreement = {a.oid for a in table[KEY_REF.DEC] if a.algorithm_id == 18}
                    authentication = {a.oid for a in table[KEY_REF.AUT] if a.algorithm_id == 19}
                    self.assertTrue(signing)
                    self.assertTrue(signing <= agreement)
                    self.assertEqual(signing, authentication)
                    self.assertFalse(any(a.algorithm_id == 19 for a in table[KEY_REF.DEC]))
                    if boot == 0:
                        session.verify_admin("12345678")
                        for ref, private in keys.items():
                            session.put_key(ref, private)
                            session.set_uif(ref, UIF.ON)
                        session.set_signature_pin_policy(PGP_PIN_POLICY.ONCE)
                    self.assertEqual(session.get_pin_status().pin_policy_user, PGP_PIN_POLICY.ONCE)
                    for ref, private in keys.items():
                        self.assertEqual(session.get_uif(ref), UIF.ON)
                        self.assertEqual(session.get_public_key(ref).public_numbers(), private.public_key().public_numbers())
                    session.verify_pin("123456")
                    session.verify_pin("123456", extended=True)
                    message = os.urandom(64)
                    keys[KEY_REF.SIG].public_key().verify(session.sign(message, hashes.SHA384()), message, ec.ECDSA(hashes.SHA384()))
                    keys[KEY_REF.AUT].public_key().verify(session.authenticate(message, hashes.SHA384()), message, ec.ECDSA(hashes.SHA384()))
                    peer = ec.generate_private_key(ec.SECP384R1())
                    self.assertEqual(session.decrypt(peer.public_key()), peer.exchange(ec.ECDH(), keys[KEY_REF.DEC].public_key()))

    def test_openpgp_and_piv_required_touch_reject_without_button(self):
        keys = {ref: ec.generate_private_key(ec.SECP384R1()) for ref in (KEY_REF.SIG, KEY_REF.DEC, KEY_REF.AUT)}
        private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        management = os.urandom(24)
        with tempfile.TemporaryDirectory() as state:
            with emulator(state), closing(LoopbackCard()) as card:
                pgp = OpenPgpSession(card)
                pgp.verify_admin("12345678")
                for ref, key in keys.items():
                    pgp.put_key(ref, key)
                    pgp.set_uif(ref, UIF.ON)
                piv = PivSession(card)
                piv.authenticate(DEFAULT_MANAGEMENT_KEY)
                piv.put_key(SLOT.AUTHENTICATION, private, PIV_PIN_POLICY.ONCE, TOUCH_POLICY.ALWAYS)
                piv.set_management_key(MANAGEMENT_KEY_TYPE.AES192, management, require_touch=True)
            for operation in ("pgp_sign", "pgp_decrypt", "pgp_auth", "piv_sign", "piv_decrypt", "piv_management"):
                with self.subTest(operation=operation), emulator(state, auto_touch=False) as log, \
                     closing(LoopbackCard()) as card, closing(HidTcp()) as hid:
                    # Observe the firmware's 15-second denial, not the loopback
                    # transport's shorter default receive timeout.
                    card.card.sock.settimeout(20)
                    message = b"a physical confirmation is required"
                    if operation.startswith("pgp"):
                        pgp = OpenPgpSession(card)
                        pgp.verify_pin("123456")
                        pgp.verify_pin("123456", extended=True)
                        call = {
                            "pgp_sign": lambda: pgp.sign(message, hashes.SHA384()),
                            "pgp_auth": lambda: pgp.authenticate(message, hashes.SHA384()),
                            "pgp_decrypt": lambda: pgp.decrypt(ec.generate_private_key(ec.SECP384R1()).public_key()),
                        }[operation]
                    else:
                        piv = PivSession(card)
                        piv.verify_pin("123456")
                        call = {
                            "piv_sign": lambda: piv.sign(SLOT.AUTHENTICATION, KEY_TYPE.RSA2048, message, hashes.SHA256(), padding.PKCS1v15()),
                            "piv_decrypt": lambda: piv.decrypt(SLOT.AUTHENTICATION, private.public_key().encrypt(message, padding.PKCS1v15()), padding.PKCS1v15()),
                            "piv_management": lambda: piv.authenticate(management),
                        }[operation]
                    with ThreadPoolExecutor(max_workers=1) as pool:
                        pending = pool.submit(call)
                        deadline = time.monotonic() + 3
                        while b"USER_PRESENCE: waiting" not in log.read_bytes():
                            self.assertFalse(pending.done(), "Touch-required operation completed without user presence")
                            self.assertLess(time.monotonic(), deadline)
                            time.sleep(0.01)
                        time.sleep(0.1)
                        self.assertFalse(pending.done())
                        with self.assertRaises(ApduError) as rejected:
                            pending.result(timeout=18)
                        self.assertEqual(rejected.exception.sw, 0x6600 if operation.startswith("pgp") else 0x6982)
                    self.assertIn(b"USER_PRESENCE: timed out", log.read_bytes())
                    self.assertNotIn(b"USER_PRESENCE: confirmed", log.read_bytes())
                    self.assertEqual(hid.call(1, b"after touch timeout"), b"after touch timeout")

    def test_otp_cancel_releases_worker_and_next_request(self):
        with tempfile.TemporaryDirectory() as state, emulator(state, auto_touch=False) as log, closing(LoopbackCard()) as card:
            secret = os.urandom(20)
            YubiOtpSession(card).put_configuration(OTP_SLOT.TWO, HmacSha1SlotConfiguration(secret).require_touch(True))
            with closing(LoopbackOtp()) as conn:
                session = YubiOtpSession(conn)
                cancel = threading.Event()
                timer = threading.Timer(1, cancel.set)
                timer.start()
                try:
                    with self.assertRaises(YubiKitTimeoutError):
                        session.calculate_hmac_sha1(OTP_SLOT.TWO, b"cancel", event=cancel)
                finally:
                    timer.cancel()
                deadline = time.monotonic() + 2
                while b"USER_PRESENCE: cancelled" not in log.read_bytes():
                    self.assertLess(time.monotonic(), deadline)
                    time.sleep(0.01)
                YubiOtpSession(card).put_configuration(OTP_SLOT.TWO, HmacSha1SlotConfiguration(secret))
                self.assertEqual(session.calculate_hmac_sha1(OTP_SLOT.TWO, b"after-cancel"), hmac.digest(secret, b"after-cancel", "sha1"))

    def test_otp_natural_touch_timeout_and_recovery(self):
        with tempfile.TemporaryDirectory() as state, emulator(state, auto_touch=False) as log, \
             closing(LoopbackCard()) as card, closing(LoopbackOtp()) as conn:
            secret = os.urandom(20)
            config = YubiOtpSession(card)
            config.put_configuration(OTP_SLOT.TWO, HmacSha1SlotConfiguration(secret).require_touch(True))
            session = YubiOtpSession(conn)
            started = time.monotonic()
            with self.assertRaises(YubiKitTimeoutError):
                session.calculate_hmac_sha1(OTP_SLOT.TWO, b"natural timeout")
            self.assertGreaterEqual(time.monotonic() - started, 14)
            self.assertIn(b"USER_PRESENCE: timed out", log.read_bytes())
            self.assertNotIn(b"USER_PRESENCE: confirmed", log.read_bytes())
            config.put_configuration(OTP_SLOT.TWO, HmacSha1SlotConfiguration(secret).require_touch(False))
            self.assertEqual(session.calculate_hmac_sha1(OTP_SLOT.TWO, b"after timeout"),
                             hmac.digest(secret, b"after timeout", "sha1"))

    def test_native_otp_reports_concurrent_with_fido_and_ccid(self):
        with tempfile.TemporaryDirectory() as state, emulator(state) as log, closing(LoopbackCard()) as card:
            secret = os.urandom(20)
            YubiOtpSession(card).put_configuration(OTP_SLOT.TWO, HmacSha1SlotConfiguration(secret))
            with closing(LoopbackOtp()) as otp, closing(HidTcp()) as hid:
                session = YubiOtpSession(otp)
                oath = OathSession(card)
                credential = oath.put_credential(CredentialData("concurrent", OATH_TYPE.TOTP, HASH_ALGORITHM.SHA1, secret))
                def otp_work():
                    for _ in range(50):
                        challenge = os.urandom(32)
                        self.assertEqual(session.calculate_hmac_sha1(OTP_SLOT.TWO, challenge), hmac.digest(secret, challenge, "sha1"))
                def fido_work():
                    for _ in range(50):
                        self.assertTrue(Ctap2(hid).get_info().versions)
                        data = os.urandom(1024)
                        self.assertEqual(hid.call(1, data), data)
                def card_work():
                    for i in range(50):
                        timestamp = 1234567890 + 30 * i
                        digest = hmac.digest(secret, (timestamp // 30).to_bytes(8, "big"), "sha1")
                        offset = digest[-1] & 15
                        expected = f"{(int.from_bytes(digest[offset:offset+4], 'big') & 0x7fffffff) % 1000000:06d}"
                        self.assertEqual(oath.calculate_code(credential, timestamp).value, expected)
                with ThreadPoolExecutor(max_workers=3) as pool:
                    jobs = [pool.submit(f) for f in (otp_work, fido_work, card_work)]
                    for job in jobs:
                        job.result(timeout=30)
                YubiOtpSession(card).put_configuration(OTP_SLOT.TWO, HmacSha1SlotConfiguration(secret).require_touch(True))
                self.assertEqual(session.calculate_hmac_sha1(OTP_SLOT.TWO, b"touch"), hmac.digest(secret, b"touch", "sha1"))
                self.assertIn(b"USER_PRESENCE: confirmed", log.read_bytes())
                self.assertEqual(hid.call(1, b"after-otp-touch"), b"after-otp-touch")

    def test_ccid_authorized_sessions_survive_fido_and_u2f(self):
        with tempfile.TemporaryDirectory() as state, emulator(state), closing(LoopbackCard()) as card:
            def interleave():
                # INIT and alternating CBOR/MSG exercise both worker types.
                with closing(HidTcp()) as hid:
                    for _ in range(3):
                        self.assertTrue(Ctap2(hid).get_info().versions)
                        self.assertEqual(hid.call(3, bytes.fromhex("0003000000")), b"U2F_V2\x90\x00")

            oath = OathSession(card)
            oath.put_credential(CredentialData("session-test", OATH_TYPE.TOTP, HASH_ALGORITHM.SHA1, bytes(range(20))))
            oath.set_key(oath.derive_key("isolated session password"))
            oath = OathSession(card)
            self.assertTrue(oath.locked)
            oath.validate(oath.derive_key("isolated session password"))
            interleave()
            self.assertEqual(len(oath.list_credentials()), 1)
            oath.unset_key()

            piv = PivSession(card)
            piv.authenticate(DEFAULT_MANAGEMENT_KEY)
            piv.put_object(OBJECT_ID.PRINTED, b"private session fixture")
            piv.verify_pin("123456")
            interleave()
            self.assertEqual(piv.get_object(OBJECT_ID.PRINTED), b"private session fixture")
            # A real CCID application change must still clear authorization.
            OathSession(card)
            piv = PivSession(card)
            with self.assertRaises(ApduError) as denied:
                piv.get_object(OBJECT_ID.PRINTED)
            self.assertEqual(denied.exception.sw, SW.SECURITY_CONDITION_NOT_SATISFIED)

            pgp = OpenPgpSession(card)
            pgp.verify_admin("12345678")
            interleave()
            pgp.put_data(DO.NAME, b"session preserved")
            self.assertEqual(pgp.get_data(DO.NAME), b"session preserved")

    def test_smartcard_transport_handover_clears_authentication(self):
        with tempfile.TemporaryDirectory() as state, emulator(state), closing(LoopbackCard()) as card:
            OathSession(card).put_credential(CredentialData("owner-session", OATH_TYPE.TOTP, HASH_ALGORITHM.SHA1, bytes(range(20))))
            piv = PivSession(card)
            piv.authenticate(DEFAULT_MANAGEMENT_KEY)
            piv.put_object(OBJECT_ID.PRINTED, b"private-owner-fixture")
            piv.verify_pin("123456")
            self.assertEqual(piv.get_object(OBJECT_ID.PRINTED), b"private-owner-fixture")
            with closing(HidTcp()) as hid:
                response = hid.call(0x70, bytes.fromhex("00a1000000"))
                # The legacy CTAPHID OTP command prefixes its status word.
                self.assertEqual(response[:2], b"\x90\x00")
                self.assertIn(b"owner-session", response[2:])
                # A different APDU interface must not inherit the first one's PIN.
                with self.assertRaises(ApduError):
                    piv.get_object(OBJECT_ID.PRINTED)
                piv = PivSession(card)
                with self.assertRaises(ApduError) as denied:
                    piv.get_object(OBJECT_ID.PRINTED)
                self.assertEqual(denied.exception.sw, SW.SECURITY_CONDITION_NOT_SATISFIED)
                with self.assertRaises(ApduError):
                    piv.put_object(OBJECT_ID.PRINTED, b"unauthorized overwrite")
                piv.verify_pin("123456")
                self.assertEqual(piv.get_object(OBJECT_ID.PRINTED), b"private-owner-fixture")

    def test_pending_apdu_blocks_foreign_context_handover(self):
        with tempfile.TemporaryDirectory() as state, emulator(state), closing(LoopbackCard()) as card:
            oath = OathSession(card)
            data = bytes(Tlv(0x71, b"owner chain")) + bytes(Tlv(0x73, b"\x21\x06" + bytes(range(20))))
            split = 8
            self.assertEqual(card.card.exchange(bytes.fromhex("10010000") + bytes([split]) + data[:split]), b"\x90\x00")
            with closing(HidTcp()) as hid:
                with self.assertRaisesRegex(RuntimeError, "CTAPHID error: 06"):
                    hid.call(0x70, bytes.fromhex("00a1000000"))
                self.assertEqual(card.card.exchange(bytes.fromhex("00010000") + bytes([len(data)-split]) + data[split:]), b"\x90\x00")
                self.assertEqual([c.name for c in oath.list_credentials()], ["owner chain"])

    def test_ccid_get_response_survives_intervening_fido(self):
        with tempfile.TemporaryDirectory() as state, emulator(state), closing(LoopbackCard()) as card:
            piv = PivSession(card)
            piv.authenticate(DEFAULT_MANAGEMENT_KEY)
            payload = bytes(range(256)) * 2
            piv.put_object(0x5FFF11, payload)
            packet(card.card.sock, bytes.fromhex("00cb3fff055c035fff1140"))
            first = response(card.card.sock)
            self.assertEqual(first[-2], 0x61)
            with closing(HidTcp()) as hid:
                Ctap2(hid).get_info()
            rest = card.card.exchange(bytes.fromhex("00c0000000"))
            self.assertEqual(rest[-2:], b"\x90\x00")
            self.assertEqual(Tlv.unpack(0x53, first[:-2] + rest[:-2]), payload)

    def test_ccid_command_chain_survives_intervening_fido(self):
        with tempfile.TemporaryDirectory() as state, emulator(state), closing(LoopbackCard()) as card:
            oath = OathSession(card)
            name, key = b"chained session", bytes(range(20))
            data = bytes(Tlv(0x71, name)) + bytes(Tlv(0x73, b"\x21\x06" + key))
            split = 13
            self.assertEqual(card.card.exchange(bytes.fromhex("10010000") + bytes([split]) + data[:split]), b"\x90\x00")
            with closing(HidTcp()) as hid:
                Ctap2(hid).get_info()
                self.assertEqual(hid.call(3, bytes.fromhex("0003000000")), b"U2F_V2\x90\x00")
            self.assertEqual(card.card.exchange(bytes.fromhex("00010000") + bytes([len(data) - split]) + data[split:]), b"\x90\x00")
            self.assertEqual([c.name for c in oath.list_credentials()], [name.decode()])

    def test_four_piv_private_objects_require_pin(self):
        objects = (0x5FC103, 0x5FC108, 0x5FC109, 0x5FC121)
        with tempfile.TemporaryDirectory() as state, emulator(state):
            with closing(LoopbackCard()) as card:
                piv = PivSession(card)
                piv.authenticate(DEFAULT_MANAGEMENT_KEY)
                for obj in objects:
                    piv.put_object(obj, b"isolated private object")
            for obj in objects:
                with closing(LoopbackCard()) as card:
                    piv = PivSession(card)
                    with self.assertRaises(ApduError) as denied:
                        piv.get_object(obj)
                    self.assertEqual(denied.exception.sw, SW.SECURITY_CONDITION_NOT_SATISFIED)
                    piv.verify_pin("123456")
                    self.assertEqual(piv.get_object(obj), b"isolated private object")

    def test_piv_pin_protected_management_key(self):
        with tempfile.TemporaryDirectory() as state, emulator(state):
            exercise_protected_management_key(LoopbackCard)

    def test_import_rejects_ambiguous_device_selection(self):
        import test_emulation
        sys.path.insert(0, str(Path(test_emulation.__file__).resolve().parents[1] / "tools"))
        import import_piv_pkcs12 as helper
        readers = [SimpleNamespace(name="Pico Key A"), SimpleNamespace(name="Pico Key B")]
        with patch.object(helper, "list_readers", return_value=readers):
            for selection in (None, "Pico Key"):
                with self.assertRaises(RuntimeError):
                    helper.choose_reader(selection)
            self.assertIs(helper.choose_reader("Pico Key B"), readers[1])

    def test_pkcs12_script_import_and_private_key_operations(self):
        import test_emulation
        sys.path.insert(0, str(Path(test_emulation.__file__).resolve().parents[1] / "tools"))
        import import_piv_pkcs12 as helper

        class ScriptCard(LoopbackCard):
            connection = SimpleNamespace(getATR=lambda: [])

        reader = SimpleNamespace(name="isolated loopback", createConnection=lambda: None)
        with tempfile.TemporaryDirectory() as state, emulator(state):
            preserved_mapping = None
            roots = b"\x82\x07fixture"
            for private in (rsa.generate_private_key(65537, 2048), ec.generate_private_key(ec.SECP256R1())):
                with self.subTest(algorithm=type(private).__name__):
                    name = x509.Name([x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, "T-Dongle isolated import")])
                    now = datetime.now(timezone.utc)
                    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
                            .public_key(private.public_key()).serial_number(x509.random_serial_number())
                            .not_valid_before(now - timedelta(minutes=1)).not_valid_after(now + timedelta(days=1))
                            .sign(private, hashes.SHA256()))
                    pfx = Path(state) / "fixture.p12"
                    pfx.write_bytes(serialization.pkcs12.serialize_key_and_certificates(
                        b"isolated", private, cert, None, serialization.NoEncryption()))
                    if preserved_mapping is None:
                        _, payload = helper.build_mscmap_object(SLOT.SIGNATURE, cert)
                        preserved_mapping = Tlv.parse_dict(payload)[0x53]
                        with closing(LoopbackCard()) as conn:
                            piv = PivSession(conn)
                            piv.authenticate(DEFAULT_MANAGEMENT_KEY)
                            piv.put_object(0x5FFF10, preserved_mapping)
                            piv.put_object(0x5FFF11, roots)
                            expected_serial = piv.get_serial()
                    # A unique reader name is insufficient when devices are exchanged.
                    with patch.object(helper, "list_readers", return_value=[reader]), \
                         patch.object(helper, "ScardSmartCardConnection", side_effect=lambda _: ScriptCard()), \
                         patch.object(sys, "argv", ["import_piv_pkcs12.py", "--input", str(pfx), "--serial", str(expected_serial + 1)]), \
                         patch.object(helper.PivSession, "authenticate") as auth, \
                         patch.object(helper, "import_direct") as write, redirect_stdout(io.StringIO()):
                        self.assertEqual(helper.main(), 1)
                        auth.assert_not_called()
                        write.assert_not_called()
                    report = io.StringIO()
                    with patch.object(helper, "list_readers", return_value=[reader]), \
                         patch.object(helper, "ScardSmartCardConnection", side_effect=lambda _: ScriptCard()), \
                         patch.object(sys, "argv", ["import_piv_pkcs12.py", "--input", str(pfx), "--slot", "9d", "--verify", "--serial", str(expected_serial)]), \
                         redirect_stdout(report):
                        result = helper.main()
                    self.assertEqual(result, 0, report.getvalue())
                    with closing(LoopbackCard()) as conn:
                        piv = PivSession(conn)
                        mapping = Tlv.parse_list(piv.get_object(0x5FFF10))
                        self.assertEqual(len(mapping), 1, "upstream format uses a single TLV around the packed array")
                        self.assertEqual(len(mapping[0].value), 214)
                        self.assertEqual(mapping[0].value[:107], Tlv.unpack(0x81, preserved_mapping))
                        self.assertEqual(mapping[0].value[107 + 80], int(SLOT.KEY_MANAGEMENT))
                        self.assertEqual(piv.get_object(0x5FFF11), roots)
                        self.assertEqual(piv.get_certificate(SLOT.KEY_MANAGEMENT).public_bytes(serialization.Encoding.DER), cert.public_bytes(serialization.Encoding.DER))
                        piv.verify_pin("123456")
                        if isinstance(private, rsa.RSAPrivateKey):
                            message = os.urandom(32)
                            encrypted = private.public_key().encrypt(message, padding.PKCS1v15())
                            self.assertEqual(piv.decrypt(SLOT.KEY_MANAGEMENT, encrypted, padding.PKCS1v15()), message)
                        else:
                            peer = ec.generate_private_key(ec.SECP256R1())
                            self.assertEqual(piv.calculate_secret(SLOT.KEY_MANAGEMENT, peer.public_key()), peer.exchange(ec.ECDH(), private.public_key()))

    def test_client_settings_round_trip(self):
        with tempfile.TemporaryDirectory() as state:
            with emulator(state):
                exercise_client_settings(LoopbackCard)
                exercise_protected_management_key(LoopbackCard)
            with emulator(state), closing(LoopbackCard()) as card:
                piv = PivSession(card)
                self.assertTrue(piv.get_management_key_metadata().default_value)
                piv.authenticate(DEFAULT_MANAGEMENT_KEY)
                with self.assertRaises(InvalidPinError):
                    piv.verify_pin("654321")
                piv.verify_pin("123456")
                self.assertFalse(get_pivman_data(piv).has_protected_key)
                self.assertIsNone(get_pivman_protected_data(piv).key)
                pgp = OpenPgpSession(card)
                pgp.verify_pin("123456")
                pgp.verify_admin("12345678")
                self.assertFalse(OathSession(card).locked)

    def test_application_sessions_parse_actual_firmware_responses(self):
        with tempfile.TemporaryDirectory() as state, emulator(state):
            for session_type, expected in ((OathSession, (8, 2, 0)),
                                           (PivSession, (5, 7, 0)),
                                           (OpenPgpSession, (8, 2, 0)),
                                           (YubiOtpSession, (8, 2, 0))):
                with self.subTest(application=session_type.__name__), closing(LoopbackCard()) as conn:
                    self.assertEqual(tuple(session_type(conn).version), expected)

    def test_openpgp_cli_information_with_empty_and_generated_slots(self):
        with tempfile.TemporaryDirectory() as state:
            with emulator(state):
                with closing(LoopbackCard()) as conn:
                    session = OpenPgpSession(conn)
                    self.assertEqual(session.get_key_information(), {
                        ref: KEY_STATUS.NONE for ref in (KEY_REF.SIG, KEY_REF.DEC, KEY_REF.AUT)})
                    self.assertNotIn("Signature key", get_openpgp_info(session))
                with closing(CardTcp()) as card:
                    public = configure(card)
                    exercise(card, public, 1)
            with emulator(state), closing(LoopbackCard()) as conn:
                session = OpenPgpSession(conn)
                self.assertEqual(session.get_key_information(), {
                    ref: KEY_STATUS.GENERATED for ref in (KEY_REF.SIG, KEY_REF.DEC, KEY_REF.AUT)})
                info = get_openpgp_info(session)
                for key in ("Signature key", "Decryption key", "Authentication key"):
                    self.assertIn(key, info)


if __name__ in ("__main__", "builtins"):
    result = unittest.TextTestRunner(verbosity=2).run(
        unittest.defaultTestLoader.loadTestsFromTestCase(OfficialClientRegression))
    if not result.wasSuccessful():
        raise SystemExit(1)
