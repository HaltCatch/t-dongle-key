"""Protocol evidence for the YubiKey 5 comparison. Uses disposable simulator flash."""
import datetime
import hashlib
import hmac
import os
import tempfile
import time
import unittest
from contextlib import closing

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, utils
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from fido2 import cbor
from fido2.ctap import CtapError
from fido2.ctap1 import Ctap1
from fido2.ctap2 import AssertionResponse, AttestationResponse, ClientPin, CredentialManagement, Ctap2
from fido2.ctap2.blob import LargeBlobs
from fido2.ctap2.config import Config

from test_emulation import CardTcp, HidTcp, emulator, packet, response
from test_openpgp_isolation import apdu


PIN = "763218"
RP = {"id": "comparison.example.invalid", "name": "Comparison"}
USER = {"id": b"comparison-user", "name": "comparison"}
HASH = hashlib.sha256(b"isolated comparison fixture").digest()


def register(ctap, algorithm=-7, extensions=None, resident=False, authorization=None):
    extra = {}
    if authorization:
        protocol, token = authorization
        extra = {"pin_uv_param": protocol.authenticate(token, HASH),
                 "pin_uv_protocol": protocol.VERSION}
    return ctap.make_credential(
        HASH, RP, USER, [{"type": "public-key", "alg": algorithm}],
        extensions=extensions, options={"rk": resident}, **extra,
    )


def allow(attestation):
    return [{"type": "public-key", "id": attestation.auth_data.credential_data.credential_id}]


def oath_put(card, name, key, mode, digits=6, increasing=False):
    payload = bytes([0x71, len(name)]) + name
    payload += bytes([0x73, len(key) + 2, mode, digits]) + key
    if increasing:
        payload += b"\x78\x01\x01"
    apdu(card, "00010000", payload, le=False)


def oath_calculate(card, name, counter):
    data = bytes([0x71, len(name)]) + name + b"\x74\x08" + counter.to_bytes(8, "big")
    answer = apdu(card, "00a20001", data)
    assert answer[:3] == b"\x76\x05\x06", answer.hex()
    return int.from_bytes(answer[3:], "big")


def tlv_value(data, tag):
    if data[0] != tag:
        raise AssertionError((data[0], tag))
    size = data[1]
    offset = 2
    if size & 0x80:
        width = size & 0x7F
        size = int.from_bytes(data[offset:offset + width], "big")
        offset += width
    if len(data) < offset + size:
        raise AssertionError("truncated TLV")
    return data[offset:offset + size]


def piv_login(card):
    card.select("a000000308000010000100")
    key = bytes(range(1, 9)) * 3  # Default only on disposable blank simulator flash.
    cipher = Cipher(algorithms.AES(key), modes.ECB())
    encrypted = apdu(card, "00870a9b", b"\x7c\x02\x80\x00")
    assert encrypted[:4] == b"\x7c\x12\x80\x10"
    witness = cipher.decryptor().update(encrypted[4:])
    challenge = b"comparison-piv!!"
    reply = apdu(card, "00870a9b", b"\x7c\x24\x80\x10" + witness + b"\x81\x10" + challenge)
    assert reply == b"\x7c\x12\x82\x10" + cipher.encryptor().update(challenge)


def piv_certificate(public):
    issuer = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, "Simulator fixture")])
    certificate = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
                   .public_key(public).serial_number(x509.random_serial_number())
                   .not_valid_before(datetime.datetime(2026, 1, 1))
                   .not_valid_after(datetime.datetime(2030, 1, 1)).sign(issuer, hashes.SHA256()))
    from cryptography.hazmat.primitives.serialization import Encoding
    der = certificate.public_bytes(Encoding.DER)
    inner = b"\x70\x82" + len(der).to_bytes(2, "big") + der + b"\x71\x01\x00\xfe\x00"
    return b"\x53\x82" + len(inner).to_bytes(2, "big") + inner


def piv_public(reply):
    assert reply[:2] == b"\x7f\x49" and reply[2] < 128
    return ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), tlv_value(reply[3:], 0x86))


class CompatibilityEvidence(unittest.TestCase):
    def test_openpgp_constructed_data_objects_for_clients(self):
        with tempfile.TemporaryDirectory() as state, emulator(state), closing(CardTcp()) as card:
            card.select("d27600012401")
            data = apdu(card, "00ca006e")
            inner = tlv_value(data, 0x6e)
            self.assertEqual(len(tlv_value(inner, 0x4f)), 16)
            self.assertTrue(tlv_value(apdu(card, "00ca0065"), 0x65))
            self.assertEqual(tlv_value(apdu(card, "00ca007a"), 0x7a)[:2], b"\x93\x03")
            self.assertEqual(len(apdu(card, "00ca004f")), 16)
            self.assertEqual(len(apdu(card, "00ca00c4")), 7)

    def test_piv_application_template_for_gnupg(self):
        with tempfile.TemporaryDirectory() as state, emulator(state), closing(CardTcp()) as card:
            data = apdu(card, "00a40400", bytes.fromhex("a000000308000010000100"))
            apt = tlv_value(data, 0x61)
            self.assertEqual(tlv_value(apt, 0x4f), bytes.fromhex("000010000100"))
            self.assertEqual(tlv_value(tlv_value(apt[8:], 0x79), 0x4f), bytes.fromhex("a000000308"))

    def test_fido_signature_and_u2f(self):
        with tempfile.TemporaryDirectory() as state, emulator(state), closing(HidTcp()) as hid:
            ctap = Ctap2(hid)
            for algorithm in (-7, -8, -35, -36):
                with self.subTest(algorithm=algorithm):
                    att = register(ctap, algorithm)
                    assertion = ctap.get_assertion(RP["id"], HASH, allow(att))
                    assertion.verify(HASH, att.auth_data.credential_data.public_key)
            u2f = Ctap1(hid)
            self.assertEqual(u2f.get_version(), "U2F_V2")
            app_id = hashlib.sha256(b"https://comparison.example.invalid").digest()
            credential = u2f.register(HASH, app_id)
            credential.verify(app_id, HASH)
            u2f.authenticate(HASH, app_id, credential.key_handle).verify(
                app_id, HASH, credential.public_key
            )

    def test_fido_ccid_presence_after_registration(self):
        with tempfile.TemporaryDirectory() as state, emulator(state) as log, closing(CardTcp()) as card:
            card.select("a0000006472f0001")

            def ctap_command(command, params=None):
                payload = bytes([command])
                if params is not None:
                    payload += cbor.encode(params)
                reply = apdu(card, "80100000", payload)
                self.assertEqual(reply[0], 0)
                return cbor.decode(reply[1:])

            self.assertIn("FIDO_2_3", ctap_command(4)[1])
            att = AttestationResponse.from_dict(ctap_command(1, {
                1: HASH, 2: RP, 3: USER, 4: [{"type": "public-key", "alg": -7}],
            }))
            assertion = AssertionResponse.from_dict(ctap_command(2, {
                1: RP["id"], 2: HASH, 3: allow(att), 5: {"up": False},
            }))
            self.assertFalse(assertion.auth_data.is_user_present())
            assertion.verify(HASH, att.auth_data.credential_data.public_key)

            assertion = AssertionResponse.from_dict(ctap_command(2, {1: RP["id"], 2: HASH, 3: allow(att)}))
            self.assertTrue(assertion.auth_data.is_user_present())
            assertion.verify(HASH, att.auth_data.credential_data.public_key)
            self.assertEqual(apdu(card, "80100000", b"\x0b"), b"\x00")
            self.assertIn(b"USER_PRESENCE: confirmed", log.read_bytes())

    def test_fido_ccid_disconnect_releases_waiting_request(self):
        with tempfile.TemporaryDirectory() as state, emulator(state, auto_touch=False) as log:
            with closing(HidTcp()) as hid:
                with closing(CardTcp()) as card:
                    card.select("a0000006472f0001")
                    packet(card.sock, bytes.fromhex("80100000010b00"))
                    deadline = time.monotonic() + 3
                    while b"USER_PRESENCE: waiting" not in log.read_bytes():
                        self.assertLess(time.monotonic(), deadline)
                        time.sleep(0.02)
                deadline = time.monotonic() + 2
                while b"USER_PRESENCE: cancelled" not in log.read_bytes():
                    self.assertLess(time.monotonic(), deadline)
                    time.sleep(0.01)
                self.assertEqual(hid.call(1, b"after-ccid-disconnect"), b"after-ccid-disconnect")
                self.assertIn(b"USER_PRESENCE: cancelled", log.read_bytes())
            with closing(CardTcp()) as card:
                card.select("a0000006472f0001")
                self.assertEqual(apdu(card, "80100000", b"\x04")[0], 0)

    def test_fido_prf_payment_and_cred_blob(self):
        with tempfile.TemporaryDirectory() as state, emulator(state), closing(HidTcp()) as hid:
            ctap = Ctap2(hid)
            pin = ClientPin(ctap)
            protocol = pin.protocol
            key, shared = pin._get_shared_secret()
            salts = hashlib.sha512(b"two independent fixture salts").digest()
            encrypted = protocol.encrypt(shared, salts)
            hmac_input = {1: key, 2: encrypted, 3: protocol.authenticate(shared, encrypted),
                          4: protocol.VERSION}
            blob = b"test credential metadata"
            att = register(ctap, extensions={"hmac-secret": True, "hmac-secret-mc": hmac_input,
                                             "thirdPartyPayment": True, "credBlob": blob},
                           resident=True)
            output = att.auth_data.extensions
            self.assertTrue(output["hmac-secret"])
            self.assertTrue(output["thirdPartyPayment"])
            self.assertTrue(output["credBlob"])
            prf = protocol.decrypt(shared, output["hmac-secret-mc"])
            self.assertEqual(len(prf), 64)
            self.assertNotEqual(prf[:32], prf[32:])
            assertion = ctap.get_assertion(
                RP["id"], HASH, allow(att),
                extensions={"hmac-secret": hmac_input, "thirdPartyPayment": True, "credBlob": True}
            )
            assertion.verify(HASH, att.auth_data.credential_data.public_key)
            result = assertion.auth_data.extensions
            self.assertEqual(protocol.decrypt(shared, result["hmac-secret"]), prf)
            self.assertTrue(result["thirdPartyPayment"])
            self.assertEqual(result["credBlob"], blob)

    def test_fido_pin_always_uv_and_large_blob(self):
        with tempfile.TemporaryDirectory() as state, emulator(state), closing(HidTcp()) as hid:
            ctap = Ctap2(hid)
            self.assertEqual(ctap.info.max_large_blob, 4096)
            client = ClientPin(ctap)
            client.set_pin(PIN)
            token = client.get_pin_token(PIN, ClientPin.PERMISSION.MAKE_CREDENTIAL, RP["id"])
            att = register(ctap, extensions={"largeBlobKey": True}, resident=True,
                           authorization=(client.protocol, token))
            self.assertEqual(len(att.large_blob_key), 32)
            token = client.get_pin_token(PIN, ClientPin.PERMISSION.LARGE_BLOB_WRITE)
            storage = LargeBlobs(ctap, client.protocol, token)
            payload = os.urandom(3300)
            storage.put_blob(att.large_blob_key, payload)
            self.assertEqual(storage.get_blob(att.large_blob_key), payload)
            with self.assertRaises(CtapError) as failure:
                storage.put_blob(att.large_blob_key, os.urandom(4300))
            self.assertEqual(failure.exception.code, CtapError.ERR.LARGE_BLOB_STORAGE_FULL)
            self.assertEqual(storage.get_blob(att.large_blob_key), payload)
            token = client.get_pin_token(PIN, ClientPin.PERMISSION.AUTHENTICATOR_CFG)
            Config(ctap, client.protocol, token).toggle_always_uv()
            info = ctap.get_info()
            self.assertTrue(info.options["alwaysUv"])
            self.assertNotIn("U2F_V2", info.versions)
            token = client.get_pin_token(PIN, ClientPin.PERMISSION.AUTHENTICATOR_CFG)
            Config(ctap, client.protocol, token).set_min_pin_length(7)
            self.assertEqual(ctap.get_info().min_pin_length, 7)
            self.assertTrue(ctap.get_info().force_pin_change)

    def test_large_blob_capacity_persists_across_restart(self):
        payload = os.urandom(3300)
        with tempfile.TemporaryDirectory() as state:
            with emulator(state), closing(HidTcp()) as hid:
                ctap = Ctap2(hid)
                client = ClientPin(ctap)
                client.set_pin(PIN)
                token = client.get_pin_token(PIN, ClientPin.PERMISSION.MAKE_CREDENTIAL, RP["id"])
                att = register(ctap, extensions={"largeBlobKey": True}, resident=True,
                               authorization=(client.protocol, token))
                token = client.get_pin_token(PIN, ClientPin.PERMISSION.LARGE_BLOB_WRITE)
                store = LargeBlobs(ctap, client.protocol, token)
                store.put_blob(att.large_blob_key, payload)
                with self.assertRaises(CtapError) as failure:
                    store.put_blob(att.large_blob_key, os.urandom(4300))
                self.assertEqual(failure.exception.code, CtapError.ERR.LARGE_BLOB_STORAGE_FULL)
            with emulator(state), closing(HidTcp()) as hid:
                self.assertEqual(LargeBlobs(Ctap2(hid)).get_blob(att.large_blob_key), payload)

    def test_gap_fido_attestation_preference(self):
        with tempfile.TemporaryDirectory() as state, emulator(state), closing(HidTcp()) as hid:
            ctap = Ctap2(hid)
            self.assertNotIn(0x16, ctap.send_cbor(4))
            params = {1: HASH, 2: RP, 3: USER, 4: [{"type": "public-key", "alg": -7}]}
            self.assertEqual(ctap.send_cbor(1, params)[1], "packed")
            with self.assertRaises(CtapError) as failure:
                ctap.send_cbor(1, params | {0x0B: ["none"]})
            self.assertEqual(failure.exception.code, CtapError.ERR.CBOR_UNEXPECTED_TYPE)

    def test_fido_credential_management(self):
        with tempfile.TemporaryDirectory() as state, emulator(state), closing(HidTcp()) as hid:
            ctap = Ctap2(hid)
            client = ClientPin(ctap)
            client.set_pin(PIN)
            persistent = client.get_pin_token(PIN, ClientPin.PERMISSION.PERSISTENT_CREDENTIAL_MGMT)
            state_keys = {
                field: HKDF(hashes.SHA256(), 16, bytes(32), label).derive(persistent)
                for field, label in ((0x19, b"encIdentifier"), (0x1E, b"encCredStoreState"))
            }

            def read_state():
                info = ctap.send_cbor(4)
                blocks = []
                for field, key in state_keys.items():
                    iv, encrypted = info[field][:16], info[field][16:]
                    self.assertEqual(len(encrypted), 16)
                    decryptor = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
                    blocks.append((iv, decryptor.update(encrypted) + decryptor.finalize()))
                return blocks

            states = [read_state(), read_state()]
            token = client.get_pin_token(PIN, ClientPin.PERMISSION.MAKE_CREDENTIAL, RP["id"])
            att = register(ctap, resident=True, authorization=(client.protocol, token))
            states.append(read_state())
            descriptor = allow(att)[0]
            token = client.get_pin_token(PIN, ClientPin.PERMISSION.CREDENTIAL_MGMT)
            manager = CredentialManagement(ctap, client.protocol, token)
            result = CredentialManagement.RESULT
            rp_hash = hashlib.sha256(RP["id"].encode()).digest()
            rps = manager.enumerate_rps()
            self.assertEqual([rp[result.RP_ID_HASH] for rp in rps], [rp_hash])
            entries = manager.enumerate_creds(rp_hash)
            self.assertEqual([entry[result.CREDENTIAL_ID] for entry in entries], [descriptor])
            self.assertEqual(entries[0][result.USER]["name"], USER["name"])
            manager.update_user_info(descriptor, USER | {"name": "renamed"})
            self.assertEqual(manager.enumerate_creds(rp_hash)[0][result.USER]["name"], "renamed")
            states.append(read_state())
            manager.delete_cred(descriptor)
            self.assertEqual(manager.get_metadata()[result.EXISTING_CRED_COUNT], 0)
            self.assertEqual(manager.enumerate_rps(), [])
            states.append(read_state())
            self.assertEqual(len({identifier[1] for identifier, _ in states}), 1)
            self.assertEqual(len({identifier[0] for identifier, _ in states}), len(states))
            self.assertEqual(len({state[0] for _, state in states}), len(states))
            self.assertEqual(states[0][1][1], states[1][1][1])
            self.assertEqual(len({state[1] for _, state in states}), 4)

    def test_gap_fido_ppuat_restart(self):
        with tempfile.TemporaryDirectory() as state:
            with emulator(state), closing(HidTcp()) as hid:
                ctap = Ctap2(hid)
                client = ClientPin(ctap)
                client.set_pin(PIN)
                token = client.get_pin_token(PIN, ClientPin.PERMISSION.PERSISTENT_CREDENTIAL_MGMT)
                metadata = CredentialManagement(ctap, client.protocol, token).get_metadata()
                self.assertEqual(metadata[1], 0)
                time.sleep(0.15)
            with emulator(state), closing(HidTcp()) as hid:
                ctap = Ctap2(hid)
                client = ClientPin(ctap)
                manager = CredentialManagement(ctap, client.protocol, token)
                with self.assertRaises(CtapError) as failure:
                    manager.get_metadata()
                self.assertEqual(failure.exception.code, CtapError.ERR.PIN_AUTH_INVALID)
                self.assertEqual(client.get_pin_token(
                    PIN, ClientPin.PERMISSION.PERSISTENT_CREDENTIAL_MGMT), token)
                self.assertEqual(manager.get_metadata(), metadata)

    def test_oath_totp_hotp_and_restart(self):
        secret = b"12345678901234567890"  # RFC 4226 public test vector.
        with tempfile.TemporaryDirectory() as state:
            with emulator(state), closing(CardTcp()) as card:
                card.select("a0000005272101")
                oath_put(card, b"hotp", secret, 0x11)
                self.assertEqual(oath_calculate(card, b"hotp", 999) % 1000000, 755224)
                self.assertEqual(oath_calculate(card, b"hotp", 999) % 1000000, 287082)
                for number, digest in ((1, "sha1"), (2, "sha256"), (3, "sha512")):
                    name = digest.encode()
                    oath_put(card, name, secret, 0x20 | number)
                    full = hmac.digest(secret, (2).to_bytes(8, "big"), digest)
                    offset = full[-1] & 0xF
                    expected = int.from_bytes(full[offset:offset + 4], "big") & 0x7FFFFFFF
                    self.assertEqual(oath_calculate(card, name, 2), expected)
                time.sleep(0.15)
            with emulator(state), closing(CardTcp()) as card:
                card.select("a0000005272101")
                self.assertEqual(oath_calculate(card, b"hotp", 999) % 1000000, 359152)

    def test_oath_only_increasing_across_commands_and_restart(self):
        name, key = b"monotonic", bytes(range(20))
        with tempfile.TemporaryDirectory() as state:
            with emulator(state), closing(CardTcp()) as card:
                card.select("a0000005272101")
                oath_put(card, name, key, 0x21, increasing=True)
                oath_put(card, b"ordinary", key, 0x21)
                first = oath_calculate(card, name, 2)
                for counter in (2, 1):
                    data = b"\x71\x09" + name + b"\x74\x08" + counter.to_bytes(8, "big")
                    apdu(card, "00a20001", data, status="6984")
                apdu(card, "00a20001", b"\x71\x09" + name + b"\x74\x07" + bytes(7), status="6984")
                newer = b"\x74\x08" + (3).to_bytes(8, "big")
                self.assertIn(b"\x71\x09monotonic\x76\x05\x06", apdu(card, "00a40001", newer))
                repeated = apdu(card, "00a40001", newer)
                self.assertIn(b"\x71\x09monotonic\x77\x01\x06", repeated)
                self.assertIn(b"\x71\x08ordinary\x76\x05\x06", repeated)
            with emulator(state), closing(CardTcp()) as card:
                card.select("a0000005272101")
                apdu(card, "00a20001", b"\x71\x09" + name + newer, status="6984")
                self.assertNotEqual(oath_calculate(card, name, 4), first)

    def test_oath_access_code_and_mutual_authentication(self):
        aid = "a0000005272101"
        secret, host = bytes(range(16)), b"host-oat"
        challenge = b"\x74\x08" + host
        proof = b"\x75\x14" + hmac.digest(secret, host, "sha1")
        with tempfile.TemporaryDirectory() as state:
            with emulator(state), closing(CardTcp()) as card:
                card.select(aid)
                oath_put(card, b"locked", bytes(range(20)), 0x21)
                apdu(card, "00030000", b"\x73\x11\x21" + secret + challenge + proof, le=False)
                time.sleep(0.15)
            with emulator(state), closing(CardTcp()) as card:
                selected = apdu(card, "00a40400", bytes.fromhex(aid))
                for tag in (0x79, 0x71):
                    self.assertEqual(selected[0], tag)
                    selected = selected[2 + selected[1]:]
                card_challenge = tlv_value(selected, 0x74)
                self.assertEqual(len(card_challenge), 8)
                apdu(card, "00a10000", status="6982")
                apdu(card, "00a30000", challenge + b"\x75\x14" + bytes(20), status="6984")
                response = b"\x75\x14" + hmac.digest(secret, card_challenge, "sha1")
                self.assertEqual(apdu(card, "00a30000", challenge + response), proof)
                self.assertEqual(apdu(card, "00a10000"), b"\x72\x07\x21locked")

    def test_otp_hmac_challenge_response(self):
        with tempfile.TemporaryDirectory() as state:
            secret = bytes(range(20))
            config = bytearray(52)
            config[16:20] = secret[16:]
            config[22:38] = secret[:16]
            config[46:48] = b"\x40\x22"  # Challenge response and HMAC-SHA1.
            crc = 0xFFFF
            for byte in config[:-2]:
                crc ^= byte
                for _ in range(8):
                    crc = (crc >> 1) ^ (0x8408 if crc & 1 else 0)
            config[-2:] = (crc ^ 0xFFFF).to_bytes(2, "little")
            message = bytes(range(64))
            with emulator(state), closing(CardTcp()) as card:
                card.select("a0000005272001")
                apdu(card, "00010100", config)
                self.assertEqual(apdu(card, "00013000", message), hmac.digest(secret, message, "sha1"))
                time.sleep(0.15)
            with emulator(state), closing(CardTcp()) as card:
                card.select("a0000005272001")
                self.assertEqual(apdu(card, "00013000", message), hmac.digest(secret, message, "sha1"))
                apdu(card, "00010100", bytes(58))
                time.sleep(0.15)
            with emulator(state), closing(CardTcp()) as card:
                status = apdu(card, "00a40400", bytes.fromhex("a0000005272001"))
                self.assertEqual(status[4] & 3, 0, "deleted slots must remain empty after reboot")

    def test_piv_generation_preserves_existing_certificate(self):
        with tempfile.TemporaryDirectory() as state:
            with emulator(state), closing(CardTcp()) as card:
                piv_login(card)
                public = piv_public(apdu(card, "0047009a", bytes.fromhex("ac03800111")))
                tag = bytes.fromhex("5c035fc105")
                apdu(card, "00cb3fff", tag, status="6a82")
                certificate = piv_certificate(public)
                apdu(card, "00db3fff", tag + certificate)
                replacement = piv_public(apdu(card, "0047009a", bytes.fromhex("ac03800111")))
                self.assertNotEqual(public.public_numbers(), replacement.public_numbers())
                self.assertEqual(apdu(card, "00cb3fff", tag), certificate)
                apdu(card, "00200080", b"123456\xff\xff", le=False)
                signed = apdu(card, "0087119a", b"\x7c\x24\x82\x00\x81\x20" + HASH)
                replacement.verify(tlv_value(tlv_value(signed, 0x7c), 0x82), HASH,
                                   ec.ECDSA(utils.Prehashed(hashes.SHA256())))
            with emulator(state), closing(CardTcp()) as card:
                card.select("a000000308000010000100")
                self.assertEqual(apdu(card, "00cb3fff", tag), certificate)

    def test_piv_management_key_and_certificate(self):
        with tempfile.TemporaryDirectory() as state, emulator(state), closing(CardTcp()) as card:
            piv_login(card)
            public = piv_public(apdu(card, "0047009a", bytes.fromhex("ac03800111")))
            certificate = piv_certificate(public)
            apdu(card, "00db3fff", bytes.fromhex("5c035fc105") + certificate)
            der = tlv_value(tlv_value(certificate, 0x53), 0x70)
            public = x509.load_der_x509_certificate(der).public_key()
            self.assertEqual(public.curve.name, "secp256r1")
            apdu(card, "00200080", b"123456\xff\xff", le=False)
            signed = apdu(card, "0087119a", b"\x7c\x24\x82\x00\x81\x20" + HASH)
            public.verify(tlv_value(tlv_value(signed, 0x7C), 0x82), HASH,
                          ec.ECDSA(utils.Prehashed(hashes.SHA256())))

    def test_piv_move_and_delete_preserve_both_certificates(self):
        with tempfile.TemporaryDirectory() as state, emulator(state), closing(CardTcp()) as card:
            piv_login(card)
            for algorithm in (0x16, 0xE0, 0xE1):
                apdu(card, "0047009a", bytes([0xAC, 3, 0x80, 1, algorithm]), status="6984")
            old, new = bytes.fromhex("5c035fc105"), bytes.fromhex("5c035fc10a")
            algorithm = bytes.fromhex("ac03800111")
            dest_cert = piv_certificate(piv_public(apdu(card, "0047009c", algorithm)))
            apdu(card, "00db3fff", new + dest_cert)
            apdu(card, "00f6ff9c")
            source_cert = piv_certificate(piv_public(apdu(card, "0047009a", algorithm)))
            apdu(card, "00db3fff", old + source_cert)
            self.assertNotEqual(source_cert, dest_cert)
            apdu(card, "00f6939a")
            apdu(card, "00f70093")  # Logical slot 93 has a different storage FID.
            apdu(card, "00f69c93")
            apdu(card, "00f70093", status="6a88")
            self.assertEqual(apdu(card, "00cb3fff", old), source_cert)
            self.assertEqual(apdu(card, "00cb3fff", new), dest_cert)
            apdu(card, "00f7009a", status="6a88")
            apdu(card, "00200080", b"123456\xff\xff", le=False)
            signed = apdu(card, "0087119c", b"\x7c\x24\x82\x00\x81\x20" + HASH)
            public = x509.load_der_x509_certificate(tlv_value(tlv_value(source_cert, 0x53), 0x70)).public_key()
            public.verify(tlv_value(tlv_value(signed, 0x7C), 0x82), HASH,
                          ec.ECDSA(utils.Prehashed(hashes.SHA256())))
            apdu(card, "00f6ff9c")
            apdu(card, "00f7009c", status="6a88")
            self.assertEqual(apdu(card, "00cb3fff", old), source_cert)
            self.assertEqual(apdu(card, "00cb3fff", new), dest_cert)
            apdu(card, "00f6fff9", status="6a86")

    def test_piv_chuid_rewrite(self):
        with tempfile.TemporaryDirectory() as state, emulator(state), closing(CardTcp()) as card:
            piv_login(card)
            tag = bytes.fromhex("5c035fc102")
            # GUID and error detection code TLVs in the CHUID object.
            first = b"\x34\x10" + bytes(range(16)) + b"\xfe\x00"
            second = b"\x34\x10" + bytes(reversed(range(16))) + b"\xfe\x00"
            apdu(card, "00db3fff", tag + bytes([0x53, len(first)]) + first)
            self.assertEqual(tlv_value(apdu(card, "00cb3fff", tag), 0x53), first)
            apdu(card, "00db3fff", tag + bytes([0x53, len(second)]) + second)
            self.assertEqual(tlv_value(apdu(card, "00cb3fff", tag), 0x53), second)

    def test_management_and_missing_security_applications(self):
        with tempfile.TemporaryDirectory() as state, emulator(state), closing(CardTcp()) as card:
            card.select("a000000527471117")
            config = apdu(card, "001d0000")
            self.assertEqual(config[0], len(config) - 1)
            usb_caps = int.from_bytes(tlv_value(config[1:], 1), "big")
            self.assertEqual(usb_caps & 0x033B, 0x023B)
            for aid in ("a000000151000000", "a000000527210701"):
                apdu(card, "00a40400", bytes.fromhex(aid), status="6a82")

    def test_gap_openpgp_attestation(self):
        with tempfile.TemporaryDirectory() as state, emulator(state), closing(CardTcp()) as card:
            card.select("d27600012401")
            apdu(card, "80fb0100", status="6d00")


@unittest.skipUnless(os.environ.get("TDONGLE_COMPARE_CAPACITY") == "1", "optional capacity run")
class CapacityEvidence(unittest.TestCase):
    def test_fido_100_and_oath_64_coexist(self):
        with tempfile.TemporaryDirectory() as state:
            with emulator(state):
                with closing(HidTcp()) as hid:
                    ctap = Ctap2(hid)
                    for index in range(100):
                        user = {"id": index.to_bytes(2, "big")}
                        last = ctap.make_credential(
                            HASH, RP, user, [{"type": "public-key", "alg": -7}], options={"rk": True}
                        )
                with closing(CardTcp()) as card:
                    card.select("a0000005272101")
                    for index in range(64):
                        name = f"coexist-{index:02d}".encode()
                        oath_put(card, name, bytes(range(20)), 0x21)
                    expected = oath_calculate(card, name, 2)
                time.sleep(0.15)
            with emulator(state), closing(HidTcp()) as hid, closing(CardTcp()) as card:
                ctap = Ctap2(hid)
                assertion = ctap.get_assertion(RP["id"], HASH, allow(last))
                assertion.verify(HASH, last.auth_data.credential_data.public_key)
                card.select("a0000005272101")
                self.assertEqual(oath_calculate(card, name, 2), expected)

    def test_oath_255_and_pagination(self):
        with tempfile.TemporaryDirectory() as state, emulator(state), closing(CardTcp()) as card:
            card.select("a0000005272101")
            names = {f"comparison-{n:03d}".encode() for n in range(255)}
            for name in sorted(names):
                oath_put(card, name, bytes(range(20)), 0x21)
            extra = b"\x71\x05extra\x73\x16\x21\x06" + bytes(range(20))
            apdu(card, "00010000", extra, le=False, status="6a84")
            seen = []
            for command in ("00a1000000", "00a5000000"):
                packet(card.sock, bytes.fromhex(command))
                raw = response(card.sock)
                self.assertEqual(raw[-2:].hex(), "6100" if command[2:4] == "a1" else "9000")
                data = raw[:-2]
                while data:
                    self.assertEqual(data[0], 0x72)
                    self.assertEqual(data[2], 0x21)
                    seen.append(data[3:data[1] + 2])
                    data = data[data[1] + 2:]
            self.assertEqual(len(seen), len(names))
            self.assertEqual(set(seen), names)

    def test_shared_capacity_fido_full_reports_no_free_slots(self):
        with tempfile.TemporaryDirectory() as state:
            with emulator(state):
                with closing(HidTcp()) as hid:
                    ctap = Ctap2(hid)
                    for index in range(255):
                        user = {"id": index.to_bytes(2, "big")}
                        params = [{"type": "public-key", "alg": -7}]
                        if index < 254:
                            last = ctap.make_credential(HASH, RP, user, params, options={"rk": True})
                        else:
                            with self.assertRaises(CtapError) as failure:
                                ctap.make_credential(HASH, RP, user, params, options={"rk": True})
                            self.assertEqual(failure.exception.code, CtapError.ERR.KEY_STORE_FULL)
                    client = ClientPin(ctap)
                    client.set_pin(PIN)
                    token = client.get_pin_token(PIN, ClientPin.PERMISSION.CREDENTIAL_MGMT)
                    self.assertEqual(CredentialManagement(ctap, client.protocol, token).get_metadata(),
                                     {1: 254, 2: 0})
                    self.assertEqual(ctap.get_info().remaining_disc_creds, 0)
                with closing(CardTcp()) as card:
                    card.select("a0000005272101")
                    for index in range(4):
                        oath_put(card, f"comparison-{index:03d}".encode(), bytes(range(20)), 0x21)
                    fifth = b"\x71\x05fifth\x73\x16\x21\x06" + bytes(range(20))
                    apdu(card, "00010000", fifth, le=False, status="6400")
                with closing(HidTcp()) as hid:
                    ctap = Ctap2(hid)
                    client = ClientPin(ctap)
                    token = client.get_pin_token(PIN, ClientPin.PERMISSION.CREDENTIAL_MGMT)
                    manager = CredentialManagement(ctap, client.protocol, token)
                    manager.delete_cred(allow(last)[0])
                    self.assertEqual(manager.get_metadata(), {1: 253, 2: 1})
                    self.assertEqual(ctap.get_info().remaining_disc_creds, 1)
            with emulator(state), closing(HidTcp()) as hid:
                ctap = Ctap2(hid)
                client = ClientPin(ctap)
                token = client.get_pin_token(PIN, ClientPin.PERMISSION.CREDENTIAL_MGMT)
                self.assertEqual(CredentialManagement(ctap, client.protocol, token).get_metadata(),
                                 {1: 253, 2: 1})
                self.assertEqual(ctap.get_info().remaining_disc_creds, 1)
                self.assertEqual(hid.call(1, b"full-store-restart"), b"full-store-restart")


if __name__ == "__main__":
    unittest.main(verbosity=2)
