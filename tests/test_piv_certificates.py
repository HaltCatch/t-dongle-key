"""Certificate regression against disposable loopback firmware, never USB cards.

Run with yubikey-manager installed and TDONGLE_SIM_BINARY set, as for the
existing official-client tests. Private keys below are ephemeral test material.
"""
import datetime
import os
import tempfile
import unittest
from contextlib import closing

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa, padding
from yubikit.core import TRANSPORT, Tlv, NotSupportedError
from yubikit.core.smartcard import SmartCardConnection, ApduError, SW
from yubikit.piv import (PivSession, SLOT, OBJECT_ID, KEY_TYPE,
                        DEFAULT_MANAGEMENT_KEY, PIN_POLICY, TOUCH_POLICY)
from test_emulation import CardTcp, emulator


class LoopbackCard(SmartCardConnection):
    def __init__(self):
        self.card = CardTcp()

    @property
    def transport(self):
        return TRANSPORT.USB

    def send_and_receive(self, command):
        answer = self.card.exchange(command)
        return answer[:-2], int.from_bytes(answer[-2:], 'big')

    def close(self):
        self.card.close()


def certificate(key, signer=None, issuer=None, padding_bytes=0):
    name = x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, 'PIV isolated test')])
    builder = (x509.CertificateBuilder().subject_name(name).issuer_name(issuer or name)
               .public_key(key.public_key()).serial_number(x509.random_serial_number())
               .not_valid_before(datetime.datetime(2026, 1, 1, tzinfo=datetime.timezone.utc))
               .not_valid_after(datetime.datetime(2030, 1, 1, tzinfo=datetime.timezone.utc))
               .add_extension(x509.ExtendedKeyUsage([
                   x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH,
                   x509.ObjectIdentifier('1.3.6.1.4.1.311.67.1.1')]), critical=False)
               .add_extension(x509.SubjectAlternativeName([
                   x509.DNSName('piv-test.example.invalid')]), critical=False))
    if padding_bytes:
        builder = builder.add_extension(x509.UnrecognizedExtension(
            x509.ObjectIdentifier('1.3.6.1.4.1.55555.1'), b'A' * padding_bytes), False)
    return builder.sign(signer or key, hashes.SHA256())


def der(cert):
    return cert.public_bytes(serialization.Encoding.DER)


class PivCertificateRegression(unittest.TestCase):
    def assert_sw(self, status, function, *args):
        with self.assertRaises(ApduError) as raised:
            function(*args)
        self.assertEqual(int(raised.exception.sw), int(status))

    def test_rsa_and_ecc_import_certificate_sign_and_decrypt(self):
        with tempfile.TemporaryDirectory() as state, emulator(state), closing(LoopbackCard()) as conn:
            piv = PivSession(conn)
            piv.authenticate(DEFAULT_MANAGEMENT_KEY)
            for kind in (KEY_TYPE.RSA2048, KEY_TYPE.RSA3072, KEY_TYPE.RSA4096,
                         KEY_TYPE.ECCP256, KEY_TYPE.ECCP384):
                with self.subTest(algorithm=kind.name):
                    key = (rsa.generate_private_key(public_exponent=65537, key_size=kind.bit_len)
                           if kind.name.startswith('RSA') else ec.generate_private_key(
                               ec.SECP256R1() if kind == KEY_TYPE.ECCP256 else ec.SECP384R1()))
                    cert = certificate(key)
                    slot = SLOT.AUTHENTICATION if kind.name.startswith('RSA') else SLOT.KEY_MANAGEMENT
                    piv.put_key(slot, key, PIN_POLICY.ONCE, TOUCH_POLICY.NEVER)
                    piv.put_certificate(slot, cert)
                    read = piv.get_certificate(slot)
                    self.assertEqual(der(read), der(cert))
                    self.assertEqual(piv.get_slot_metadata(slot).public_key.public_numbers(),
                                     cert.public_key().public_numbers())
                    piv.verify_pin('123456')
                    message = os.urandom(32)
                    if kind.name.startswith('RSA'):
                        signature = piv.sign(slot, kind, message, hashes.SHA256(), padding.PKCS1v15())
                        read.public_key().verify(signature, message, padding.PKCS1v15(), hashes.SHA256())
                        for pad in (padding.PKCS1v15(), padding.OAEP(padding.MGF1(hashes.SHA256()), hashes.SHA256(), None)):
                            ciphertext = read.public_key().encrypt(message, pad)
                            self.assertEqual(piv.decrypt(slot, ciphertext, pad), message)
                    else:
                        peer = ec.generate_private_key(key.curve)
                        self.assertEqual(piv.calculate_secret(slot, peer.public_key()),
                                         peer.exchange(ec.ECDH(), key.public_key()))
                        piv.put_key(SLOT.SIGNATURE, key, PIN_POLICY.ONCE, TOUCH_POLICY.NEVER)
                        signature = piv.sign(SLOT.SIGNATURE, kind, message, hashes.SHA256())
                        read.public_key().verify(signature, message, ec.ECDSA(hashes.SHA256()))

    def test_all_24_certificate_slots_compression_and_restart(self):
        cert = certificate(ec.generate_private_key(ec.SECP256R1()))
        slots = [slot for slot in SLOT if slot != SLOT.ATTESTATION]
        self.assertEqual(len(slots), 24)
        with tempfile.TemporaryDirectory() as state:
            with emulator(state), closing(LoopbackCard()) as conn:
                piv = PivSession(conn)
                piv.authenticate(DEFAULT_MANAGEMENT_KEY)
                for i, slot in enumerate(slots):
                    piv.put_certificate(slot, cert, compress=bool(i % 2))
                    self.assertEqual(der(piv.get_certificate(slot)), der(cert))
            with emulator(state), closing(LoopbackCard()) as conn:
                piv = PivSession(conn)
                for slot in slots:
                    self.assertEqual(der(piv.get_certificate(slot)), der(cert))

    def test_large_compressed_certificate_exceeds_der_object_limit(self):
        cert = certificate(ec.generate_private_key(ec.SECP256R1()), padding_bytes=3000)
        self.assertGreater(len(der(cert)), 2048)
        with tempfile.TemporaryDirectory() as state, emulator(state), closing(LoopbackCard()) as conn:
            piv = PivSession(conn)
            piv.authenticate(DEFAULT_MANAGEMENT_KEY)
            piv.put_certificate(SLOT.SIGNATURE, cert, compress=True)
            self.assertEqual(der(piv.get_certificate(SLOT.SIGNATURE)), der(cert))
            # The official library rejects oversized APDUs before transmission.
            with self.assertRaises(NotSupportedError):
                piv.put_certificate(SLOT.SIGNATURE, cert)
            self.assertEqual(der(piv.get_certificate(SLOT.SIGNATURE)), der(cert))

    def test_unauthenticated_certificate_write_is_rejected(self):
        cert = certificate(ec.generate_private_key(ec.SECP256R1()))
        with tempfile.TemporaryDirectory() as state, emulator(state), closing(LoopbackCard()) as conn:
            piv = PivSession(conn)
            self.assert_sw(SW.SECURITY_CONDITION_NOT_SATISFIED,
                           piv.put_certificate, SLOT.AUTHENTICATION, cert)
            self.assert_sw(SW.FILE_NOT_FOUND, piv.get_certificate, SLOT.AUTHENTICATION)

    def test_bad_certificate_wrappers_do_not_replace_valid_certificate(self):
        cert = certificate(ec.generate_private_key(ec.SECP256R1()))
        malformed = [b'\x70\x00\x71\x01\x00',
                     Tlv(0x70, b'not DER') + Tlv(0x71, b'\0'),
                     Tlv(0x70, der(cert)) + Tlv(0x71, b'\x02'),
                     Tlv(0x70, der(cert)) * 2 + Tlv(0x71, b'\0')]
        with tempfile.TemporaryDirectory() as state, emulator(state), closing(LoopbackCard()) as conn:
            piv = PivSession(conn)
            piv.authenticate(DEFAULT_MANAGEMENT_KEY)
            piv.put_certificate(SLOT.AUTHENTICATION, cert)
            for raw in malformed:
                with self.assertRaises(ApduError) as raised:
                    piv.put_object(OBJECT_ID.AUTHENTICATION, raw)
                self.assertIn(int(raised.exception.sw), (0x6700, 0x6a80))
                self.assertEqual(der(piv.get_certificate(SLOT.AUTHENTICATION)), der(cert))

    def test_gap_ecdh_outside_key_management_slots(self):
        key = ec.generate_private_key(ec.SECP256R1())
        peer = ec.generate_private_key(ec.SECP256R1())
        with tempfile.TemporaryDirectory() as state, emulator(state), closing(LoopbackCard()) as conn:
            piv = PivSession(conn)
            piv.authenticate(DEFAULT_MANAGEMENT_KEY)
            for slot in (SLOT.AUTHENTICATION, SLOT.CARD_AUTH):
                piv.put_key(slot, key)
                piv.verify_pin('123456')
                self.assert_sw(0x6a80, piv.calculate_secret, slot, peer.public_key())

    def test_delete_certificate_preserves_private_key(self):
        key = ec.generate_private_key(ec.SECP256R1())
        with tempfile.TemporaryDirectory() as state, emulator(state), closing(LoopbackCard()) as conn:
            piv = PivSession(conn)
            piv.authenticate(DEFAULT_MANAGEMENT_KEY)
            piv.put_key(SLOT.SIGNATURE, key, PIN_POLICY.ALWAYS, TOUCH_POLICY.NEVER)
            piv.put_certificate(SLOT.SIGNATURE, certificate(key))
            piv.delete_certificate(SLOT.SIGNATURE)
            self.assert_sw(SW.FILE_NOT_FOUND, piv.get_certificate, SLOT.SIGNATURE)
            piv.verify_pin('123456')
            signature = piv.sign(SLOT.SIGNATURE, KEY_TYPE.ECCP256, b'certificate deleted', hashes.SHA256())
            key.public_key().verify(signature, b'certificate deleted', ec.ECDSA(hashes.SHA256()))
            self.assert_sw(SW.SECURITY_CONDITION_NOT_SATISFIED,
                           piv.sign, SLOT.SIGNATURE, KEY_TYPE.ECCP256, b'again', hashes.SHA256())

    def test_ca_signed_certificate_eku_san_and_public_key_survive_roundtrip(self):
        ca = ec.generate_private_key(ec.SECP384R1())
        ca_name = x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, 'Isolated test CA')])
        key = ec.generate_private_key(ec.SECP256R1())
        cert = certificate(key, signer=ca, issuer=ca_name)
        with tempfile.TemporaryDirectory() as state, emulator(state), closing(LoopbackCard()) as conn:
            piv = PivSession(conn)
            piv.authenticate(DEFAULT_MANAGEMENT_KEY)
            piv.put_key(SLOT.AUTHENTICATION, key)
            piv.put_certificate(SLOT.AUTHENTICATION, cert, compress=True)
            read = piv.get_certificate(SLOT.AUTHENTICATION)
            self.assertEqual(der(read), der(cert))
            ca.public_key().verify(read.signature, read.tbs_certificate_bytes, ec.ECDSA(read.signature_hash_algorithm))
            self.assertIn(x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH,
                          read.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value)
            piv.verify_pin('123456')
            signature = piv.sign(SLOT.AUTHENTICATION, KEY_TYPE.ECCP256, b'CA challenge', hashes.SHA256())
            read.public_key().verify(signature, b'CA challenge', ec.ECDSA(hashes.SHA256()))


if __name__ in ('__main__', 'builtins'):
    result = unittest.TextTestRunner(verbosity=2).run(
        unittest.defaultTestLoader.loadTestsFromTestCase(PivCertificateRegression))
    if not result.wasSuccessful():
        raise SystemExit(1)
