"""Upgrade synthetic old firmware flash; never access USB or real credentials."""
import json
import hashlib
import struct
from pathlib import Path
import tempfile
import time
import unittest
import zlib

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, utils
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms
from cryptography.hazmat.decrepit.ciphers import modes
from fido2 import cbor
from fido2.cose import CoseKey
from fido2.ctap2 import Ctap2
from test_emulation import emulator, HidTcp, CardTcp

FIXTURES = Path(__file__).parent / "fixtures"


def legacy_flash_with_custom_piv_pin():
    """Avoid a factory-PIN fixture masking accidental PIN reset on upgrade."""
    flash = bytearray(zlib.decompress((FIXTURES / "legacy-combined.flash.zlib").read_bytes()))
    records = {}
    pointer = struct.unpack_from("<Q", flash, len(flash) - 16 - 16384 - 12)[0]
    while pointer:
        following, _, fid, size = struct.unpack_from("<QQHH", flash, pointer)
        records[fid] = (pointer + 20, size)
        pointer = following
    def hash_multi(pin):
        return hashlib.sha256((pin * 256)[:256]).digest()
    pin = b"876543\xff\xff"
    pos, size = records[0x1184]
    assert size == 33
    intermediate = hash_multi(pin)
    flash[pos + 1:pos + 33] = hash_multi(bytes(v ^ pin[i % len(pin)] for i, v in enumerate(intermediate)))
    pos, _ = records[0x1099]
    iv = bytes(flash[pos:pos + 16])
    decrypt = Cipher(algorithms.AES(hash_multi(b"123456\xff\xff")), modes.CFB(iv)).decryptor()
    wrapped = decrypt.update(bytes(flash[pos + 112:pos + 144])) + decrypt.finalize()
    encrypt = Cipher(algorithms.AES(hash_multi(pin)), modes.CFB(iv)).encryptor()
    flash[pos + 112:pos + 144] = encrypt.update(wrapped) + encrypt.finalize()
    return flash, pin


class LegacyUpgrade(unittest.TestCase):
    def test_old_credentials_remain_usable_after_upgrade_and_restart(self):
        meta = json.loads((FIXTURES / "legacy-combined.json").read_text())
        self.assertTrue(meta["test_only"])
        with tempfile.TemporaryDirectory(prefix="tdongle-upgrade-") as state:
            flash, piv_pin = legacy_flash_with_custom_piv_pin()
            (Path(state) / "memory.flash").write_bytes(flash)
            counter = 0
            for boot in range(2):
                with emulator(state):
                    fido = meta["fido"]
                    hid = HidTcp()
                    challenge = bytes.fromhex(fido["challenge"])
                    assertion = Ctap2(hid).get_assertion(fido["rp_id"], challenge,
                        [{"type": "public-key", "id": bytes.fromhex(fido["credential_id"])}])
                    CoseKey.parse(cbor.decode(bytes.fromhex(fido["public_key"]))).verify(
                        bytes(assertion.auth_data) + challenge, assertion.signature)
                    self.assertGreater(assertion.auth_data.counter, counter)
                    counter = assertion.auth_data.counter
                    hid.close()
                    card = CardTcp()

                    def apdu(header, data=b"", le=True):
                        answer = card.exchange(bytes.fromhex(header) + bytes([len(data)]) + data +
                                               (b"\0" if le else b""))
                        self.assertEqual(answer[-2:], b"\x90\0", (header, answer.hex(), boot))
                        return answer[:-2]

                    card.select("a0000005272101")
                    oath = meta["oath"]
                    name = oath["name"].encode()
                    self.assertEqual(apdu("00a20001", b"\x71" + bytes([len(name)]) + name +
                        b"\x74\x08" + bytes.fromhex(oath["challenge"])).hex(), oath["answer"])
                    card.select("d27600012401")
                    pgp = meta["openpgp"]
                    self.assertEqual(apdu("00478100", bytes.fromhex("b600")).hex(), pgp["public_key"])
                    apdu("00200081", b"123456", False)
                    raw = apdu("002a9e9a", bytes.fromhex(pgp["digest"]))
                    self.assertEqual(len(raw), 64)
                    signature = utils.encode_dss_signature(int.from_bytes(raw[:32], "big"),
                                                           int.from_bytes(raw[32:], "big"))
                    key = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(),
                        bytes.fromhex(pgp["public_key"])[-65:])
                    key.verify(signature, bytes.fromhex(pgp["digest"]), ec.ECDSA(utils.Prehashed(hashes.SHA256())))
                    card.select("a000000308000010000100")
                    piv = meta["piv"]
                    # The old fixture advertises AES192 management metadata.
                    witness = apdu("00870a9b", bytes.fromhex("7c028000"))
                    self.assertGreaterEqual(len(witness), 20)
                    apdu("00200080", piv_pin, False)
                    signature = apdu("0087119a", bytes.fromhex("7c2482008120") + bytes.fromhex(piv["digest"]))
                    # GENERAL AUTHENTICATE returns 7c <length> 82 <length> DER signature.
                    self.assertEqual(signature[0], 0x7c)
                    self.assertEqual(signature[2], 0x82)
                    key = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(),
                        bytes.fromhex(piv["public_key"])[-65:])
                    key.verify(signature[4:], bytes.fromhex(piv["digest"]), ec.ECDSA(utils.Prehashed(hashes.SHA256())))
                    card.close()
                    time.sleep(0.2)


if __name__ == "__main__":
    unittest.main(verbosity=2)
