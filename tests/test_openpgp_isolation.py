"""Verify OpenPGP/FIDO storage isolation using only isolated simulator flash."""
import json
import os
import tempfile
import time
import unittest
import zlib
from contextlib import closing
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric import ed25519, x25519
from fido2 import cbor
from fido2.cose import CoseKey
from fido2.ctap import CtapError
from fido2.ctap2 import Ctap2

from test_emulation import CardTcp, HidTcp, emulator


ED = bytes.fromhex('162b06010401da470f01')
CV = bytes.fromhex('122b060104019755010501')
SLOTS = [(0xc1, ED, 0xb6), (0xc2, CV, 0xb8), (0xc3, ED, 0xa4)]
AID='d27600012401'

def apdu(c, header, payload=None, le=True, status='9000'):
    packet=bytes.fromhex(header)
    if payload is not None:
        packet+=(bytes([len(payload)]) if len(payload) <= 255 else b'\0'+len(payload).to_bytes(2,'big'))+payload
    if le:
        packet+=b'\0\0' if payload is not None and len(payload) > 255 else b'\0'
    result=c.exchange(packet)
    assert result[-2:].hex()==status,(header,result[-2:].hex(),status)
    return result[:-2]

def slot(c, ref, create=False):
    data=apdu(c,'00478000' if create else '00478100', bytes([ref,0]))
    assert data.startswith(bytes.fromhex('7f49228620')) and len(data)==37,data.hex()
    return data[5:]

def configure(c):
    c.select(AID)
    algorithms=apdu(c,'00ca00fa')
    for attr,alg,_ in SLOTS:
        assert bytes([attr,len(alg)])+alg in algorithms
    apdu(c,'00200083',b'12345678',False)
    result={}
    for attr,alg,ref in SLOTS:
        apdu(c,f'00da00{attr:02x}',alg,False)
        assert apdu(c,f'00ca00{attr:02x}').endswith(alg)
        result[ref]=slot(c,ref,True)
        assert slot(c,ref)==result[ref]
    assert result[0xb6]!=result[0xa4]
    return result

def exercise(c, public, count):
    c.select(AID)
    for attr,alg,ref in SLOTS:
        assert apdu(c,f'00ca00{attr:02x}').endswith(alg)
        assert slot(c,ref)==public[ref]
    sign=ed25519.Ed25519PublicKey.from_public_bytes(public[0xb6])
    auth=ed25519.Ed25519PublicKey.from_public_bytes(public[0xa4])
    dec=x25519.X25519PublicKey.from_public_bytes(public[0xb8])
    apdu(c,'002a9e9a',b'unsigned',status='6982')
    apdu(c,'00200082',b'123456',False)
    for i in range(count):
        challenge=os.urandom(64)
        apdu(c,'00200081',b'123456',False)
        sign.verify(apdu(c,'002a9e9a',challenge),challenge)
        auth.verify(apdu(c,'00880000',challenge),challenge)
        peer=x25519.X25519PrivateKey.generate()
        peer_public=peer.public_key().public_bytes_raw()
        if i % 2: peer_public=bytes([0x40])+peer_public
        template=bytes([0xa6,len(peer_public)+5,0x7f,0x49,len(peer_public)+2,0x86,len(peer_public)])+peer_public
        assert apdu(c,'002a8086',template)==peer.exchange(dec)


class OpenPgpIsolation(unittest.TestCase):
    def test_legacy_keys_and_fido_credential_survive_upgrade(self):
        fixtures = Path(__file__).parent / "fixtures"
        meta = json.loads((fixtures / "legacy-openpgp25519.json").read_text())
        self.assertTrue(meta["test_only"])
        public = {int(k, 16): bytes.fromhex(v) for k, v in meta["openpgp"].items()}
        with tempfile.TemporaryDirectory(prefix="tdongle-openpgp-upgrade-") as state:
            flash = zlib.decompress((fixtures / "legacy-openpgp25519.flash.zlib").read_bytes())
            (Path(state) / "memory.flash").write_bytes(flash)
            for boot in range(2):
                with emulator(state):
                    with closing(HidTcp()) as hid:
                        challenge = bytes.fromhex(meta["challenge"])
                        allow = [{"type": "public-key", "id": bytes.fromhex(meta["fido_id"])}]
                        ctap = Ctap2(hid)
                        if boot == 0:
                            assertion = ctap.get_assertion(meta["rp"], challenge, allow)
                            CoseKey.parse(cbor.decode(bytes.fromhex(meta["fido_public"]))).verify(
                                bytes(assertion.auth_data) + challenge, assertion.signature)
                        else:
                            with self.assertRaises(CtapError) as error:
                                ctap.get_assertion(meta["rp"], challenge, allow)
                            self.assertEqual(error.exception.code, CtapError.ERR.NO_CREDENTIALS)
                    with closing(CardTcp()) as card:
                        exercise(card, public, 3)
                    if boot == 0:
                        with closing(HidTcp()) as hid:
                            Ctap2(hid).reset()
                        with closing(CardTcp()) as card:
                            exercise(card, public, 3)
                    time.sleep(0.15)  # Let the asynchronous signature counter flush.

    def test_openpgp_reset_does_not_remove_fido_credential(self):
        fixtures = Path(__file__).parent / "fixtures"
        meta = json.loads((fixtures / "legacy-openpgp25519.json").read_text())
        with tempfile.TemporaryDirectory(prefix="tdongle-openpgp-reset-") as state:
            flash = zlib.decompress((fixtures / "legacy-openpgp25519.flash.zlib").read_bytes())
            (Path(state) / "memory.flash").write_bytes(flash)
            with emulator(state):
                with closing(CardTcp()) as card:
                    card.select(AID)
                    apdu(card, "00200083", b"12345678", False)
                    apdu(card, "00e60000", le=False)
                    for _, _, slot_id in SLOTS:
                        apdu(card, "00478100", bytes([slot_id, 0]), status="6a88")
                with closing(HidTcp()) as hid:
                    challenge = bytes.fromhex(meta["challenge"])
                    allow = [{"type": "public-key", "id": bytes.fromhex(meta["fido_id"])}]
                    assertion = Ctap2(hid).get_assertion(meta["rp"], challenge, allow)
                    CoseKey.parse(cbor.decode(bytes.fromhex(meta["fido_public"]))).verify(
                        bytes(assertion.auth_data) + challenge, assertion.signature)

    def test_new_keys_survive_fido_initialization_and_restart(self):
        with tempfile.TemporaryDirectory(prefix="tdongle-openpgp-new-") as state:
            with emulator(state):
                with closing(CardTcp()) as card:
                    public = configure(card)
                    exercise(card, public, 3)
                for _ in range(3):
                    with closing(HidTcp()) as hid:
                        self.assertIn(-8, [a["alg"] for a in Ctap2(hid).get_info().algorithms])
                    with closing(CardTcp()) as card:
                        exercise(card, public, 3)
            with emulator(state), closing(CardTcp()) as card:
                exercise(card, public, 3)


if __name__ == "__main__":
    unittest.main(verbosity=2)
