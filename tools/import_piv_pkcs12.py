#!/usr/bin/env python3
from __future__ import annotations

import argparse
import struct
import sys
from pathlib import Path
from typing import Iterable

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PublicFormat,
    pkcs12,
)
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography import x509
from smartcard import System
from ykman.pcsc import ScardSmartCardConnection
from ykman.piv import generate_ccc
from yubikit.core import Tlv
from yubikit.core.smartcard import AID, SW, ApduError, SmartCardProtocol
from yubikit.piv import (
    DEFAULT_MANAGEMENT_KEY,
    KEY_TYPE,
    OBJECT_ID,
    PIN_POLICY,
    SLOT,
    TOUCH_POLICY,
    PivSession,
)


PIN_POLICIES = {
    "default": PIN_POLICY.DEFAULT,
    "never": PIN_POLICY.NEVER,
    "once": PIN_POLICY.ONCE,
    "always": PIN_POLICY.ALWAYS,
}

TOUCH_POLICIES = {
    "default": TOUCH_POLICY.DEFAULT,
    "never": TOUCH_POLICY.NEVER,
    "always": TOUCH_POLICY.ALWAYS,
    "cached": TOUCH_POLICY.CACHED,
}


def tlv(tag: int, value: bytes = b"") -> bytes:
    if len(value) < 0x80:
        return bytes((tag, len(value))) + value
    if len(value) <= 0xFF:
        return bytes((tag, 0x81, len(value))) + value
    if len(value) <= 0xFFFF:
        return bytes((tag, 0x82, (len(value) >> 8) & 0xFF, len(value) & 0xFF)) + value
    raise ValueError(f"TLV value too large for tag 0x{tag:02x}: {len(value)} bytes")


def int_to_bytes(value: int, length: int | None = None) -> bytes:
    if value < 0:
        raise ValueError("value must be non-negative")
    if length is None:
        length = max(1, (value.bit_length() + 7) // 8)
    return value.to_bytes(length, "big")


def parse_slot(value: str) -> SLOT:
    slot_value = int(value, 16) if value.lower().startswith("0x") else int(value, 16)
    return SLOT(slot_value)


def parse_object_id(value: str) -> int:
    if value.lower().startswith("0x"):
        return int(value, 16)
    return int(value, 16)


def list_readers() -> list:
    return list(System.readers())


def choose_reader(reader_filter: str | None):
    readers = list_readers()
    if not readers:
        raise RuntimeError("Kein PC/SC-Reader gefunden.")

    if not reader_filter:
        if len(readers) != 1:
            raise RuntimeError("检测到多个读卡器；请用 --reader 唯一选择目标，不会自动写入第一台设备")
        return readers[0]

    lowered = reader_filter.lower()
    matches = [reader for reader in readers if lowered in reader.name.lower()]
    if not matches:
        available = ", ".join(reader.name for reader in readers)
        raise RuntimeError(
            f"Kein Reader passend zu '{reader_filter}' gefunden. Verfuegbar: {available}"
        )
    if len(matches) != 1:
        raise RuntimeError("读卡器名称匹配多个设备；请提供完整且唯一的 --reader")
    return matches[0]


def load_pkcs12_bundle(path: Path, password: str | None):
    blob = path.read_bytes()
    key, cert, extra = pkcs12.load_key_and_certificates(
        blob, password.encode("utf-8") if password is not None else None
    )
    if key is None:
        raise RuntimeError("Die PKCS#12-Datei enthaelt keinen privaten Schluessel.")
    if cert is None:
        raise RuntimeError("Die PKCS#12-Datei enthaelt kein Zertifikat.")
    return key, cert, extra or []


def same_public_key(cert: x509.Certificate, private_key) -> bool:
    cert_pub = cert.public_key().public_bytes(
        Encoding.DER, PublicFormat.SubjectPublicKeyInfo
    )
    key_pub = private_key.public_key().public_bytes(
        Encoding.DER, PublicFormat.SubjectPublicKeyInfo
    )
    return cert_pub == key_pub


def _ms_container_name(slot: SLOT) -> bytes:
    name = f"PIV {int(slot):02X}".encode("utf-16le") + b"\x00\x00"
    if len(name) > 80:
        raise RuntimeError("Windows-Containername ist unerwartet lang.")
    return name.ljust(80, b"\x00")


def _ms_key_spec(slot: SLOT) -> int:
    slot_value = int(slot)
    if slot_value == 0x9A:
        return 0x01  # AT_KEYEXCHANGE
    if slot_value == 0x9C:
        return 0x02  # AT_SIGNATURE
    return 0x00


def _public_key_bits(cert: x509.Certificate) -> int:
    public_key = cert.public_key()
    if isinstance(public_key, rsa.RSAPublicKey):
        return public_key.key_size
    if isinstance(public_key, ec.EllipticCurvePublicKey):
        return public_key.curve.key_size
    raise RuntimeError(f"Nicht unterstuetzter Public-Key-Typ fuer MSCMAP: {type(public_key)!r}")


def build_mscmap_object(slot: SLOT, cert: x509.Certificate) -> tuple[int, bytes]:
    key_bits = _public_key_bits(cert).to_bytes(2, "little")
    cert_sha1 = cert.fingerprint(hashes.SHA1())
    record = (
        _ms_container_name(slot)
        + bytes((int(slot), _ms_key_spec(slot)))
        + key_bits
        + b"\x03\x01\xFF"
        + cert_sha1
    )
    obj_id = 0x5FFF10
    obj_data = tlv(0x81, record)
    return obj_id, tlv(0x5C, int_to_bytes(obj_id)) + tlv(0x53, obj_data)


def parse_mscmap_records(raw: bytes) -> list[bytes]:
    # Yubico's ykpiv_util_write_mscmap stores one 0x81 TLV containing a packed
    # array of Windows ykpiv_container records (40 UTF-16 code units, 107 B).
    # Also accept this project's older repeated-TLV representation for migration.
    records = []
    for item in Tlv.parse_list(raw):
        if item.tag != 0x81 or len(item.value) % 107:
            raise ValueError("无法合并已有 Windows 映射格式；尚未写入密钥或证书")
        records.extend(item.value[i:i + 107] for i in range(0, len(item.value), 107))
    return records


def _cert_not_after_ascii(cert: x509.Certificate) -> bytes:
    not_after = getattr(cert, "not_valid_after_utc", None)
    if not_after is None:
        not_after = cert.not_valid_after
    return not_after.strftime("%Y%m%d").encode("ascii")


def build_chuid_object(cert: x509.Certificate) -> tuple[int, bytes]:
    obj_id = 0x5FC102
    fasc_n = bytes.fromhex("D4E739DA739CED39CE739D836858210842108421C84210C3EB")
    guid = cert.fingerprint(hashes.SHA1())[:16]
    chuid = (
        tlv(0x30, fasc_n)
        + tlv(0x34, guid)
        + tlv(0x35, _cert_not_after_ascii(cert))
        + tlv(0x3E)
        + tlv(0xFE)
    )
    return obj_id, tlv(0x5C, int_to_bytes(obj_id)) + tlv(0x53, chuid)


def print_readers(readers: Iterable) -> None:
    for idx, reader in enumerate(readers, start=1):
        print(f"{idx}. {reader.name}")


def select_piv(protocol: SmartCardProtocol) -> None:
    protocol.select(AID.PIV)


def get_certificate_raw(protocol: SmartCardProtocol, slot: SLOT) -> bytes:
    obj_id = OBJECT_ID.from_slot(slot)
    cmd = tlv(0x5C, int_to_bytes(int(obj_id)))
    return protocol.send_apdu(0, 0xCB, 0x3F, 0xFF, cmd)


def get_metadata_raw(protocol: SmartCardProtocol, slot: SLOT) -> bytes:
    return protocol.send_apdu(0, 0xF7, 0x00, int(slot))


def get_object_raw(protocol: SmartCardProtocol, object_id: int) -> bytes:
    cmd = tlv(0x5C, int_to_bytes(object_id))
    return protocol.send_apdu(0, 0xCB, 0x3F, 0xFF, cmd)


def encode_pin_block(pin: str) -> bytes:
    pin_bytes = pin.encode("ascii")
    if len(pin_bytes) > 8:
        raise RuntimeError("PIN darf maximal 8 ASCII-Zeichen haben.")
    return pin_bytes + (b"\xFF" * (8 - len(pin_bytes)))


def verify_pin_raw(protocol: SmartCardProtocol, pin: str) -> None:
    protocol.send_apdu(0, 0x20, 0x00, 0x80, encode_pin_block(pin))


def ga_rsa_test(
    protocol: SmartCardProtocol,
    slot: SLOT,
    use_tag_82: bool,
    leading_zero: bool = False,
    payload_len: int = 256,
    payload_byte: int = 0x6A,
) -> bytes:
    tag = 0x82 if use_tag_82 else 0x81
    if payload_len <= 0:
        raise RuntimeError("payload_len muss > 0 sein.")
    if payload_byte < 0 or payload_byte > 0xFF:
        raise RuntimeError("payload_byte muss zwischen 0x00 und 0xFF liegen.")
    payload = bytes([payload_byte]) * payload_len
    if leading_zero:
        payload = b"\x00" + payload
    dyn = tlv(tag, payload)
    cmd = tlv(0x7C, dyn)
    return protocol.send_apdu(0, 0x87, 0x07, int(slot), cmd)


def parse_trace_dump(raw: bytes) -> bool:
    data = raw
    if len(data) >= 2 and data[0] == 0x53:
        if data[1] < 0x80:
            l_len = 1
            v_len = data[1]
        elif data[1] == 0x81 and len(data) >= 3:
            l_len = 2
            v_len = data[2]
        elif data[1] == 0x82 and len(data) >= 4:
            l_len = 3
            v_len = (data[2] << 8) | data[3]
        else:
            return False
        v_off = 1 + l_len
        if v_off + v_len > len(data):
            return False
        data = data[v_off : v_off + v_len]

    if len(data) < 8 or data[:4] != b"TRC1":
        return False

    version = data[4]
    count = data[5]
    req_snap = data[6]
    resp_snap = data[7]
    print(
        f"PIV Trace Dump erkannt: Version={version}, Eintraege={count}, ReqSnap={req_snap}, RespSnap={resp_snap}"
    )

    hdr_fmt = "<IBBBBHHHHBB"
    hdr_len = struct.calcsize(hdr_fmt)
    rec_len = hdr_len + req_snap + resp_snap
    max_records = (len(data) - 8) // rec_len if len(data) >= 8 else 0
    if count > max_records:
        print(
            f"Hinweis: Header meldet {count} Eintraege, im Dump enthalten sind {max_records}. Begrenze Ausgabe."
        )
        count = max_records
    off = 8

    for i in range(count):
        if off + rec_len > len(data):
            print(f"Trace-Ende bei Eintrag {i}, unvollstaendige Daten.")
            break

        seq, cla, ins, p1, p2, lc, le, sw, resp_len, req_len, resp_snap_len = struct.unpack_from(
            hdr_fmt, data, off
        )
        off += hdr_len
        req_raw = data[off : off + req_snap]
        off += req_snap
        resp_raw = data[off : off + resp_snap]
        off += resp_snap

        req = req_raw[:req_len]
        resp = resp_raw[:resp_snap_len]

        print(
            f"[{i}] seq={seq} CLA={cla:02X} INS={ins:02X} P1={p1:02X} P2={p2:02X} LC={lc} LE={le} SW=0x{sw:04X} RespLen={resp_len}"
        )
        if req:
            print(f"    REQ:  {req.hex().upper()}")
        if resp:
            print(f"    RESP: {resp.hex().upper()}")
    return True


def import_direct(
    session: PivSession,
    slot: SLOT,
    private_key,
    cert: x509.Certificate,
    pin_policy: PIN_POLICY,
    touch_policy: TOUCH_POLICY,
    verify: bool,
) -> None:
    # Validate and merge existing mapping before changing any key or certificate.
    try:
        existing_mapping = session.get_object(0x5FFF10)
    except ApduError as exc:
        if exc.sw != SW.FILE_NOT_FOUND:
            raise
        existing_mapping = b""
    records = parse_mscmap_records(existing_mapping)
    _, new_mapping = build_mscmap_object(slot, cert)
    replacement = Tlv.unpack(0x81, Tlv.parse_dict(new_mapping)[0x53])
    mapping = Tlv(0x81, b"".join(record for record in records if record[80] != int(slot)) + replacement)
    if len(mapping) > 2048:
        raise ValueError("Windows 映射超过本固件 2 KiB 对象上限；尚未写入密钥或证书")

    session.put_key(slot, private_key, pin_policy, touch_policy)
    session.put_certificate(slot, cert)
    protocol = session.protocol
    obj_id = OBJECT_ID.from_slot(slot)
    print(f"Import-APDUs erfolgreich gesendet, Objekt {obj_id.name} geschrieben.")

    chuid_id, chuid_payload = build_chuid_object(cert)
    protocol.send_apdu(0, 0xDB, 0x3F, 0xFF, chuid_payload)
    print(f"CHUID-Objekt 0x{chuid_id:06X} geschrieben.")

    try:
        ccc = session.get_object(OBJECT_ID.CAPABILITY)
    except ApduError as exc:
        if exc.sw != SW.FILE_NOT_FOUND:
            raise
        ccc = b""
    if not Tlv.parse_dict(ccc).get(0xF0):
        session.put_object(OBJECT_ID.CAPABILITY, generate_ccc())
    session.put_object(0x5FFF10, mapping)
    print("Windows 映射已合并；其他槽位映射和 MSROOTS 保留。")

    if not verify:
        return

    try:
        raw = session.get_certificate(slot).public_bytes(Encoding.DER)
    except Exception as exc:  # noqa: BLE001
        raise RuntimeError(
            f"Import gesendet, aber GET DATA zur Verifikation ist fehlgeschlagen: {exc}"
        ) from exc

    if cert.public_bytes(Encoding.DER) != raw:
        raise RuntimeError(
            f"Import gesendet, aber das gelesene Objekt fuer {slot.name} enthaelt nicht das erwartete Zertifikat."
        )

    print("Zertifikat per GET DATA verifiziert.")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Importiert PKCS#12-Schluessel und Zertifikat direkt in den PIV-Slot."
    )
    parser.add_argument("-i", "--input", type=Path, help="Pfad zur .pfx/.p12 Datei")
    parser.add_argument("-p", "--password", help="Passwort der PKCS#12-Datei")
    parser.add_argument(
        "-s", "--slot", default="9d", help="PIV-Slot in Hex, z. B. 9a, 9c, 9d, 9e"
    )
    parser.add_argument("--reader", help="唯一的读卡器名称或子串")
    parser.add_argument("--serial", type=int, help="写入时必须提供预期设备序列号")
    parser.add_argument(
        "--auth-mode",
        choices=("auto", "on", "off"),
        default="auto",
        help="兼容旧参数；写入必须完成管理认证，off 仅允许只读诊断",
    )
    parser.add_argument(
        "--management-key",
        default=DEFAULT_MANAGEMENT_KEY.hex(),
        help="Management-Key als Hexstring, Standard ist der PIV-Default",
    )
    parser.add_argument(
        "--pin-policy",
        choices=tuple(PIN_POLICIES),
        default="default",
        help="Optionale PIN-Policy fuer den importierten Schluessel",
    )
    parser.add_argument(
        "--touch-policy",
        choices=tuple(TOUCH_POLICIES),
        default="default",
        help="Optionale Touch-Policy fuer den importierten Schluessel",
    )
    parser.add_argument(
        "--list-readers",
        action="store_true",
        help="Nur verfuegbare PC/SC-Reader anzeigen",
    )
    parser.add_argument(
        "--verify",
        action="store_true",
        help="Nach dem Schreiben per GET DATA lesen und das Zertifikat pruefen",
    )
    parser.add_argument(
        "--connect-only",
        action="store_true",
        help="Nur PC/SC connect, ATR und optional PIV SELECT testen",
    )
    parser.add_argument(
        "--select-only",
        action="store_true",
        help="Nach Connect nur SELECT PIV senden und dann beenden",
    )
    parser.add_argument(
        "--invalid-apdu",
        action="store_true",
        help="Nach Connect ein ungueltiges Test-APDU senden und die SW ausgeben",
    )
    parser.add_argument(
        "--read-cert",
        action="store_true",
        help="Nach SELECT nur das aktuelle Zertifikatsobjekt des Slots lesen",
    )
    parser.add_argument(
        "--read-metadata",
        action="store_true",
        help="Nach SELECT nur GET METADATA fuer den Slot ausfuehren",
    )
    parser.add_argument(
        "--read-object",
        help="Nach SELECT GET DATA fuer ein beliebiges Objekt (Hex), z. B. 0x5fff10",
    )
    parser.add_argument(
        "--clear-trace",
        action="store_true",
        help="Loescht den internen PIV-APDU-Trace (GET DATA auf 0x5FFF21).",
    )
    parser.add_argument(
        "--verify-pin-raw",
        help="Fuehrt rohe VERIFY (INS 0x20) mit diesem PIN aus (ASCII, max 8 Zeichen)",
    )
    parser.add_argument(
        "--ga81-test",
        action="store_true",
        help="Fuehrt GENERAL AUTH (RSA2048, Tag 0x81, 256-Byte-Block) fuer den Slot aus",
    )
    parser.add_argument(
        "--ga82-test",
        action="store_true",
        help="Fuehrt GENERAL AUTH (RSA2048, Tag 0x82, 256-Byte-Block) fuer den Slot aus",
    )
    parser.add_argument(
        "--ga82-test-leading-zero",
        action="store_true",
        help="Fuehrt GENERAL AUTH (Tag 0x82) mit fuehrendem 0x00 + 256-Byte-Block aus",
    )
    parser.add_argument(
        "--ga-test-tag",
        choices=("81", "82"),
        help="Custom GENERAL AUTH Test-Tag (81 oder 82).",
    )
    parser.add_argument(
        "--ga-test-len",
        type=int,
        help="Custom GENERAL AUTH Payload-Laenge in Bytes (vor optionalem leading zero).",
    )
    parser.add_argument(
        "--ga-test-byte",
        default="6A",
        help="Payload-Byte fuer Custom GA-Test als Hex (z.B. 6A).",
    )
    parser.add_argument(
        "--ga-test-leading-zero",
        action="store_true",
        help="Fuegt bei Custom GA-Test ein fuehrendes 0x00 vor die Payload ein.",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()

    if args.list_readers:
        readers = list_readers()
        if not readers:
            print("Keine PC/SC-Reader gefunden.", file=sys.stderr)
            return 1
        print_readers(readers)
        return 0

    slot = parse_slot(args.slot)
    pin_policy = PIN_POLICIES[args.pin_policy]
    touch_policy = TOUCH_POLICIES[args.touch_policy]
    _management_key = bytes.fromhex(args.management_key)

    needs_pkcs12 = not (
        args.connect_only
        or args.select_only
        or args.invalid_apdu
        or args.read_cert
        or args.read_metadata
        or args.read_object
        or args.clear_trace
        or args.verify_pin_raw
        or args.ga81_test
        or args.ga82_test
        or args.ga82_test_leading_zero
        or args.ga_test_tag
    )

    private_key = cert = None
    chain = []
    if needs_pkcs12:
        if args.serial is None:
            raise RuntimeError("导入必须提供 --serial，连接后核对设备身份再写入")
        if args.auth_mode == "off":
            print("导入必须完成管理密钥认证，请使用 --auth-mode auto 或 on", file=sys.stderr)
            return 2
        if not args.input:
            print("--input ist erforderlich.", file=sys.stderr)
            return 2
        if not args.input.exists():
            print(f"Datei nicht gefunden: {args.input}", file=sys.stderr)
            return 2

        private_key, cert, chain = load_pkcs12_bundle(args.input, args.password)
        if not same_public_key(cert, private_key):
            raise RuntimeError(
                "Zertifikat und privater Schluessel in der PKCS#12-Datei gehoeren nicht zusammen."
            )

    reader = choose_reader(args.reader)
    print(f"Nutze Reader: {reader.name}")
    if args.read_object:
        obj_id = parse_object_id(args.read_object)
        print(f"Lese Objekt: 0x{obj_id:06X}")
    else:
        print(f"Importiere in Slot: 0x{int(slot):02X} ({slot.name})")
    if cert is not None:
        print(f"Zertifikatsgroesse (DER): {len(cert.public_bytes(Encoding.DER))} Bytes")
    if chain:
        print(f"Zusatz-Zertifikate in PKCS#12: {len(chain)}")

    try:
        print("Oeffne PC/SC-Verbindung...")
        connection = ScardSmartCardConnection(reader.createConnection())
        atr = bytes(connection.connection.getATR())
        print(f"PC/SC connect erfolgreich. ATR: {atr.hex().upper()}")

        if args.connect_only:
            return 0

        protocol = SmartCardProtocol(connection)

        if args.invalid_apdu:
            print("Sende Test-APDU 00 00 00 00 ...")
            try:
                protocol.send_apdu(0, 0, 0, 0)
                print("Test-APDU unerwartet erfolgreich.")
            except ApduError as exc:
                print(f"Test-APDU beantwortet mit SW=0x{exc.sw:04X}")
                return 0

        print("Sende SELECT PIV...")
        select_piv(protocol)
        print("PIV-Applet erfolgreich selektiert.")

        if args.select_only:
            return 0

        if args.read_cert:
            print("Lese Zertifikatsobjekt per GET DATA...")
            raw = get_certificate_raw(protocol, slot)
            print(f"GET DATA erfolgreich, Laenge: {len(raw)} Bytes")
            return 0

        if args.read_metadata:
            print("Lese Slot-Metadaten per GET METADATA...")
            raw = get_metadata_raw(protocol, slot)
            print(f"GET METADATA erfolgreich, Laenge: {len(raw)} Bytes")
            return 0

        if args.read_object:
            obj_id = parse_object_id(args.read_object)
            print(f"Lese Objekt 0x{obj_id:06X} per GET DATA...")
            raw = get_object_raw(protocol, obj_id)
            print(f"GET DATA erfolgreich, Laenge: {len(raw)} Bytes")
            if not parse_trace_dump(raw):
                print(f"HEX: {raw.hex().upper()}")
            return 0

        if args.clear_trace:
            print("Loesche internen Trace per GET DATA 0x5FFF21...")
            raw = get_object_raw(protocol, 0x5FFF21)
            print(f"Trace-Reset Antwort, Laenge: {len(raw)} Bytes")
            print(f"HEX: {raw.hex().upper()}")
            return 0

        if args.verify_pin_raw:
            print("Sende rohe VERIFY PIN...")
            verify_pin_raw(protocol, args.verify_pin_raw)
            print("VERIFY erfolgreich.")
            if not (
                args.ga81_test
                or args.ga82_test
                or args.ga82_test_leading_zero
                or args.ga_test_tag
            ):
                return 0

        if args.ga81_test:
            print(f"Sende GENERAL AUTH Test (Tag 0x81) fuer Slot 0x{int(slot):02X}...")
            raw = ga_rsa_test(protocol, slot, use_tag_82=False)
            print(f"GA(0x81) erfolgreich, Laenge: {len(raw)} Bytes")
            print(f"HEX: {raw.hex().upper()}")
            return 0

        if args.ga82_test:
            print(f"Sende GENERAL AUTH Test (Tag 0x82) fuer Slot 0x{int(slot):02X}...")
            raw = ga_rsa_test(protocol, slot, use_tag_82=True)
            print(f"GA(0x82) erfolgreich, Laenge: {len(raw)} Bytes")
            print(f"HEX: {raw.hex().upper()}")
            return 0

        if args.ga82_test_leading_zero:
            print(
                f"Sende GENERAL AUTH Test (Tag 0x82) mit fuehrendem 0x00 fuer Slot 0x{int(slot):02X}..."
            )
            raw = ga_rsa_test(protocol, slot, use_tag_82=True, leading_zero=True)
            print(f"GA(0x82 + 0x00-Prefix) erfolgreich, Laenge: {len(raw)} Bytes")
            print(f"HEX: {raw.hex().upper()}")
            return 0

        if args.ga_test_tag:
            use_tag_82 = args.ga_test_tag == "82"
            payload_byte = int(args.ga_test_byte, 16)
            payload_len = args.ga_test_len if args.ga_test_len else 256
            print(
                f"Sende Custom GENERAL AUTH Test (Tag 0x{args.ga_test_tag}, Len={payload_len}, Byte=0x{payload_byte:02X}, LeadingZero={args.ga_test_leading_zero})..."
            )
            raw = ga_rsa_test(
                protocol,
                slot,
                use_tag_82=use_tag_82,
                leading_zero=args.ga_test_leading_zero,
                payload_len=payload_len,
                payload_byte=payload_byte,
            )
            print(f"GA(Custom) erfolgreich, Laenge: {len(raw)} Bytes")
            print(f"HEX: {raw.hex().upper()}")
            return 0

        session = PivSession(connection)
        if session.get_serial() != args.serial:
            raise RuntimeError("设备序列号不匹配；未进行管理认证或写入")
        session.authenticate(_management_key)
        print("管理密钥认证成功，使用官方 yubikit 导入。")
        import_direct(
            session,
            slot,
            private_key,
            cert,
            pin_policy,
            touch_policy,
            args.verify,
        )

        print("Direktimport abgeschlossen.")
        return 0
    except ApduError as exc:
        print(f"APDU-Fehler: SW=0x{exc.sw:04X}", file=sys.stderr)
        return 1
    except Exception as exc:  # noqa: BLE001
        print(str(exc), file=sys.stderr)
        return 1
    finally:
        if "connection" in locals():
            connection.close()


if __name__ in ("__main__", "builtins"):
    raise SystemExit(main())
