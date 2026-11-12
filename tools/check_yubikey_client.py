"""Read-only YubiKey client smoke test: ykman script --force FILE --serial SERIAL."""
import argparse
from contextlib import closing

from fido2.ctap2 import Ctap2
from ykman.device import list_all_devices
from ykman.openpgp import get_openpgp_info
from yubikit.core.fido import FidoConnection
from yubikit.core.smartcard import SmartCardConnection
from yubikit.oath import OathSession
from yubikit.openpgp import OpenPgpSession
from yubikit.piv import PivSession
from yubikit.yubiotp import YubiOtpSession


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--serial", required=True, type=int, help="Expected management serial")
    args = parser.parse_args()
    matches = [(device, info) for device, info in list_all_devices((FidoConnection, SmartCardConnection))
               if info.serial == args.serial]
    if len(matches) != 1:
        parser.error(f"Expected one matching device, found {len(matches)}")
    device, info = matches[0]
    print(f"Device serial={info.serial} firmware={info.version}")
    with closing(device.open_connection(FidoConnection)) as connection:
        ctap = Ctap2(connection)
        print(f"FIDO versions={','.join(ctap.info.versions)} largeBlob={ctap.info.max_large_blob}")
        assert connection.call(1, b"client-script-check") == b"client-script-check"
    for name, session_type in (("OATH", OathSession), ("PIV", PivSession),
                               ("OpenPGP", OpenPgpSession), ("OTP", YubiOtpSession)):
        with closing(device.open_connection(SmartCardConnection)) as connection:
            session = session_type(connection)
            print(f"{name} version={session.version}")
            if name == "OpenPGP":
                get_openpgp_info(session)  # Exercise the same parser as `ykman openpgp info`.
            elif name == "OATH":
                if session.locked:
                    print("OATH is password-locked; credential enumeration requires unlock")
                else:
                    session.list_credentials()
            elif name == "OTP":
                session.get_config_state()
    print("PASS native client discovery, FIDO echo and application information (OTP over PC/SC)")


if __name__ in ("__main__", "builtins"):
    # ykman 5.9 executes scripts with __name__ inherited as "builtins".
    main()
