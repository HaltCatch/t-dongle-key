"""Prevent host signing or stale card stubs from passing board acceptance."""
import importlib.util
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location(
    "check_openpgp_gnupg", Path(__file__).resolve().parents[1] / "tools/check_openpgp_gnupg.py")
checker = importlib.util.module_from_spec(spec)
spec.loader.exec_module(checker)


class CardBindingRegression(unittest.TestCase):
    def test_exact_card_keys_and_false_positive_cases(self):
        serial = "D276000124010304FFFE000000010000"
        fingerprints = [str(index) * 40 for index in (1, 2, 3)]
        rows = []
        agent = [f"S SERIALNO {serial}"]
        for slot, fingerprint in enumerate(fingerprints, 1):
            record = [""] * 18
            record[0] = "sec" if slot == 1 else "ssb"
            record[14] = serial
            record[16] = "cv25519" if slot == 2 else "ed25519"
            rows += [":".join(record), "fpr:::::::::" + fingerprint + ":", "grp:::::::::" + fingerprint + ":"]
            agent += [f"S KEYINFO {fingerprint} T {serial} OPENPGP.{slot} - - - - A"]
        rows, agent = "\n".join(rows), "\n".join(agent)
        checker.check_bindings(rows, agent, serial, fingerprints)
        p384_rows = rows.replace("ed25519", "nistp384").replace("cv25519", "nistp384")
        checker.check_bindings(p384_rows, agent, serial, fingerprints, ("nistp384",) * 3)
        with self.assertRaises(RuntimeError):
            checker.check_bindings(p384_rows, agent, serial, fingerprints)
        with self.assertRaises(RuntimeError):
            checker.check_bindings(rows, agent, serial, fingerprints, ("nistp384",) * 3)
        cases = {
            # Three card stubs still exist, but the requested signing key is local.
            "local signing key": (rows.replace(serial, "+", 1), agent),
            "stale unrelated key": (rows, agent.replace("S KEYINFO " + fingerprints[0], "S KEYINFO " + "F" * 40)),
            "wrong slot": (rows, agent.replace("OPENPGP.1", "OPENPGP.3")),
            "wrong connected card": (rows, agent.replace("S SERIALNO " + serial, "S SERIALNO OTHER")),
            "missing binding": (rows, "\n".join(agent.splitlines()[:-1])),
            "connection failure": (rows, "ERR 100696144 Operation not supported\n" + agent),
        }
        for name, (candidate_rows, candidate_agent) in cases.items():
            with self.subTest(case=name), self.assertRaises(RuntimeError):
                checker.check_bindings(candidate_rows, candidate_agent, serial, fingerprints)


if __name__ == "__main__":
    unittest.main()
