"""The networking test entrypoints must fail before touching a shared runtime."""

import os
from pathlib import Path
import subprocess
import sys
import unittest


class IsolationGate(unittest.TestCase):
    def test_direct_lab_entrypoints_fail_closed(self):
        if Path("/run/eivro-test-isolated").exists():
            self.skipTest("This runner already has an isolated runtime")
        here = Path(__file__).parent
        net = os.readlink("/proc/self/ns/net")
        mount = os.readlink("/proc/self/ns/mnt")
        for script, args in [
            ("network_lab.py", [net]),
            ("domain_dns_lab.py", [net, "direct"]),
            ("domain_dns_helper_lab.py", [net, mount]),
        ]:
            with self.subTest(script=script):
                result = subprocess.run(
                    [sys.executable, str(here / script), "lab", *args],
                    capture_output=True,
                    text=True,
                    timeout=5,
                )
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("private /run is required", result.stderr)
                self.assertEqual(result.stdout, "")


if __name__ == "__main__":
    unittest.main()
