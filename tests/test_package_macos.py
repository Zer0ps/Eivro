"""Exercise local staging and atomic publication without creating real disk images."""
import contextlib
import importlib.util
import io
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock

spec = importlib.util.spec_from_file_location('package_macos', Path(__file__).resolve().parents[1] / 'scripts/package-macos.py')
package = importlib.util.module_from_spec(spec)
spec.loader.exec_module(package)


class DiskImagesTests(unittest.TestCase):
    def exercise(self, errors):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / 'source'
            source.mkdir()
            (source / 'test.pkg').write_bytes(b'fixture')
            final = root / 'dist/Eivro.dmg'
            final.parent.mkdir()
            final.write_bytes(b'previous published image')
            stages = []

            def create(command, **kwargs):
                payload = Path(command[command.index('-srcfolder') + 1])
                image = Path(command[-1])
                self.assertEqual(kwargs['env']['LC_ALL'], 'C')
                self.assertEqual((payload / 'test.pkg').read_bytes(), b'fixture')
                self.assertFalse(image.exists())
                self.assertEqual(final.read_bytes(), b'previous published image')
                stages.append(image.parent)
                message = errors[len(stages)-1]
                image.write_bytes(b'partial' if message else b'complete')
                return subprocess.CompletedProcess(command, int(bool(message)), stdout=message)

            with mock.patch.object(package.subprocess, 'run', side_effect=create), \
                    mock.patch.object(package.time, 'sleep') as sleep, contextlib.redirect_stderr(io.StringIO()):
                if errors[-1]:
                    with self.assertRaises(subprocess.CalledProcessError):
                        package.create_dmg(source, final, 80)
                else:
                    package.create_dmg(source, final, 80)
                self.assertEqual(sleep.call_count, len(errors)-1)
            self.assertEqual(len(set(stages)), len(errors))
            self.assertTrue(all(not stage.exists() for stage in stages))
            self.assertEqual(final.read_bytes(), b'previous published image' if errors[-1] else b'complete')

    def test_transient_resource_busy_uses_fresh_attempt_and_publishes_complete_image(self):
        self.exercise(['hdiutil: create failed - Resource busy\n', ''])

    def test_resource_busy_retries_are_bounded(self):
        self.exercise(['hdiutil: create failed - Resource busy\n']*3)

    def test_other_failure_preserves_existing_image_and_is_not_retried(self):
        self.exercise(['hdiutil: create failed - No space left on device\n'])
