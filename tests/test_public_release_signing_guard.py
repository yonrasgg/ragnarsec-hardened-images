import os
from pathlib import Path
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
GUARD = ROOT / "tools" / "release_signing_guard.py"


class ReleaseSigningGuard(unittest.TestCase):
    def test_jenkins_checks_before_enabling_publication_or_accessing_registry(self):
        publish = (ROOT / "Jenkinsfile").read_text().split("stage('Publish')", 1)[1]
        guard = publish.index("python3 tools/release_signing_guard.py")
        for later in ("PUBLICATION_ENABLED=true", "docker login", "tools/image_ci.py publish"):
            self.assertLess(guard, publish.index(later))

    def test_guard_accepts_the_approved_key_and_rejects_another(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "tools").mkdir()
            script = root / "tools" / GUARD.name
            script.write_bytes(GUARD.read_bytes())
            (root / "cosign.pub").write_text("approved\n")
            key = root / "test-key"
            key.touch()
            cosign = root / "cosign"
            cosign.write_text('#!/bin/sh\n[ "$1" = public-key ] || exit 2\nprintf "%s\\n" "$FAKE_PUBLIC" > "$5"\n')
            cosign.chmod(0o700)
            env = dict(os.environ, PATH=f"{root}:{os.environ['PATH']}", COSIGN_KEY=str(key))
            for material, success in (("approved", True), ("other", False)):
                with self.subTest(success=success):
                    result = subprocess.run([os.sys.executable, str(script)],
                                            env=dict(env, FAKE_PUBLIC=material),
                                            capture_output=True, text=True)
                    self.assertEqual(result.returncode == 0, success)
                    if not success:
                        self.assertEqual(result.stdout, "")
                        self.assertIn("signing-key-does-not-match", result.stderr)
