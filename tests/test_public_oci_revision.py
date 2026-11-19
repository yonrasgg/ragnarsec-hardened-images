"""Bind image metadata to the commit actually checked out by Jenkins."""

import os
from pathlib import Path
import sys
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
import image_ci


class OciRevision(unittest.TestCase):
    def test_jenkins_exports_checked_out_sha_before_native_validation(self):
        stage = (ROOT / "Jenkinsfile").read_text().split("stage('Plan and validate')", 1)[1]
        stage = stage.split("stage('Publish')", 1)[0]
        self.assertLess(stage.index('export GIT_COMMIT="$(git rev-parse --verify HEAD)"'),
                        stage.index("tools/image_ci.py validate"))

    def test_docker_build_argument_carries_jenkins_revision(self):
        sha = "f1fc38f858ca8c2bd2afbe320e6488b2958468bc"
        with patch.dict(os.environ, {"GIT_COMMIT": sha, "GITHUB_SHA": "different"}, clear=True):
            args = image_ci._build_args({"dockerfile": "base/Dockerfile", "context": "base"},
                                        "test", "linux/amd64")
        self.assertIn("VCS_REF=" + sha, args)
