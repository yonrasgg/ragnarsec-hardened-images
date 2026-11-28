"""Static contract for the explicit, agent-scoped Jenkins checkout."""
import json
from pathlib import Path
import re
import sys
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
import image_ci


class CheckoutContract(unittest.TestCase):
    def test_explicit_scm_checkout_precedes_provenance(self):
        pipeline = (Path(__file__).resolve().parents[1] / "Jenkinsfile").read_text()
        self.assertRegex(pipeline, r"options\s*\{\s*skipDefaultCheckout\(\)")
        # Control stages share the global agent so skipDefaultCheckout() cannot
        # leave Provenance/Secret scan/Plan on a fresh worker without a checkout.
        entry = re.search(
            r"agent \{ label 'ragnarsec-linux' \}.*?stage\('Control'\)\s*\{\s*stages\s*\{\s*"
            r"stage\('Checkout SCM'\)\s*\{\s*steps\s*\{\s*checkout scm\s*\}\s*\}\s*"
            r"stage\('Provenance'\)",
            pipeline, re.S,
        )
        self.assertIsNotNone(entry)
        control = entry.group(0)
        self.assertEqual(control.count("agent {"), 1)


    def test_enforced_egress_uses_build_proxy_and_single_trivy_registry(self):
        with patch.dict("os.environ", {
            "RAGNARSEC_REQUIRE_STAGE_EGRESS": "1",
            "RAGNARSEC_BUILD_PROXY": "http://198.18.87.1:13128",
        }, clear=True):
            args = image_ci.build_proxy_args()
            for value in ("HTTP_PROXY=http://198.18.87.1:13128",
                          "https_proxy=http://198.18.87.1:13128", "NO_PROXY=", "no_proxy="):
                self.assertIn(value, args)
            self.assertEqual(image_ci.trivy_db_args(),
                             ("--db-repository", "ghcr.io/aquasecurity/trivy-db:2",
                              "--java-db-repository", "ghcr.io/aquasecurity/trivy-java-db:1"))
            self.assertEqual(image_ci.trivy_checks_args(),
                             ("--checks-bundle-repository", "ghcr.io/aquasecurity/trivy-checks:0"))

    def test_image_validation_uses_private_workspace_temp_directory(self):
        pipeline = (ROOT / "Jenkinsfile").read_text()
        self.assertIn('CI_ROOT = "${WORKSPACE_TMP}/ragnarsec-ci"', pipeline)
        self.assertRegex(
            pipeline,
            r'validation_tmp="\$\(mktemp -d "\$CI_ROOT/validation-tmp\.XXXXXXXX"\)"\s*'
            r'TMPDIR="\$validation_tmp" RAGNARSEC_REQUIRE_STAGE_EGRESS=1 '
            r'python3 tools/image_ci\.py validate',
        )

    def test_node_exporter_pins_its_package_and_enforces_recipe_policy(self):
        recipe = ROOT / "node-exporter" / "Dockerfile"
        self.assertIn("apk add --no-cache prometheus-node-exporter=1.11.1-r0",
                      recipe.read_text())
        self.assertEqual(image_ci.policy.check_dockerfile(recipe), [])
        self.assertIn("ragnarsec-node-exporter", json.loads((ROOT / "policy.json").read_text())["enforce"])

    def test_node_exporter_inherits_the_only_entrypoint(self):
        base = (ROOT / "base" / "Dockerfile").read_text()
        child = (ROOT / "node-exporter" / "Dockerfile").read_text()
        self.assertEqual(re.findall(r"(?im)^\s*ENTRYPOINT\s+(.+)$", base), ['["/sbin/tini", "--"]'])
        self.assertNotRegex(child, r"(?im)^\s*ENTRYPOINT\s+")
        self.assertRegex(child, r'(?m)^CMD \["node_exporter"\]$')

    def test_enforced_egress_rejects_absent_or_unsafe_build_proxy(self):
        for proxy in ("", "http://127.0.0.1:13128", "http://8.8.8.8:13128",
                      "http://name:13128", "http://user@198.18.87.1:13128"):
            with self.subTest(proxy=proxy), patch.dict("os.environ", {
                "RAGNARSEC_REQUIRE_STAGE_EGRESS": "1", "RAGNARSEC_BUILD_PROXY": proxy,
            }, clear=True):
                with self.assertRaisesRegex(ValueError, "build-proxy"):
                    image_ci.build_proxy_args()
