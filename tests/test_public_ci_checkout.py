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
        entry = re.search(
            r"stages\s*\{\s*stage\('Checkout SCM'\)\s*\{\s*steps\s*\{\s*"
            r"checkout scm\s*\}\s*\}\s*stage\('Provenance'\)",
            pipeline,
        )
        self.assertIsNotNone(entry)

    def test_20261119_staging_sync_pins_route_and_single_parent(self):
        pipeline = (Path(__file__).resolve().parents[1] / "Jenkinsfile").read_text()
        branch = 'elif [ "$source" = "sync/development-to-staging-node-exporter-entrypoint-20261119" ]; then'
        self.assertEqual(pipeline.count(branch), 1)
        lane = pipeline.split(branch, 1)[1].split("\n                else", 1)[0]
        self.assertIn("staging_tip=96e2cba1a818751d827ddda9397b8f14995c2c91", lane)
        self.assertIn('require_one_time_sync "$head" staging "$staging_tip" development', lane)
        self.assertIn(
            'test "$(git rev-list --parents -n 1 "$head")" = "$head $staging_tip"',
            lane,
        )
        self.assertIn('exit 2', lane)

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
