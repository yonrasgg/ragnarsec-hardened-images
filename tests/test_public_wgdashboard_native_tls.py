"""Structure contract for the O1 native-HTTPS WGDashboard image.

Byte/structure assertions only: they are not a claim that an image built and
ran. The reviewed inputs are pinned so a later edit cannot silently reintroduce
diagnostic overlays, plaintext HTTP or a PID-file healthcheck.

The Dockerfile wiring lands in the staging reconciliation PR (the development
tree and the already-promoted staging tree share a divergent squash history,
so a fix PR that edits that path fails the protected-route simulation). The
Dockerfile-dependent assertions therefore activate only once the O1 marker is
present in the checked-out Dockerfile.
"""
import hashlib
import unittest
from pathlib import Path

ROOT = Path(__file__).parents[1]
WGD = ROOT / "wgdashboard"
O1_MARKER = "O1 native HTTPS"
O1_WIRED = O1_MARKER in (WGD / "Dockerfile").read_text()

# Exact inputs exercised in the isolated rehearsal recorded in EVD-PRJ-192.
REVIEWED_SOURCES = {
    "dashboard.py": "2127272eb484d323282c524e81f40691487cbbe3660ee4d671519d6e895bec09",
    "readonly_mode.py": "0351bdea64f3f97d935711abf6b041f921f478292fbcac3ff206779d4e1388c9",
    "readonly_preflight.py": "a239b8930add59f96ea7a02b09490b95be1e76bfd3a80c68c65957854f7bb779",
}


class WgdashboardNativeTlsStructureTests(unittest.TestCase):
    def setUp(self):
        self.dockerfile = (WGD / "Dockerfile").read_text()
        self.entrypoint = (WGD / "docker" / "entrypoint.sh").read_text()
        self.healthcheck = (WGD / "docker" / "healthcheck.sh").read_text()

    def test_reviewed_guard_sources_are_pinned(self):
        for name, digest in REVIEWED_SOURCES.items():
            path = WGD / "src" / name
            self.assertTrue(path.is_file(), name)
            self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(), digest, name)

    def test_no_key_material_in_build_context(self):
        for path in WGD.rglob("*"):
            if path.is_file() and path.suffix in {".key", ".pem", ".crt", ".p12"}:
                self.fail(f"key material in build context: {path}")

    def test_entrypoint_is_fail_closed_and_binds_native_tls(self):
        self.assertIn("/run/secrets/wgdashboard", self.entrypoint)
        self.assertIn("readonly_preflight.py", self.entrypoint)
        self.assertIn("--no-control-socket", self.entrypoint)
        self.assertIn("--bind 0.0.0.0:10086", self.entrypoint)
        self.assertIn("--keyfile", self.entrypoint)
        self.assertIn("--certfile", self.entrypoint)
        self.assertIn("dashboard:app", self.entrypoint)

    def test_healthcheck_script_is_real_https_probe(self):
        self.assertIn("/api/handshake", self.healthcheck)
        self.assertIn("--proto '=https'", self.healthcheck)
        self.assertIn("--cacert", self.healthcheck)
        self.assertIn("--connect-to", self.healthcheck)
        self.assertIn('test "$status" = 200', self.healthcheck)

    @unittest.skipUnless(O1_WIRED, "Dockerfile wiring is promoted from staging")
    def test_base_is_pinned_multi_arch_digest_without_go_rebuild(self):
        self.assertIn(
            "ghcr.io/wgdashboard/wgdashboard@sha256:"
            "8c5b550db4fda04eff06e96af801499be485c73e0912fcf0c1031babca0f7e7b",
            self.dockerfile,
        )
        instructions = "\n".join(
            line for line in self.dockerfile.splitlines()
            if line.strip() and not line.lstrip().startswith("#")
        )
        self.assertNotIn("go build", instructions)
        self.assertNotIn("GOPROXY", instructions)
        self.assertNotIn("proxy.golang.org", instructions)

    @unittest.skipUnless(O1_WIRED, "Dockerfile wiring is promoted from staging")
    def test_reviewed_guard_sources_are_canonical_image_content(self):
        for name in REVIEWED_SOURCES:
            self.assertIn(f"COPY --chown=1000:1000 --chmod=0444 src/{name} /opt/wgdashboard/src/{name}",
                          self.dockerfile)

    @unittest.skipUnless(O1_WIRED, "Dockerfile wiring is promoted from staging")
    def test_image_runs_unprivileged_and_exposes_only_tls_port(self):
        self.assertIn("USER 1000:1000", self.dockerfile)
        self.assertIn("EXPOSE 10086", self.dockerfile)

    @unittest.skipUnless(O1_WIRED, "Dockerfile wiring is promoted from staging")
    def test_healthcheck_is_real_https_probe_not_pid_stub(self):
        self.assertIn('HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3',
                      self.dockerfile)
        self.assertIn('CMD ["/usr/local/bin/wgdashboard-healthcheck"]', self.dockerfile)
        self.assertNotIn("gunicorn.pid", self.dockerfile)
        self.assertIn("COPY --chown=1000:1000 --chmod=0555 docker/healthcheck.sh "
                      "/usr/local/bin/wgdashboard-healthcheck", self.dockerfile)

    @unittest.skipUnless(O1_WIRED, "Dockerfile wiring is promoted from staging")
    def test_entrypoint_copy_and_runtime_tls_environment_are_explicit(self):
        self.assertIn("COPY --chown=1000:1000 --chmod=0555 docker/entrypoint.sh /entrypoint.sh",
                      self.dockerfile)
        for value in (
            "WG_DASHBOARD_READ_ONLY=1",
            "WG_DASHBOARD_BACKEND_TLS_NAME=wgdashboard-backend.svc.ragnarsec.com",
            "WG_DASHBOARD_BACKEND_CA_FILE=/run/secrets/wgdashboard/ca.crt",
            "WG_DASHBOARD_BACKEND_CERT_FILE=/run/secrets/wgdashboard/server.crt",
            "WG_DASHBOARD_BACKEND_KEY_FILE=/run/secrets/wgdashboard/server.key",
            "PYTHONDONTWRITEBYTECODE=1",
        ):
            self.assertIn(value, self.dockerfile)


if __name__ == "__main__":
    unittest.main()
