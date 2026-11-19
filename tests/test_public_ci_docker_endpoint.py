"""Offline endpoint and Jenkinsfile integration checks; no real daemon."""
import argparse
import contextlib
import importlib.util
import io
import json
from pathlib import Path
import stat
import types
import unittest
from unittest import mock

ROOT = Path(__file__).parents[1]
HELPER = ROOT / "tools" / "ci_docker_endpoint.py"


class PipelineIntegrationTests(unittest.TestCase):
    def test_existing_pipeline_selects_agent_socket_before_provenance_fetch(self):
        pipeline = (ROOT / "Jenkinsfile").read_text()
        self.assertIn('DOCKER_HOST = "unix://${env.XDG_RUNTIME_DIR}/docker.sock"', pipeline)
        self.assertIn("DOCKER_CONTEXT = ''", pipeline)
        guard = pipeline.index("python3 tools/ci_docker_endpoint.py")
        self.assertLess(pipeline.index("stage('Provenance')"), guard)
        self.assertLess(guard, pipeline.index("git fetch"))
        self.assertIn("python3 tools/ci_docker_endpoint.py --config-only", pipeline)
        self.assertLess(pipeline.index("--config-only"), pipeline.index("docker logout"))
        self.assertTrue(HELPER.is_file())

    def test_existing_contract_stage_includes_endpoint_tests(self):
        pipeline = (ROOT / "Jenkinsfile").read_text()
        self.assertIn("python3 -m unittest discover -s tests -p 'test_public*.py'", pipeline)
        self.assertIn("defaultValue: false", pipeline)
        self.assertIn('if [ "$target" = "development" ]; then', pipeline)
        self.assertIn("input message: 'Publish the validated digests to the registry?'", pipeline)


class EndpointTests(unittest.TestCase):
    def setUp(self):
        spec = importlib.util.spec_from_file_location("endpoint", HELPER)
        self.module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.module)
        self.env = {
            "XDG_RUNTIME_DIR": "/run/user/1001",
            "DOCKER_HOST": "unix:///run/user/1001/docker.sock",
            "DOCKER_CONTEXT": "",
            "WORKSPACE_TMP": "/synthetic/workspace@tmp",
            "DOCKER_CONFIG": "/synthetic/workspace@tmp/ragnarsec-ci/docker-auth",
        }

    def validate(self, env=None, uid=1001):
        return self.module.validate_environment(self.env if env is None else env, uid)

    def test_valid_endpoint_is_explicit_and_uid_bound(self):
        self.assertEqual(self.validate(), "/run/user/1001/docker.sock")

    def test_root_missing_runtime_and_other_uid_are_rejected(self):
        with self.assertRaises(ValueError):
            self.validate(uid=0)
        for runtime in ("", "/run/user/1000", "/tmp/runtime", "/run/user/1001/../1000"):
            with self.subTest(runtime=runtime), self.assertRaises(ValueError):
                self.validate(dict(self.env, XDG_RUNTIME_DIR=runtime))

    def test_remote_app_and_rootful_hosts_are_rejected(self):
        for host in ("", "tcp://example.invalid:2375", "ssh://example.invalid",
                     "unix:///run/user/1000/docker.sock", "unix:///run/docker.sock"):
            with self.subTest(host=host), self.assertRaises(ValueError):
                self.validate(dict(self.env, DOCKER_HOST=host))

    def test_context_tls_api_and_builder_overrides_are_rejected(self):
        for key in ("DOCKER_CONTEXT", "DOCKER_TLS", "DOCKER_TLS_VERIFY",
                    "DOCKER_CERT_PATH", "DOCKER_API_VERSION", "BUILDX_CONFIG"):
            with self.subTest(key=key), self.assertRaises(ValueError):
                self.validate(dict(self.env, **{key: "unexpected"}))
        with self.assertRaises(ValueError):
            self.validate(dict(self.env, BUILDX_BUILDER="remote"))
        self.validate(dict(self.env, BUILDX_BUILDER="default"))

    def test_home_or_nonisolated_config_is_rejected(self):
        for config in ("", "/home/synthetic/.docker", "/tmp/docker"):
            with self.subTest(config=config), self.assertRaises(ValueError):
                self.validate(dict(self.env, DOCKER_CONFIG=config))
        with self.assertRaises(ValueError):
            self.validate(dict(self.env, WORKSPACE_TMP="relative"))

    def test_missing_or_symlinked_runtime_is_rejected(self):
        with mock.patch.object(Path, "lstat", side_effect=FileNotFoundError()):
            with self.assertRaises(OSError):
                self.module.validate_filesystem(self.env, 1001)
        item = types.SimpleNamespace(st_mode=stat.S_IFLNK | 0o777, st_uid=1001)
        with mock.patch.object(Path, "lstat", return_value=item):
            with self.assertRaises(ValueError):
                self.module.validate_filesystem(self.env, 1001)

    def test_existing_docker_config_is_not_read_or_reused(self):
        with mock.patch.object(self.module, "no_symlinks"), \
                mock.patch.object(Path, "lstat", return_value=types.SimpleNamespace(
                    st_mode=stat.S_IFDIR | 0o700, st_uid=1001)), \
                mock.patch.object(Path, "exists", return_value=True):
            with self.assertRaisesRegex(ValueError, "fresh"):
                self.module.validate_filesystem(self.env, 1001)

    def test_daemon_response_is_filtered_and_rootless_required(self):
        self.assertEqual(self.module.summarize_info({
            "SecurityOptions": ["name=rootless", "name=seccomp,profile=builtin"],
            "ServerVersion": "synthetic", "private-extra": "not-disclosed"
        }), {"rootless": True, "server_version": "synthetic"})
        with self.assertRaises(ValueError):
            self.module.summarize_info({"SecurityOptions": ["name=seccomp"]})

    def test_http_probe_peer_response_limits_and_closure(self):
        for peer_uid, status_code, payload, passes in [
            (1001, 200, b'{"SecurityOptions":["name=rootless"],"ServerVersion":"test"}', True),
            (1000, 200, b'{}', False),
            (1001, 403, b'{}', False),
            (1001, 200, b'x' * 262145, False),
            (1001, 200, b'not-json', False),
            (1001, 200, b'{}', False)
        ]:
            connection = mock.Mock()
            connection.peer_uid = peer_uid
            response = connection.getresponse.return_value
            response.status = status_code
            response.read.return_value = payload
            with mock.patch.object(self.module, "OwnSocketHTTP", return_value=connection):
                if passes:
                    self.assertTrue(self.module.probe("/synthetic/socket", 1001)["rootless"])
                else:
                    with self.assertRaises((ValueError, json.JSONDecodeError)):
                        self.module.probe("/synthetic/socket", 1001)
                connection.close.assert_called_once()

    def test_filesystem_positive_and_private_post_config(self):
        def metadata(path):
            is_socket = str(path).endswith("/docker.sock")
            return types.SimpleNamespace(
                st_mode=(stat.S_IFSOCK | 0o660) if is_socket else (stat.S_IFDIR | 0o700),
                st_uid=1001)
        with mock.patch.object(self.module, "no_symlinks"), \
                mock.patch.object(Path, "lstat", metadata), \
                mock.patch.object(Path, "exists", return_value=False):
            self.module.validate_filesystem(self.env, 1001)
        with mock.patch.object(self.module, "no_symlinks"), \
                mock.patch.object(Path, "lstat", metadata), \
                mock.patch.object(Path, "exists", return_value=True):
            self.module.validate_filesystem(self.env, 1001, require_fresh=False)

    def test_filesystem_wrong_runtime_owner_and_socket_type(self):
        for mode, owner in ((stat.S_IFDIR | 0o755, 1001),
                            (stat.S_IFDIR | 0o700, 1000)):
            with mock.patch.object(self.module, "no_symlinks"), \
                    mock.patch.object(Path, "lstat", return_value=types.SimpleNamespace(
                        st_mode=mode, st_uid=owner)):
                with self.assertRaises(ValueError):
                    self.module.validate_filesystem(self.env, 1001)
        def wrong_socket(path):
            return types.SimpleNamespace(st_mode=stat.S_IFDIR | 0o700, st_uid=1001)
        with mock.patch.object(self.module, "no_symlinks"), \
                mock.patch.object(Path, "exists", return_value=False), \
                mock.patch.object(Path, "lstat", wrong_socket):
            with self.assertRaisesRegex(ValueError, "socket-owner"):
                self.module.validate_filesystem(self.env, 1001)

    def test_socket_connection_peer_and_cleanup_with_fake_socket(self):
        for uid, passed in ((1001, True), (1000, False)):
            sock = mock.Mock()
            sock.getsockopt.return_value = self.module.struct.pack("3i", 123, uid, uid)
            with mock.patch.object(self.module.socket, "socket", return_value=sock):
                connection = self.module.OwnSocketHTTP("/synthetic/socket", 1001)
                if passed:
                    connection.connect()
                    self.assertEqual(connection.peer_uid, 1001)
                    connection.close()
                else:
                    with self.assertRaises(ValueError):
                        connection.connect()
                    sock.close.assert_called_once()

    def test_main_normal_and_post_config_modes(self):
        for config_only in (False, True):
            with mock.patch.dict(self.module.os.environ, self.env, clear=True), \
                    mock.patch.object(self.module.os, "geteuid", return_value=1001), \
                    mock.patch.object(argparse.ArgumentParser, "parse_args",
                                      return_value=types.SimpleNamespace(config_only=config_only)), \
                    mock.patch.object(self.module, "validate_filesystem") as fs, \
                    mock.patch.object(self.module, "probe", return_value={"rootless": True}) as probe, \
                    contextlib.redirect_stdout(io.StringIO()):
                self.module.main()
                fs.assert_called_once_with(
                    self.module.os.environ, 1001, require_fresh=not config_only)
                self.assertEqual(probe.call_count, 0 if config_only else 1)


if __name__ == "__main__":
    unittest.main()
