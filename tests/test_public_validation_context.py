"""The promotion collector must be able to identify the actual Jenkins inputs."""
from contextlib import redirect_stderr
import io
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import validation_context as ctx


class ValidationContext(unittest.TestCase):
    def setUp(self):
        self.inputs = dict(pull_request=150, head_sha='a' * 40, base_sha='b' * 40,
                           target='development', image='ragnarsec-base-min',
                           build_number=1, publish_requested=False)

    def test_context_binds_exact_plan_inputs_without_claiming_success(self):
        self.assertEqual(ctx.build_context(**self.inputs), {
            **self.inputs, 'schema_version': 1, 'kind': 'jenkins-plan-inputs',
        })

    def test_rejects_invalid_or_unpinned_inputs(self):
        for key, invalid in (
            ('pull_request', 0), ('pull_request', True), ('head_sha', 'HEAD'),
            ('base_sha', 'origin/main'), ('base_sha', 'b' * 39), ('target', 'unreviewed'),
            ('image', '../base'), ('build_number', False), ('build_number', -1),
            ('publish_requested', 'false'), ('publish_requested', 0),
        ):
            with self.subTest(key=key, invalid=invalid):
                with self.assertRaises(ValueError):
                    ctx.build_context(**dict(self.inputs, **{key: invalid}))

    def test_publish_requested_is_captured_not_hidden(self):
        self.assertIs(ctx.build_context(**dict(self.inputs, publish_requested=True))['publish_requested'],
                      True)

    def test_cli_writes_only_a_new_artifact(self):
        with tempfile.TemporaryDirectory() as tmp:
            artifact = Path(tmp) / 'validation-context.json'
            args = [sys.executable, str(ROOT / 'tools/validation_context.py'), '--write', str(artifact),
                    '--pull-request', '150', '--head-sha', 'a' * 40, '--base-sha', 'b' * 40,
                    '--target', 'development', '--image', 'ragnarsec-base-min', '--build-number', '1',
                    '--publish-requested', 'false']
            first = subprocess.run(args, capture_output=True, text=True, check=True)
            self.assertEqual(first.stdout, '')
            self.assertEqual(json.loads(artifact.read_text()), ctx.build_context(**self.inputs))
            before = artifact.read_bytes()
            args[args.index('--base-sha') + 1] = 'c' * 40
            second = subprocess.run(args, capture_output=True, text=True)
            self.assertNotEqual(second.returncode, 0)
            self.assertEqual(artifact.read_bytes(), before)

    def test_cli_captures_true_and_rejects_an_unpinned_base_before_writing(self):
        with tempfile.TemporaryDirectory() as tmp:
            artifact = Path(tmp) / 'validation-context.json'
            args = ['validation_context.py', '--write', str(artifact), '--pull-request', '150',
                    '--head-sha', 'a' * 40, '--base-sha', 'origin/main', '--target', 'main',
                    '--image', 'ragnarsec-prometheus', '--build-number', '1',
                    '--publish-requested', 'true']
            with patch.object(sys, 'argv', args), redirect_stderr(io.StringIO()) as output:
                with self.assertRaises(SystemExit) as stop:
                    ctx.main()
            self.assertEqual(stop.exception.code, 2)
            self.assertIn('invalid-plan-revision', output.getvalue())
            self.assertFalse(artifact.exists())
            args[args.index('--base-sha') + 1] = 'b' * 40
            with patch.object(sys, 'argv', args):
                ctx.main()
            self.assertIs(json.loads(artifact.read_text())['publish_requested'], True)

    def test_selector_freezes_revisions_and_pipeline_archives_the_input_record(self):
        source = (ROOT / 'Jenkinsfile').read_text()
        plan = (ROOT / 'tools/image_ci.py').read_text()
        self.assertIn('capture_plan_inputs(args.image, os.environ)', plan)
        self.assertIn("archiveArtifacts artifacts: 'ci-summary/validation-context.json'", source)
        post = source.split('\n  post {', 1)[1]
        self.assertLess(post.index("archiveArtifacts artifacts: 'ci-summary/validation-context.json'"),
                        post.index('rm -rf "$CI_ROOT"'))

    def test_replanned_image_and_refs_must_match_before_capture(self):
        with tempfile.TemporaryDirectory() as tmp:
            env = dict(CHANGE_TARGET='development', CHANGE_ID='150', BUILD_NUMBER='1',
                       CI_PUBLISH_REQUESTED='false', CI_ROOT=tmp, IMAGE='')
            artifact = Path(tmp) / 'validation-context.json'
            for revisions, image in (
                (['b'*40, 'a'*40, 'c'*40, 'a'*40], 'ragnarsec-base-min'),
                (['b'*40, 'a'*40, 'b'*40, 'a'*40], 'ragnarsec-other'),
            ):
                with patch.object(ctx, 'resolve_revision', side_effect=revisions), \
                        patch('select_image.changed_paths', return_value=['Jenkinsfile']):
                    with self.assertRaisesRegex(ValueError, 'plan-revision-or-image-changed'):
                        ctx.capture_plan_inputs(image, env)
                self.assertFalse(artifact.exists())
            with patch.object(ctx, 'resolve_revision', side_effect=['b'*40, 'a'*40]*2), \
                    patch('select_image.changed_paths', return_value=['Jenkinsfile']) as paths:
                ctx.capture_plan_inputs('ragnarsec-base-min', env)
                paths.assert_called_once_with('b'*40, 'a'*40)
            self.assertEqual(json.loads(artifact.read_text()), ctx.build_context(**self.inputs))


if __name__ == '__main__':
    unittest.main()
