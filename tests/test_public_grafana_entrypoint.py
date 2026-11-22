"""Grafana must inherit the base init rather than duplicating it in its image history."""
import json
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import image_policy as policy


class GrafanaEntrypoint(unittest.TestCase):
    def instructions(self, name):
        return list(policy._logical_instructions((ROOT / name / 'Dockerfile').read_text()))

    def test_grafana_inherits_exactly_one_tini_entrypoint(self):
        base = [line.removeprefix('ENTRYPOINT ') for line in self.instructions('base')
                if line.startswith('ENTRYPOINT ')]
        self.assertEqual([json.loads(line) for line in base], [['/sbin/tini', '--']])
        self.assertFalse(any(line.startswith('ENTRYPOINT ') for line in self.instructions('grafana')))

    def test_grafana_keeps_the_server_command(self):
        cmds = [json.loads(line.removeprefix('CMD ')) for line in self.instructions('grafana')
                if line.startswith('CMD ')]
        self.assertEqual(cmds, [['grafana', 'server', '--homepath=/usr/share/grafana',
                                 '--config=/etc/grafana.ini', 'cfg:default.paths.data=/var/lib/grafana',
                                 'cfg:default.paths.logs=/var/log/grafana']])
