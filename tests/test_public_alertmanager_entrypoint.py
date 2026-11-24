"""Alertmanager must inherit the base init without changing its server command."""
import json
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import image_policy as policy


class AlertmanagerEntrypoint(unittest.TestCase):
    def instructions(self, name):
        return list(policy._logical_instructions((ROOT / name / 'Dockerfile').read_text()))

    def test_alertmanager_inherits_exactly_one_tini_entrypoint(self):
        base = [json.loads(line.removeprefix('ENTRYPOINT ')) for line in self.instructions('base')
                if line.startswith('ENTRYPOINT ')]
        self.assertEqual(base, [['/sbin/tini', '--']])
        self.assertFalse(any(line.startswith('ENTRYPOINT ') for line in self.instructions('alertmanager')))

    def test_alertmanager_keeps_the_server_command(self):
        commands = [json.loads(line.removeprefix('CMD ')) for line in self.instructions('alertmanager')
                    if line.startswith('CMD ')]
        self.assertEqual(commands, [['alertmanager', '--config.file=/etc/alertmanager/alertmanager.yml',
                                     '--storage.path=/var/lib/alertmanager']])
