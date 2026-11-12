import os
from pathlib import Path
import subprocess
import unittest

ROOT = Path(__file__).resolve().parents[1]

PRODUCER = """
import os
import signal
import sys
signal.signal(signal.SIGPIPE, signal.SIG_DFL)
tree = os.environ['TEST_TREE']
first = tree if os.environ['TEST_MATCH'] == 'yes' else '0' * 40
sys.stdout.write(first + chr(10))
sys.stdout.write(('f' * 40 + chr(10)) * 100000)
sys.stdout.flush()
sys.exit(int(os.environ['TEST_PRODUCER_RC']))
"""


class ProvenancePipefail(unittest.TestCase):
    def condition(self):
        lines = (ROOT / 'Jenkinsfile').read_text().splitlines()
        matches = [
            line.strip() for line in lines
            if 'if git log ' in line and '$tree' in line
        ]
        self.assertEqual(len(matches), 1)
        return matches[0].removeprefix('if ').removesuffix('; then')

    def run_condition(self, condition, match=True, producer_rc=0):
        env = os.environ.copy()
        env.update({
            'TEST_TREE': 'a' * 40,
            'TEST_MATCH': 'yes' if match else 'no',
            'TEST_PRODUCER_RC': str(producer_rc),
            'TEST_PRODUCER': PRODUCER,
        })
        script = """
set -o pipefail
branch=staging
tree="$TEST_TREE"
git() { python3 -c "$TEST_PRODUCER"; }
""" + condition
        return subprocess.run(
            ['bash', '-c', script],
            env=env, capture_output=True, text=True, timeout=15,
        )

    def test_long_matching_history_is_accepted(self):
        result = self.run_condition(self.condition())
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_nonmatching_history_is_rejected(self):
        result = self.run_condition(self.condition(), match=False)
        self.assertEqual(result.returncode, 1, result.stderr)

    def test_producer_failure_is_not_hidden_by_match(self):
        result = self.run_condition(self.condition(), producer_rc=37)
        self.assertEqual(result.returncode, 37, result.stderr)

    def test_original_quiet_grep_reproduces_sigpipe(self):
        original = self.condition().replace(
            'grep -x "$tree" >/dev/null', 'grep -qx "$tree"', 1
        )
        self.assertNotEqual(original, self.condition())
        result = self.run_condition(original)
        self.assertEqual(result.returncode, 141, result.stderr)


if __name__ == '__main__':
    unittest.main()
