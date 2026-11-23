from copy import deepcopy
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
from development_autosquash import (
    ACTOR, APP, BINDING, BOT, JENKINS, REPO, REPO_ID, SAFE_RULES,
    Blocked, fingerprint, read_plan, squash_once,
)


class DevelopmentAutosquashTests(unittest.TestCase):
    def setUp(self):
        self.head, self.base, self.tree, self.candidate = [c * 40 for c in 'abcd']
        issuer = {'id': ACTOR, 'login': BOT, 'type': 'Bot'}
        self.event = dict(sha=self.head, context=JENKINS, state='success', sender=issuer)
        repo = dict(id=REPO_ID, full_name=REPO)
        pr = dict(number=7, state='open', draft=False, mergeable=True,
                  head=dict(sha=self.head, ref='fix/ready', repo=repo),
                  base=dict(sha=self.base, ref='development', repo=repo),
                  merge_commit_sha=self.candidate)
        self.association = f'commits/{self.head}/pulls?per_page=100'
        self.status = f'commits/{self.head}/statuses?per_page=100'
        self.parent = 'git/ref/heads/development'
        self.branch_rules = 'rules/branches/development'
        self.scope = 'rulesets/99?includes_parents=true'
        url = 'http://127.0.0.1:8080/job/ragnarsec-hardened-images/job/PR-7/3/display/redirect'
        statuses = [
            dict(id=80, state='success', context=JENKINS, target_url=url, creator=issuer),
            dict(id=81, state='success', context=BINDING, target_url=url, creator=issuer,
                 description=f'pr=7;base={self.base};run=3'),
        ]
        rules = [{'type': name} for name in sorted(SAFE_RULES)] + [
            dict(type='required_status_checks', parameters=dict(
                strict_required_status_checks_policy=True,
                required_status_checks=[dict(context=c, integration_id=APP) for c in (JENKINS, BINDING)]))]
        self.data = {
            self.association: [deepcopy(pr)],
            'pulls/7': pr,
            self.parent: dict(object=dict(sha=self.base)),
            'git/ref/heads/fix/ready': dict(object=dict(sha=self.head)),
            f'commits/{self.head}': dict(sha=self.head, parents=[dict(sha=self.base)],
                                        commit=dict(tree=dict(sha=self.tree),
                                                    verification=dict(verified=True, reason='valid'))),
            f'git/commits/{self.candidate}': dict(sha=self.candidate, tree=dict(sha=self.tree),
                                                 parents=[dict(sha=self.base), dict(sha=self.head)]),
            'commits/' + 'f'*40: dict(sha='f'*40, parents=[dict(sha=self.base)],
                                      commit=dict(tree=dict(sha=self.tree),
                                                  verification=dict(verified=True, reason='valid'))),
            self.branch_rules: rules,
            self.status: statuses,
            'rulesets?includes_parents=true&targets=branch&per_page=100':
                [dict(id=99, enforcement='active', target='branch')],
            self.scope: dict(id=99, enforcement='active', target='branch',
                             conditions=dict(ref_name=dict(include=['~ALL'], exclude=['refs/heads/development'])),
                             rules=[dict(type='update')], bypass_actors=[dict(actor_type='Team')]),
        }
        self.writes = []

    def get(self, path):
        return deepcopy(self.data[path])

    def put(self, path, body):
        self.writes.append((path, body))
        return dict(merged=True, sha='f' * 40)

    def test_one_ordinary_squash_uses_expected_head_and_no_bypass(self):
        preflight = read_plan(self.get, self.event)
        self.assertEqual(self.writes, [])
        plan, commit = squash_once(self.get, self.put, self.event, fingerprint(preflight))
        self.assertEqual(self.writes, [('pulls/7/merge', {'sha': self.head, 'merge_method': 'squash'})])
        self.assertEqual(plan, preflight)
        self.assertEqual(commit, 'f' * 40)

    def test_github_must_strictly_enforce_both_checks_by_the_same_app(self):
        rules = self.data[self.branch_rules][-1]['parameters']
        for status, app in ((False, APP), (True, 99)):
            with self.subTest(strict=status, app=app):
                rules['strict_required_status_checks_policy'] = status
                rules['required_status_checks'][1]['integration_id'] = app
                with self.assertRaisesRegex(Blocked, 'github-does-not-enforce'):
                    read_plan(self.get, self.event)

    def test_no_staging_main_or_fork_automation(self):
        all_prs = self.data[self.association]
        for ref in ('staging', 'main'):
            with self.subTest(ref=ref):
                all_prs[0]['base']['ref'] = ref
                with self.assertRaisesRegex(Blocked, 'no-unique-fix-to-development'):
                    read_plan(self.get, self.event)
        all_prs[0]['base']['ref'] = 'development'
        all_prs[0]['head']['repo']['id'] += 1
        with self.assertRaisesRegex(Blocked, 'no-unique-fix-to-development'):
            read_plan(self.get, self.event)

    def test_existing_generic_green_is_never_enough(self):
        del self.data[self.status][1]
        with self.assertRaisesRegex(Blocked, 'missing-jenkins-check'):
            read_plan(self.get, self.event)

    def test_stale_base_or_different_run_not_accepted(self):
        binding = self.data[self.status][1]
        binding['description'] = f"pr=7;base={'8'*40};run=3"
        with self.assertRaisesRegex(Blocked, 'jenkins-base-not-attested'):
            read_plan(self.get, self.event)
        binding['target_url'] = binding['target_url'].replace('/3/', '/4/')
        with self.assertRaisesRegex(Blocked, 'jenkins-run-mismatch'):
            read_plan(self.get, self.event)

    def test_later_pending_or_forged_status_invalidates_old_green(self):
        for change in (dict(state='pending'), dict(creator=dict(id=1, login=BOT, type='Bot'))):
            with self.subTest(change=change):
                self.data[self.status].append(dict(self.data[self.status][1], id=100, **change))
                with self.assertRaisesRegex(Blocked, 'untrusted-latest-check'):
                    read_plan(self.get, self.event)
                self.data[self.status].pop()

    def test_concurrent_retarget_base_movement_or_status_change_never_calls_put(self):
        changes = (
            ('pulls/7', lambda p: p['base'].update(ref='staging')),
            (self.parent, lambda p: p['object'].update(sha='9' * 40)),
            (self.status, lambda p: p[1].update(id=99)),
        )
        for path, change in changes:
            with self.subTest(path=path):
                intended = fingerprint(read_plan(self.get, self.event))
                original = deepcopy(self.data[path])
                change(self.data[path])
                with self.assertRaises(Blocked):
                    squash_once(self.get, self.put, self.event, intended)
                self.assertEqual(self.writes, [])
                self.data[path] = original

    def test_stop_when_scope_bypass_is_hidden_or_includes_an_integration(self):
        r = self.data[self.scope]
        del r['bypass_actors']
        with self.assertRaisesRegex(Blocked, 'scope-actions-writes'):
            read_plan(self.get, self.event)
        r['bypass_actors'] = [{'actor_type': 'Integration'}]
        with self.assertRaisesRegex(Blocked, 'scope-actions-writes'):
            read_plan(self.get, self.event)

    def test_no_repeat_when_github_refuses_request(self):
        def refused(path, body):
            self.writes.append((path, body))
            return {'merged': False}

        intended = fingerprint(read_plan(self.get, self.event))
        with self.assertRaisesRegex(Blocked, 'squash-not-confirmed'):
            squash_once(self.get, refused, self.event, intended)
        self.assertEqual(len(self.writes), 1)

    def test_squash_is_not_reported_as_verified_if_server_returns_other_tree(self):
        intended = fingerprint(read_plan(self.get, self.event))
        self.data['commits/' + 'f'*40]['commit']['tree']['sha'] = 'e'*40
        with self.assertRaisesRegex(Blocked, 'squash-reported-but-signed-result-not-verified'):
            squash_once(self.get, self.put, self.event, intended)
        self.assertEqual(len(self.writes), 1)
