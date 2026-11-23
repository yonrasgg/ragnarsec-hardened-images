"""Offline preflight for protected squash promotions."""
import json


if __name__ == '__main__':
    print(json.dumps({'result': 'error', 'exit_code': 2, 'phases': [],
                      'merge_authorized': False}, sort_keys=True))
    raise SystemExit(2)
