#!/usr/bin/env python3
"""Install only checksum-pinned public CI tools into a new temporary directory."""
import argparse
import hashlib
import io
import json
from pathlib import Path
import tarfile
import urllib.request


def payload(data, pin):
    if hashlib.sha256(data).hexdigest() != pin['sha256']:
        raise ValueError('tool-checksum-mismatch')
    if 'member' not in pin:
        return data
    with tarfile.open(fileobj=io.BytesIO(data), mode='r:gz') as archive:
        member = archive.getmember(pin['member'])
        if not member.isfile() or member.size > 250 * 1024 * 1024:
            raise ValueError('unexpected-tool-member')
        return archive.extractfile(member).read()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('directory', type=Path)
    args = parser.parse_args()
    args.directory.mkdir(mode=0o700, exist_ok=False)
    pins = json.loads(Path(__file__).with_name('ci-tools.json').read_text())
    for name, pin in pins.items():
        if not pin['url'].startswith('https://github.com/') or '/releases/download/' not in pin['url']:
            raise ValueError('non-release-download')
        with urllib.request.urlopen(pin['url'], timeout=60) as response:
            data = response.read(250 * 1024 * 1024 + 1)
        if len(data) > 250 * 1024 * 1024:
            raise ValueError('tool-size-limit')
        target = args.directory / name
        target.write_bytes(payload(data, pin))
        target.chmod(0o700)
        print(name + ' ' + pin['version'] + ' checksum verified')


if __name__ == '__main__':
    main()
