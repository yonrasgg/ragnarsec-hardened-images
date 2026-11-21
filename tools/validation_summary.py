"""Human-gate summary for one validation run.

Reads the receipts ``image_ci.py validate`` writes (``validated.json`` + CycloneDX SBOMs)
and the captured stage log, and renders a deterministic ``summary.md`` / ``summary.json``
for the promotion PR. The summary is what the reviewer reads before merging to
staging/main; it never decides anything by itself.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[1]
_LAYER_BYTES = re.compile(r'^IMAGE_LAYER_BYTES (\S+) (\S+) (\d+)$', re.M)
_POLICY_WARN = re.compile(r'^POLICY_WARN (\S+) (.+)$', re.M)
_TRIVY_TOTAL = re.compile(r'Total: (\d+) \((?:UNKNOWN: \d+, )?(?:LOW: \d+, )?(?:MEDIUM: \d+, )?HIGH: (\d+), CRITICAL: (\d+)\)')


def sbom_component_count(path):
    """Number of components in a CycloneDX JSON SBOM (0 when unreadable)."""
    try:
        return len(json.loads(path.read_text()).get('components', []))
    except (OSError, ValueError):
        return 0


def parse_log(text):
    """Deterministic facts from the validate stage log."""
    sizes = {(m.group(1), m.group(2)): int(m.group(3)) for m in _LAYER_BYTES.finditer(text)}
    warnings = [{'image': m.group(1), 'problems': m.group(2).split(',')} for m in _POLICY_WARN.finditer(text)]
    totals = [(int(a), int(h), int(c)) for a, h, c in _TRIVY_TOTAL.findall(text)]
    high = sum(t[1] for t in totals)
    critical = sum(t[2] for t in totals)
    return {'layer_bytes': sizes, 'policy_warnings': warnings,
            'trivy_tables': len(totals), 'trivy_high': high, 'trivy_critical': critical}


def budget_for(name, budgets):
    return budgets.get(name)


def build_summary(output, log_text, commit, target, run_url='', budgets=None):
    """Assemble the summary dict from a validation output dir and the stage log."""
    budgets = budgets if budgets is not None else json.loads((ROOT / 'budgets.json').read_text())
    receipts = json.loads((output / 'validated.json').read_text())
    facts = parse_log(log_text)
    rows = []
    for r in receipts:
        sbom = output / r['sbom']
        sbom_ok = sbom.is_file() and hashlib.sha256(sbom.read_bytes()).hexdigest() == r['sbom_sha256']
        size = facts['layer_bytes'].get((r['name'], r['platform']))
        budget = budget_for(r['name'], budgets)
        rows.append({'image': r['name'], 'platform': r['platform'], 'image_id': r['id'],
                     'sbom': r['sbom'], 'sbom_sha256': r['sbom_sha256'], 'sbom_hash_ok': sbom_ok,
                     'sbom_components': sbom_component_count(sbom),
                     'layer_bytes': size, 'budget_bytes': budget,
                     'budget_pct': (round(100 * size / budget, 1) if size and budget else None),
                     'vex': r.get('vex') or r.get('vex_sha256') or None})
    platforms = sorted({r['platform'] for r in rows})
    images = sorted({r['image'] for r in rows})
    return {'commit': commit, 'target': target, 'run_url': run_url,
            'images': images, 'platforms': platforms, 'receipts': len(rows),
            'trivy': {'tables': facts['trivy_tables'], 'high': facts['trivy_high'], 'critical': facts['trivy_critical']},
            'policy_warnings': facts['policy_warnings'],
            'all_sbom_hashes_ok': all(r['sbom_hash_ok'] for r in rows) if rows else False,
            'rows': rows}


def _fmt_bytes(n):
    return '-' if n is None else f'{n / 1048576:.1f} MiB'


def render_markdown(s):
    """Markdown body for the PR comment. Stable ordering; no timestamps."""
    out = [f"## Validation summary - `{s['commit'][:12]}` -> `{s['target']}`", '']
    out.append(f"- Images: {', '.join('`' + i + '`' for i in s['images'])}")
    out.append(f"- Platforms: {', '.join('`' + p + '`' for p in s['platforms'])}  (receipts: {s['receipts']})")
    t = s['trivy']
    out.append(f"- Trivy (HIGH/CRITICAL, vuln+secret+misconfig): **{t['high']} / {t['critical']}** over {t['tables']} result tables")
    out.append(f"- SBOM hashes match receipts: **{'yes' if s['all_sbom_hashes_ok'] else 'NO'}**")
    if s['policy_warnings']:
        out.append('- Dockerfile policy warnings (non-enforced images):')
        for w in s['policy_warnings']:
            out.append(f"  - `{w['image']}`: {', '.join(w['problems'])}")
    else:
        out.append('- Dockerfile policy warnings: none')
    if s['run_url']:
        out.append(f"- Run: {s['run_url']}")
    out += ['', '| Image | Platform | Layers | Budget | SBOM comps | SBOM sha256 |', '|---|---|---|---|---|---|']
    for r in sorted(s['rows'], key=lambda r: (r['image'], r['platform'])):
        budget = '-' if r['budget_bytes'] is None else f"{_fmt_bytes(r['budget_bytes'])} ({r['budget_pct']}%)"
        out.append(f"| `{r['image']}` | `{r['platform']}` | {_fmt_bytes(r['layer_bytes'])} | {budget} | {r['sbom_components']} | `{r['sbom_sha256'][:12]}` |")
    out += ['', '_Reviewer decides. This summary is generated from the validation receipts; it does not merge, publish or waive anything._', '']
    return '\n'.join(out)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True, help='VALIDATION_OUTPUT directory')
    parser.add_argument('--log', type=Path, required=True, help='captured validate stage log')
    parser.add_argument('--commit', required=True)
    parser.add_argument('--target', required=True)
    parser.add_argument('--run-url', default='')
    parser.add_argument('--write', type=Path, help='directory for summary.md + summary.json')
    args = parser.parse_args()
    s = build_summary(args.output, args.log.read_text(errors='replace'), args.commit, args.target, args.run_url)
    md = render_markdown(s)
    if args.write:
        args.write.mkdir(parents=True, exist_ok=True)
        (args.write / 'summary.json').write_text(json.dumps(s, indent=2, sort_keys=True) + '\n')
        (args.write / 'summary.md').write_text(md)
    print(md)


if __name__ == '__main__':
    main()