"""Evaluate regression and challenge cases; generate an offline dashboard.

The regression suite is the CI release gate. The challenge suite exposes known
limitations and is diagnostic: it does not fail the project build.
"""

from __future__ import annotations

import base64
import html
import json
from datetime import date
from pathlib import Path

from detector import RULE_CVC, RULE_PAN, analyze_line, group_alerts, load_config

ROOT = Path(__file__).resolve().parent
RULES = (RULE_PAN, RULE_CVC)
EVALUATION_DAY = date(2026, 10, 20)


def safe(value: object) -> str:
    return html.escape(str(value), quote=True)


def evaluate(cases: list[dict], config: dict, suite: str) -> tuple[dict, list[dict], list[dict]]:
    counts = {rule: {k: 0 for k in ('tp', 'fp', 'fn', 'tn')} for rule in RULES}
    findings: list[dict] = []
    case_results: list[dict] = []
    for case in cases:
        alerts = analyze_line(case['log'], service=case['service'], config=config, today=EVALUATION_DAY)
        actual = {a['rule_id'] for a in alerts}
        expected = set(case['expected_rule_ids'])
        for rule in RULES:
            if rule in actual:
                key = 'tp' if rule in expected else 'fp'
            else:
                key = 'fn' if rule in expected else 'tn'
            counts[rule][key] += 1
        findings.extend({'case_id': case['id'], **a} for a in alerts)
        case_results.append({
            'case_id': case['id'], 'suite': suite,
            'description': case.get('description', ''),
            'expected': ', '.join(sorted(expected)) or 'None',
            'actual': ', '.join(sorted(actual)) or 'None',
            'status': 'PASS' if expected == actual else 'KNOWN GAP',
            'observation': case.get('observation', ''),
            'future_improvement': case.get('future_improvement', ''),
        })
    return counts, findings, case_results


def combine_counts(left: dict, right: dict) -> dict:
    combined = {}
    for rule in RULES:
        data = {k: left[rule][k] + right[rule][k] for k in ('tp', 'fp', 'fn', 'tn')}
        data['precision'] = round(data['tp'] / (data['tp'] + data['fp']), 4) if data['tp'] + data['fp'] else None
        data['recall'] = round(data['tp'] / (data['tp'] + data['fn']), 4) if data['tp'] + data['fn'] else None
        data['false_positive_rate'] = round(data['fp'] / (data['fp'] + data['tn']), 4) if data['fp'] + data['tn'] else None
        combined[rule] = data
    return combined


def _pct(value: float | None) -> str:
    return f'{value:.1%}' if value is not None else 'n/a'


def _dashboard(metrics: dict, all_alerts: list[dict], base: list[dict], diagnostic: list[dict]) -> str:
    baseline_pass = sum(c['status'] == 'PASS' for c in base)
    diagnostic_pass = sum(c['status'] == 'PASS' for c in diagnostic)
    gaps = [c for c in diagnostic if c['status'] != 'PASS']
    logo_bytes = (ROOT/'assets/littlepay_logo.jpg').read_bytes()
    logo = 'data:image/jpeg;base64,' + base64.b64encode(logo_bytes).decode('ascii')

    def metric(label: str, number: str, detail: str, accent: str = '') -> str:
        return (f'<div class="metric {accent}"><div class="label">{safe(label)}</div>'
                f'<div class="number">{safe(number)}</div><div class="detail">{safe(detail)}</div></div>')

    cards = ''.join([
        metric('Regression Tests', f'{baseline_pass}/{len(base)}', 'Expected outcomes · CI regression suite', 'primary'),
        metric('Additional Scenarios', f'{len(gaps)} gaps / {len(diagnostic)}', 'Known detection limitations · not test failures', 'warning'),
        metric('Detection Findings', str(len(all_alerts)), 'Sanitized findings across both datasets'),
        metric('Detection Rules', '2', 'PAN exposure and CVC detection'),
    ])
    quality = ''.join(
        '<tr><td><strong>' + safe(rule) + '</strong><small>' + ('PAN exposure' if rule == RULE_PAN else 'CVC exposure') + '</small></td>'
        + ''.join(f'<td>{v}</td>' for v in (d['tp'],d['fp'],d['fn'],d['tn']))
        + f'<td class="emph">{_pct(d["precision"])}</td><td class="emph">{_pct(d["recall"])}</td></tr>'
        for rule, d in metrics.items()
    )
    gaps_html = ''.join(
        '<article class="gap"><div class="gap-head"><span class="pill">' + safe(c['case_id']) + '</span><h3>'
        + safe(c['description']) + '</h3></div><p>' + safe(c['observation']) + '</p><div class="next"><strong>Potential improvement</strong> ' + safe(c['future_improvement']) + '</div></article>'
        for c in gaps
    )
    # Mix PASS and KNOWN GAP rows for easier visual comparison. This changes
    # presentation order only, never the source fixtures or evaluation results.
    passing = [c for c in base + diagnostic if c['status'] == 'PASS']
    gaps_for_table = [c for c in base + diagnostic if c['status'] != 'PASS']
    display_cases = []
    last = 0
    for idx, gap_case in enumerate(gaps_for_table, 1):
        until = idx * len(passing) // (len(gaps_for_table) + 1)
        display_cases.extend(passing[last:until])
        display_cases.append(gap_case)
        last = until
    display_cases.extend(passing[last:])

    case_rows = ''.join(
        '<tr><td><b>' + safe(c['case_id']) + '</b></td><td>' + safe(c['suite']) + '</td><td>'
        + safe(c['description'] or ('Supplied/sample regression scenario')) + '</td><td>'
        + safe(c['expected']) + '</td><td>' + safe(c['actual']) + '</td><td><span class="status '
        + ('ok' if c['status'] == 'PASS' else 'gapstatus') + '">' + safe(c['status']) + '</span></td></tr>'
        for c in display_cases
    )
    alert_rows = ''.join(
        '<tr>' + ''.join(f'<td>{safe(a.get(k,""))}</td>' for k in
                           ('case_id','rule_id','severity','service','matched_field','route')) + '</tr>'
        for a in all_alerts
    )
    return f'''<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Littlepay | Detection as Code — Cardholder Data in Logs</title>
<style>

:root {{ font-family: Inter, ui-sans-serif, system-ui, Segoe UI, sans-serif; color:#eaf2ff; background:#0f172a; }}
* {{ box-sizing:border-box; }}
html, body {{ margin:0; background:#0f172a; min-height:100%; }}
.container {{ max-width:1250px; padding:0 26px 65px; margin:auto; }}
.hero {{ color:#f8fbff; background:linear-gradient(115deg,#11233c 0%,#153b51 58%,#126866 100%); overflow:hidden; position:relative; }}
.hero:after {{ content:""; position:absolute; width:440px; height:440px; border-radius:50%; border:75px solid #69ead927; right:-145px; top:-220px; }}
.hero-in {{ max-width:1250px; padding:34px 26px 55px; margin:auto; position:relative; z-index:1; }}
.top {{ display:flex; align-items:center; justify-content:space-between; gap:20px; }}
.eyebrow {{ color:#77e7d0; font-size:12px; font-weight:760; letter-spacing:.12em; text-transform:uppercase; }}
.logo {{ width:138px; height:75px; object-fit:contain; background:#fff; border-radius:12px; padding:12px 14px; box-shadow:0 8px 30px #03101b55; }}
h1 {{ font-size:clamp(32px,4.45vw,50px); margin:26px 0 12px; letter-spacing:-.045em; line-height:1.12; max-width:1040px; }}
.h1-accent {{ color:#7de5cb; }}
.subtitle {{ color:#d1e8ed; font-size:16px; line-height:1.65; max-width:875px; margin:0; }}
.grid {{ display:grid; grid-template-columns:repeat(4,minmax(0,1fr)); gap:15px; margin-top:-26px; position:relative; z-index:2; }}
.metric {{ background:#17243c; padding:23px; border:1px solid #30425f; border-radius:17px; box-shadow:0 10px 26px #040c1e30; min-height:154px; }}
.metric.primary {{ border-top:4px solid #2cbf9f; }} .metric.warning {{ border-top:4px solid #e6ad54; }}
.label {{ color:#a9c0dc; font-size:13px; font-weight:650; }}
.number {{ font-size:32px; font-weight:800; color:#f3f7ff; margin:12px 0 5px; letter-spacing:-.03em; }}
.detail {{ color:#9eb5d3; font-size:12px; line-height:1.5; }}
.panel {{ margin-top:24px; background:#17243c; border:1px solid #2b3d5a; border-radius:18px; overflow:hidden; box-shadow:0 8px 28px #05102528; }}
.panel-header {{ padding:23px 25px 15px; }}
h2 {{ margin:0 0 6px; font-size:20px; color:#f2f7ff; letter-spacing:-.025em; }}
.hint {{ color:#b0c4df; margin:0; font-size:13px; line-height:1.6; }}
.scroll {{ overflow-x:auto; }} table {{ border-collapse:collapse; width:100%; font-size:13px; }}
th {{ background:#21304b; text-align:left; font-size:11px; text-transform:uppercase; letter-spacing:.06em; color:#b7d6e7; }}
td, th {{ padding:15px 20px; border-bottom:1px solid #30425f; white-space:nowrap; }} tr:last-child td {{ border-bottom:0; }}
td {{ color:#e4eefa; }} td small {{ color:#9eb7d3; display:block; margin-top:3px; }} .emph {{ color:#73e3c5; font-weight:750; }}
.gap-grid {{ display:grid; grid-template-columns:repeat(2,minmax(0,1fr)); gap:12px; padding:0 23px 23px; }}
.gap {{ border:1px solid #324761; border-radius:12px; padding:16px; background:#1b2b46; }}
.gap-head {{ display:flex; align-items:center; gap:9px; }} .gap h3 {{ margin:0; font-size:14px; color:#f1f7fd; }}
.pill {{ font-size:11px; color:#ffd59c; background:#5a4025; border-radius:50px; padding:4px 8px; font-weight:800; }}
.gap p {{ color:#bbd0e5; line-height:1.5; font-size:13px; margin:11px 0; }}
.next {{ border-top:1px solid #36506c; padding-top:10px; font-size:12px; color:#b9cee4; line-height:1.55; }} .next strong {{ color:#7ee6c9; display:block; }}
.status {{ border-radius:25px; padding:5px 9px; font-size:11px; font-weight:800; }}
.ok {{ color:#86e2c2; background:#164d47; }} .gapstatus {{ color:#ffce84; background:#5b4025; }}
.safety {{ border-left:4px solid #2fc5a1; background:#193d4c; padding:21px 25px; border-radius:12px; margin-top:24px; }}
.safety h2 {{ font-size:17px; }} .safety ul {{ margin:9px 0 0; padding-left:21px; color:#d0eee6; line-height:1.8; font-size:13px; }}
.safety code {{ color:#a7f2da; }}
.footer {{ margin-top:25px; font-size:12px; color:#a8bfd7; }}
@media(max-width:900px) {{ .grid {{ grid-template-columns:repeat(2,1fr); }} .gap-grid {{ grid-template-columns:1fr; }} }}
@media(max-width:540px) {{ .container {{ padding-left:14px; padding-right:14px; }} .hero-in {{ padding-left:18px; padding-right:18px; }} .grid {{ gap:8px; }} .metric {{ padding:15px; }} .number {{ font-size:24px; }} .eyebrow {{ font-size:10px; }} .logo {{ width:94px; height:56px; }} }}
</style></head><body>
<header class="hero"><div class="hero-in">
  <div class="top"><div class="eyebrow">Security Engineering / Interview Challenge — Local Simulation</div><img class="logo" src="{logo}" alt="Littlepay logo"></div>
  <h1>Detection as Code <span class="h1-accent">— Cardholder Data in Logs</span></h1>
  <p class="subtitle">Finding sensitive card data in application logs, validating detection rules with labelled scenarios, and producing safe alerts that security teams can investigate.</p>
</div></header>
<main class="container"><div class="grid">{cards}</div>
<section class="panel"><div class="panel-header"><h2>Detection quality across all synthetic scenarios</h2>
<p class="hint">Combined regression and challenge datasets ({len(base)+len(diagnostic)} labelled log cases). The challenge set deliberately includes known false positives and missed detections.</p></div>
<div class="scroll"><table><thead><tr><th>Detection</th><th>TP</th><th>FP</th><th>FN</th><th>TN</th><th>Precision</th><th>Recall</th></tr></thead><tbody>{quality}</tbody></table></div></section>
<section class="panel"><div class="panel-header"><h2>What the challenge scenarios revealed</h2>
<p class="hint">Reproducible limitations of the current rule logic—not artificial score adjustments. They point directly to the next improvements.</p></div><div class="gap-grid">{gaps_html}</div></section>
<section class="panel"><div class="panel-header"><h2>Case-by-case evaluation</h2><p class="hint">The 23 regression cases and 8 additional scenarios are interleaved for easier comparison. Case IDs and suite labels remain unchanged; known gaps do not block the CI release gate.</p></div>
<div class="scroll"><table><thead><tr><th>ID</th><th>Suite</th><th>Scenario</th><th>Expected</th><th>Actual</th><th>Result</th></tr></thead><tbody>{case_rows}</tbody></table></div></section>
<section class="panel"><div class="panel-header"><h2>Sanitized detection findings</h2><p class="hint">Rule, severity, service and routing context only. Events shown here are individual findings, before grouping.</p></div>
<div class="scroll"><table><thead><tr><th>Case</th><th>Rule</th><th>Severity</th><th>Service</th><th>Field</th><th>Route</th></tr></thead><tbody>{alert_rows}</tbody></table></div></section>
<aside class="safety"><h2>Data Safety</h2><ul>
<li>No raw log lines, PAN values, or CVC values are included in this HTML dashboard or in <code>alerts.jsonl</code>.</li>
<li>All test inputs are synthetic.</li>
<li>Detection-quality metrics reflect the test dataset only.</li>
</ul></aside>
<div class="footer">Littlepay Security Engineer Challenge · Task 1, Option A · Generated locally with Python</div>
</main></body></html>'''


def main() -> int:
    config = load_config(ROOT/'config.json')
    regression = json.loads((ROOT/'fixtures/lab_cases.json').read_text(encoding='utf-8'))
    challenge = json.loads((ROOT/'fixtures/challenge_cases.json').read_text(encoding='utf-8'))
    rmetrics, ralerts, rresults = evaluate(regression, config, 'Regression')
    cmetrics, calerts, cresults = evaluate(challenge, config, 'Challenge')
    metrics = combine_counts(rmetrics, cmetrics)
    alerts = ralerts + calerts
    passed = sum(c['status'] == 'PASS' for c in rresults)
    gap_count = sum(c['status'] == 'KNOWN GAP' for c in cresults)
    destination = ROOT/'lab_output'
    destination.mkdir(exist_ok=True)
    summary = {'evaluation_date': EVALUATION_DAY.isoformat(),
               'regression_cases': len(regression), 'regression_passed': passed,
               'challenge_cases': len(challenge), 'known_gaps': gap_count,
               'rule_metrics': metrics,
               'measurement_scope': 'Labelled synthetic regression and challenge fixtures only'}
    (destination/'quality_summary.json').write_text(json.dumps(summary, indent=2)+'\n',encoding='utf-8')
    (destination/'alerts.jsonl').write_text(''.join(json.dumps(a,sort_keys=True)+'\n' for a in alerts),encoding='utf-8')
    grouped = group_alerts(alerts, int(config.get('dedup_window_minutes',15)))
    (destination/'grouped_alerts.jsonl').write_text(''.join(json.dumps(a,sort_keys=True)+'\n' for a in grouped),encoding='utf-8')
    (destination/'demo_dashboard.html').write_text(_dashboard(metrics,alerts,rresults,cresults),encoding='utf-8')
    print(f'Regression tests: {passed}/{len(regression)} expected results matched')
    print(f'Challenge tests: {len(challenge)} evaluated; {gap_count} known detection gaps reproduced')
    print(f'Sanitized findings: {len(alerts)}; grouped alerts: {len(grouped)}')
    print('Dashboard: lab_output/demo_dashboard.html')
    return 0 if passed == len(regression) else 1


if __name__ == '__main__':
    raise SystemExit(main())
