# Design decisions and delivery approach

*Littlepay Security Engineer Challenge · Tasks 1–3*

## The problem we're solving

In a payment platform, application logs help engineers investigate errors and failed transactions. Those same logs can become a data-exposure risk if the application writes a full payment-card number or a card verification code into them. Logs often travel through collectors, search platforms and backups, where access and retention may differ from those of payment-processing systems.

I chose **Task 1, Option A: Cardholder data in logs**. Instead of building three unrelated detections, the implementation concentrates on one problem with two signals: PAN exposure and CVC exposure.

## Task 1 — Detection logic, tests and trade-offs

| Rule | When it reports a finding | Why |
|---|---|---|
| `LPY-PAN-001` | A plausible 13–19-digit card number, supported space/hyphen formatting, or partial masking beyond the permitted first-six/last-four visibility | Full or improperly masked PAN data can leak into logs |
| `LPY-CVC-001` | A numeric 3- or 4-digit value associated with a recognized CVC/CVV/security-code field | Sensitive authentication data should not appear in general application logs |

The PAN rule starts by looking for candidate numbers. It then checks the **field name**, **format** and **Luhn checksum**, rather than treating every long number as a card. Known fields such as `order_id`, `phone` and `ref` are excluded because they commonly contain unrelated identifiers. A recognized PAN field can still trigger at **Medium** severity when Luhn fails; a plausible valid PAN generally triggers at **High**. Numeric CVC/CVV values are **Critical** in this demonstration.

This is a deliberate balance between **precision** (how many alerts are real) and **recall** (how many true exposures we find). Filtering known non-card fields reduces false alarms, but it can hide a real PAN mistakenly stored in one of those fields. Conversely, a Luhn-valid value in an unexpected reference field can be flagged even though it isn't a card number. A checksum supports a decision; it does not establish the true meaning of the data.

### Evidence from the tests

The **23 original regression cases all pass**. These include six examples based on the application-log lines provided by Littlepay and 17 additional synthetic cases. A separate **eight-case challenge dataset** contains five observed limitations: two PAN false negatives, one PAN false positive, one CVC false negative and one CVC false positive. The remaining three cases are additional correct classifications.

Across all 31 synthetic cases, PAN precision and recall are **90.9% and 83.3%**; CVC precision and recall are **80% and 80%**. These figures are intentionally presented as fixture results, **not** production-quality estimates. The exact labels and improvement opportunities are in [`TEST_CATALOG.md`](TEST_CATALOG.md).

## Task 2 — From a script to an operational detection

A security rule needs more than detection logic. Someone has to own it, tune it, understand the impact of an alert and know what to do next.

**Rule metadata.** `rule_metadata.json` records the rule ID, owner, description, data source, severity, PCI DSS Requirement 3 mapping and runbook reference. I haven't forced a MITRE ATT&CK technique mapping: a logging defect is not, by itself, evidence of a specific attacker technique.

**Controlled exceptions.** `config.json` contains an example allowlist entry scoped to a synthetic fixture service and a specific rule, with an approver, justification and expiry date. Tests check that missing approval or an expired exception cannot silently suppress the detection. This is a code-reviewed exception model, not an invitation to disable noisy rules globally.

**Safe, actionable alerts.** Findings include the rule, severity, service, matched field, confidence, reason, time, fingerprint and routing destination. The detector does **not** include the raw log line, PAN or CVC in emitted findings. In the command-line output, alerts can be grouped by rule/service/field/severity/route in 15-minute UTC windows, retaining the event count and first/last timestamps. Grouping helps with noise but can combine separate exposures; the underlying evidence would need restricted handling in a real incident process.

**Routing and enrichment.** Routes such as `soc-urgent` are illustrative labels, not an active Slack connection. The output contains basic context already available from the log and rule. Real production enrichment would need a trusted service inventory for ownership, environment, deployment and data classification.

A useful alert should answer: **what happened, where, how serious is it, who owns the service, and what should the analyst do next?** The response steps are in [`RUNBOOK.md`](RUNBOOK.md).

## Task 3 — Shipping a detection like application code

The repository contains a GitHub Actions workflow defining **linting, syntax checks, unit tests, fixture evaluation and artifact packaging**. The CI definition can be run on GitHub; this local demonstration does not prove a hosted CI execution or production deployment.

A production release would follow Littlepay's stated way of working:

1. **Propose a change in a branch.** Add or update the detection and the relevant positive/negative tests.
2. **Validate in CI.** Run lint, tests and labelled regressions. Fail the release gate if existing expected behaviour breaks. Diagnostic known gaps remain visible rather than being silently relabelled as passing.
3. **Review and merge.** Require Security Engineering peer review and a protected main branch with green checks.
4. **Build once.** Package an immutable, versioned artifact tied to a commit and digest. Promote the same artifact between environments rather than rebuilding it for production.
5. **Observe safely.** Test new rules in non-production and shadow mode before limited canary paging. Compare alert volume, known-positive coverage and ingestion health with baseline behaviour.
6. **Approve production.** Obtain an approved Change Request for PCI/production changes, then deploy only through the authorized CI identity—not a laptop or a cloud-console edit.
7. **Roll back if required.** Re-promote the last known-good artifact through the approved pipeline, review any lost detection coverage, and replay/backfill telemetry where available.

### How I'd prevent alert storms and silent misses

An alert storm should be caught through labelled negative cases, baseline comparisons, shadow mode, rate monitoring, grouping and early analyst feedback. A silent false negative needs a different control: maintained positive fixtures, independent test samples and validation that log ingestion still works. Rules that stop firing might be healthy, or might have lost their data source; the monitoring process has to distinguish the two.

### Known limitations and next steps

This is a small rule-based prototype, not a complete payment-data loss prevention system. It doesn't include streaming ingestion, alert delivery retries, production case-management integration, hardened evidence storage or exhaustive PAN and sensitive-authentication-data parsing. The challenge results show why a simple field exclusion or a short list of CVC names is not sufficient for every service. Before real deployment, I'd improve service-specific parsing and field dictionaries, add representative formats and confirm signal quality using securely handled, independently labelled samples.

The actual application must also **avoid logging sensitive data in the first place**. Detection is an additional safety net, not a substitute for secure logging and data handling.
