# Keeping detections useful over time

*Task 4 · Detection health strategy*

A detection isn't finished when it first produces the right alert. Services change, log formats evolve and tuning decisions can become outdated. I would manage detections as **owned, version-controlled production assets**, with tests, response guidance and a regular review cycle.

## Measure the signal, not just the number of alerts

**Precision** tells us how many investigated alerts were real. **False-positive rate** helps identify noisy rules. **Coverage and recall** address the opposite question: what are we missing? Since an unknown real-world false negative cannot always be counted, I would report coverage by scenario, service and data source, supported by controlled positive tests, confirmed incidents and independently labelled reviews—not claim universal recall. The local challenge dataset already shows why passing a regression suite isn't enough.

Operational health also matters. I would monitor event-to-alert latency, **mean time to detect (MTTD) on incidents where the relevant timestamps are available**, investigation time, alert-volume changes, missing log ingestion and rules that have gone quiet unexpectedly. These are **proposed production measures**, not metrics reported by the offline lab. A rule with zero alerts might be healthy, or it might have lost its data source.

## Give every rule an owner and a maintenance path

Each detection should have an owning team, severity, data-source contract, service scope, runbook and review date. Logic and exceptions belong in Git with peer review and a clear change history. Analyst feedback should lead to new negative tests; confirmed incidents should lead to new positive tests. Exceptions should be specific, justified, approved and time-limited. Stale or redundant rules should be retired deliberately, with any lost coverage documented.

## Make this workable across 50+ services

I would provide a shared starter template, common metadata schema, reusable test harness and normalized logging contract so teams don't have to solve the same problem independently. A self-service pull-request process should make it easy for an application owner to propose a new case or a tuning change. Coverage should be visible by critical service and PCI boundary, not just as a count of active rules.

## Review and release rhythm

- **Daily:** investigate ingestion gaps, unusual alert spikes and urgent findings.
- **Weekly:** review analyst false-positive feedback and failing positive tests.
- **Monthly:** review coverage with service owners, aging rules and expiring exceptions.
- **Quarterly:** revisit important attack/data-exposure scenarios, validate selected detections with controlled exercises and retire unsupported rules.

New or changed rules should start in shadow mode, then a limited canary rollout before broader paging. Promote the same approved artifact through CI and retain a tested rollback path. The best outcome is a reliable process where improving a rule is easy, while shipping an untested or dangerously noisy rule is hard.
