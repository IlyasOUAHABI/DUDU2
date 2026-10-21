# SOC runbook — Payment-card data in application logs

**Applies to:** `LPY-PAN-001` (PAN exposure) and `LPY-CVC-001` (card security-code exposure)

## What this alert means

An application may have written a full or improperly masked payment-card number, or a card security code, into its logs. Even if the logging was accidental, the data may have been copied to search platforms, exports or backups. The first objective is to **stop further exposure and establish the scope safely**.

| Rule | Default severity | What to prioritise |
|---|---|---|
| `LPY-PAN-001` | **High** (or Medium for an explicitly named PAN failing Luhn) | Verify the logging problem and stop it at the source |
| `LPY-CVC-001` | **Critical** | Escalate immediately to the incident lead and payment-security/compliance contact |

## Triage and response

1. **Acknowledge the alert.** Capture the rule ID, affected service, timestamps, event count, severity and deduplication key. Do **not** paste raw logs, PANs or CVC values into tickets, chats or email.
2. **Validate through approved access.** Confirm whether the event comes from a payment-related service and whether the matched field truly represents card data. Use restricted evidence access rather than widening access to sensitive log entries.
3. **Stop unsafe logging.** Contact the application owner and security incident lead. Fix or disable the offending log statement using an appropriately controlled change; simply suppressing the detection does not remove the exposure.
4. **Understand the blast radius.** Establish when logging began, which services and instances were affected, where the logs went, who could access them, and whether they were exported, retained or backed up.
5. **Coordinate the response.** Bring in the relevant PCI, data-protection and incident-response stakeholders. Determine any customer impact and agreed handling of retained sensitive data under the organisation's policies.
6. **Verify and close carefully.** Confirm new logs are properly redacted and that the detection still catches a known positive synthetic example. Record approvals, access to evidence and any cleanup/retention decision.

## Special handling for CVC/CVV

Treat a numeric card-security-code finding as urgent. Card security codes are sensitive authentication data and must not be retained after authorization under PCI rules. The incident lead and payment/compliance owner should direct any evidence-handling and retention decisions. **Never copy the CVC into the incident ticket as proof.**

## Operational cautions

- **One grouped alert is not necessarily one incident.** The detector groups by service, rule, field, severity, route and 15-minute window; review its event count and first/last timestamps.
- **A false positive is possible.** A non-card identifier might happen to look like a PAN, while `security_code` might be used for a non-payment purpose. Propose reviewed, narrowly scoped tuning with a clear expiry date.
- **A false negative is possible.** Card data in excluded fields or unusual formats may be missed. A quiet rule is not proof that logging is safe.
- **An ingestion outage is a separate failure.** Confirm that expected telemetry is still arriving before interpreting an absence of alerts.

The local project demonstrates alert structure and response guidance. It does not connect to a live ticketing or notification platform.
