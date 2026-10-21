# Test catalogue and known detection gaps

This page explains where our test cases came from, what they cover and what the results actually mean. All values are synthetic or publicly documented sample card numbers; **no customer payment data was used**.

## Two datasets, two different purposes

| Dataset | Cases | Role in the project |
|---|---:|---|
| `fixtures/lab_cases.json` | **23** | Regression tests: the known behaviours that must keep passing |
| `fixtures/challenge_cases.json` | **8** | Diagnostic challenges: harder, labelled examples used to expose limitations and plan improvements |

The first **six regression cases** (`T01–T06`) are based on Littlepay's supplied application-log examples: an order, truncated card token, phone number, settlement reference, full PAN with CVC, and a declined payment logging a full PAN. The other 17 regression cases were written for this project. The eight challenge cases are additional synthetic scenarios.

## What the original 23 regression cases cover

| Cases | Reason for testing | Expected result |
|---|---|---|
| T01–T04 | Order ID, phone, reference, first-six/last-four and timestamp | No PAN/CVC finding |
| T05–T06 | Explicit card data and decline logs | PAN and/or CVC finding |
| T07–T08 | PANs with spaces and hyphens | PAN finding |
| T09–T10 | Masked card, Luhn-valid reference | No PAN finding |
| T11–T12 | CVC in a JSON-like field, masked CVC | CVC finding / no finding |
| T13–T15 | Invalid-Luhn labelled PAN, long phone and approved exception | Expected classification and scoped suppression |
| T16–T20 | JSON-style PAN, token noise, security code, timestamp and unlabelled PAN | Expected positive/negative outcomes |
| T21–T23 | Excessive and compliant partial masking | Flag excessive disclosure only |

All **23/23** continue to match their expected rule sets when the project is run.

## The eight challenge scenarios

These cases run against the **unchanged detection logic**. Their labels describe what the data represents, independently of what the rule happens to predict.

| Case | Scenario | Observed result | Future improvement |
|---|---|---|---|
| E24 | PAN mistakenly placed in `ref` | **False negative** (PAN) | Safer contextual handling of excluded fields |
| E25 | PAN separated by dots | **False negative** (PAN) | Support additional formats with regression tests |
| E26 | Luhn-valid business value in `billing_reference` | **False positive** (PAN) | Reviewed service-specific field definitions |
| E27 | Unrelated `security_code` in configuration logs | **False positive** (CVC) | Scope CVC logic to relevant service contexts |
| E28 | CVC value under `card_cvv` | **False negative** (CVC) | Expand and test recognized field aliases |
| E29 | Supported explicit PAN field | True positive | Retain as a positive boundary test |
| E30 | Supported `cvv2` field | True positive | Retain as a positive boundary test |
| E31 | Known invoice identifier | True negative | Retain as a negative boundary test |

We are **not deliberately breaking the detector** to lower the scores. These five gaps are reproducible limitations of the current regex/context logic. They are visible in the dashboard, but are **not configured as failing release-gate tests**: that gate verifies the 23 established behaviours. An improved detector could fix these gaps and raise the challenge score in a future revision.

## Results across all 31 cases

| Rule | TP | FP | FN | TN | Precision | Recall |
|---|---:|---:|---:|---:|---:|---:|
| `LPY-PAN-001` | 10 | 1 | 2 | 18 | **90.9%** | **83.3%** |
| `LPY-CVC-001` | 4 | 1 | 1 | 25 | **80.0%** | **80.0%** |

- **Precision** = TP / (TP + FP): how many flagged examples were genuine according to their labels.
- **Recall** = TP / (TP + FN): how many labelled exposures were detected.
- **False positives** create unnecessary investigations; **false negatives** allow exposure to go unnoticed.

The same 31 log cases are evaluated independently for each rule. A single case can legitimately be positive for both. Small, deliberately constructed datasets **cannot establish production precision or recall**.

## What the tests do not cover yet

Unicode and encoded values, card data spanning multiple log records, unusual partial masking, track/PIN data and complex nested payloads need different parsing and test strategies. Even a Luhn-valid 16-digit reference may be unrelated to payment cards. Field-name tuning must be based on trustworthy knowledge of the service, not broad global suppression.

**Next testing step:** add independently labelled samples from approved, restricted sources; track analyst feedback; keep regression fixtures for every confirmed bug; and assess whether proposed improvements increase recall without flooding analysts with false positives.
