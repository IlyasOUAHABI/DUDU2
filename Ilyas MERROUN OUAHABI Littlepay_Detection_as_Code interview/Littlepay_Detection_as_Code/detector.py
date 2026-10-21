"""Payment-card data exposure detector, using only the Python standard library.

This is a demonstration detector for synthetic logs, not a PCI-certified DLP engine.
Alerts intentionally never contain raw source lines, PANs, or CVC values.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from datetime import date, datetime, timezone
from pathlib import Path
from typing import Any

RULE_PAN = "LPY-PAN-001"
RULE_CVC = "LPY-CVC-001"

# A candidate consists of 13–19 digits, possibly separated by spaces or hyphens.
# Context and Luhn checks below decide whether it should alert.
PAN_CANDIDATE = re.compile(r"(?<![A-Za-z0-9])(?:\d[ -]?){12,18}\d(?![A-Za-z0-9])")
MASKED_CARD_FIELD = re.compile(
    r"(?<![A-Za-z0-9_])[\"']?"
    r"(?P<field>primary_account_number|card_number|cardnumber|cc_number|card_no|cardnum|pan|card)"
    r"[\"']?\s*[:=]\s*[\"']?(?P<value>[0-9Xx*#-]{10,30})",
    re.IGNORECASE,
)
CVC_FIELD = re.compile(
    r"(?<![A-Za-z0-9_])[\"']?"
    r"(?P<field>card_security_code|security_code|cvc2|cvv2|cvc|cvv)"
    r"[\"']?\s*[:=]\s*[\"']?(?P<value>\d{3,4})(?!\d)",
    re.IGNORECASE,
)
FIELD_BEFORE_VALUE = re.compile(
    r"(?P<field>[A-Za-z][A-Za-z0-9_-]{0,48})[\"']?\s*[:=]\s*$"
)
TIMESTAMP = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z")

CARD_FIELDS = {
    "pan", "card", "card_number", "cardnumber", "cc_number",
    "primary_account_number", "card_no", "cardnum",
}
# Never infer that a value is a card number merely because an unrelated ID
# happens to pass Luhn. These exclusions are deliberately exact field names.
NON_CARD_FIELDS = {
    "order_id", "ref", "reference", "phone", "phone_number", "mobile",
    "transaction_id", "trace_id", "request_id", "session_id", "invoice_id",
    "customer_id", "batch", "amount", "first6", "last4", "token_id",
}


def luhn_valid(digits: str) -> bool:
    """True for a 13–19 digit string with a valid Luhn checksum."""
    if not (digits.isascii() and digits.isdigit() and 13 <= len(digits) <= 19):
        return False
    total = 0
    for index, character in enumerate(reversed(digits)):
        value = int(character)
        if index % 2 == 1:
            value *= 2
            if value > 9:
                value -= 9
        total += value
    return total % 10 == 0


def _field_at(line: str, candidate_start: int) -> str | None:
    prefix = line[max(0, candidate_start - 90):candidate_start].rstrip(" \t+\"'")
    match = FIELD_BEFORE_VALUE.search(prefix)
    return match.group("field").lower() if match else None


def _plausible_format(raw_value: str) -> bool:
    """Avoid joining unrelated timestamps/IDs separated by whitespace."""
    chunks = re.split(r"[ -]", raw_value.strip())
    if any(not chunk for chunk in chunks):
        return False
    if len(chunks) == 1:
        return True
    # Payment cards commonly use 3–6 digit chunks (e.g. 4-4-4-4, 4-6-5).
    return 3 <= len(chunks) <= 5 and all(3 <= len(c) <= 6 for c in chunks)


def _is_allowlisted(rule_id: str, service: str, config: dict[str, Any], today: date) -> bool:
    for entry in config.get("allowlist", []):
        if entry.get("rule_id") != rule_id or entry.get("service") != service:
            continue
        # Missing approval, justification or expiration never suppresses an alert.
        if not all(entry.get(key) for key in ("reason", "approved_by", "expires_on")):
            continue
        try:
            expiration = date.fromisoformat(entry["expires_on"])
        except (ValueError, TypeError):
            continue
        if today <= expiration:
            return True
    return False


def analyze_line(
    line: str,
    *,
    service: str = "payments-svc",
    config: dict[str, Any] | None = None,
    today: date | None = None,
) -> list[dict[str, str]]:
    """Find prohibited data and return *sanitized* structured alerts.

    Invalid-Luhn values in an explicit PAN field still alert with lower confidence.
    Unlabelled values must pass Luhn. Known non-card ID fields are excluded.
    """
    cfg = config if config is not None else {"allowlist": []}
    clock_day = today if today is not None else datetime.now(timezone.utc).date()
    timestamp_match = TIMESTAMP.match(line)
    timestamp = timestamp_match.group() if timestamp_match else "not-present"
    findings: list[dict[str, str]] = []

    def emit(rule_id: str, severity: str, field: str, confidence: str, reason: str) -> None:
        if _is_allowlisted(rule_id, service, cfg, clock_day):
            return
        # Hash is non-reversible, and no raw log line or matched secret is emitted.
        digest = hashlib.sha256(f"{service}|{rule_id}|{line}".encode("utf-8")).hexdigest()[:16]
        findings.append({
            "event_time": timestamp,
            "rule_id": rule_id,
            "severity": severity,
            "service": service,
            "matched_field": field,
            "confidence": confidence,
            "reason": reason,
            "fingerprint": digest,
            "route": cfg.get("routing", {}).get(severity.lower(), "soc-triage"),
        })

    # Separate detection: security codes must never be written to application logs.
    for match in CVC_FIELD.finditer(line):
        emit(RULE_CVC, "Critical", match.group("field").lower(), "high", "Sensitive authentication data in log")

    # Beyond first-six / last-four is a masking violation too, even when
    # the full PAN is not present and a Luhn check is impossible.
    for match in MASKED_CARD_FIELD.finditer(line):
        value = match.group("value").replace("-", "")
        if not re.search(r"[Xx*#]", value):
            continue
        prefix = re.match(r"[0-9]+", value)
        suffix = re.search(r"[0-9]+$", value)
        if (len(prefix.group()) if prefix else 0) > 6 or (len(suffix.group()) if suffix else 0) > 4:
            emit(RULE_PAN, "High", match.group("field").lower(), "high",
                 "Partial card masking exceeds the first-six / last-four policy")

    for match in PAN_CANDIDATE.finditer(line):
        raw = match.group()
        normalized = re.sub(r"[ -]", "", raw)
        if not (13 <= len(normalized) <= 19 and _plausible_format(raw)):
            continue
        field = _field_at(line, match.start())
        if field in NON_CARD_FIELDS:
            continue
        checksum_valid = luhn_valid(normalized)
        explicit_card_field = field in CARD_FIELDS
        if not checksum_valid and not explicit_card_field:
            continue
        emit(
            RULE_PAN,
            "High" if checksum_valid else "Medium",
            field or "unlabelled",
            "high" if checksum_valid and explicit_card_field else "medium",
            "Possible full PAN logged (field context / Luhn validation)",
        )
    return findings


def group_alerts(alerts: list[dict[str, str]], window_minutes: int = 15) -> list[dict[str, Any]]:
    """Group noisy alerts by rule/service/field in UTC time windows.

    The grouping key intentionally contains neither raw payment data nor logs.
    When an event timestamp is missing, fingerprint is used to avoid merging
    unrelated incidents into a large unknown-time bucket.
    """
    if window_minutes < 1:
        raise ValueError("window_minutes must be >= 1")
    grouped: dict[tuple[str, ...], dict[str, Any]] = {}
    for alert in alerts:
        when = alert["event_time"]
        try:
            stamp = datetime.fromisoformat(when.replace("Z", "+00:00"))
            bucket = str(int(stamp.timestamp()) // (window_minutes * 60))
        except ValueError:
            bucket = "unbounded:" + alert["fingerprint"]
        key = (alert["rule_id"], alert["service"], alert["matched_field"],
               alert["severity"], alert["route"], bucket)
        if key not in grouped:
            item: dict[str, Any] = dict(alert)
            item["dedup_key"] = hashlib.sha256("|".join(key).encode("utf-8")).hexdigest()[:16]
            item["event_count"] = 1
            item["first_seen"] = when
            item["last_seen"] = when
            grouped[key] = item
        else:
            item = grouped[key]
            item["event_count"] += 1
            if when < item["first_seen"]:
                item["first_seen"] = when
            if when > item["last_seen"]:
                item["last_seen"] = when
    return list(grouped.values())


def load_config(path: str | Path) -> dict[str, Any]:
    with Path(path).open(encoding="utf-8") as handle:
        value = json.load(handle)
    if not isinstance(value, dict) or not isinstance(value.get("allowlist", []), list):
        raise ValueError("Config must be a JSON object with an allowlist array")
    return value


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Emit sanitized payment-data alerts from application logs")
    parser.add_argument("--input", type=Path, required=True, help="UTF-8 plain text application log")
    parser.add_argument("--service", default="payments-svc")
    parser.add_argument("--config", default="config.json")
    parser.add_argument("--output", type=Path, help="Optional JSONL output; otherwise print to stdout")
    args = parser.parse_args(argv)
    try:
        config = load_config(args.config)
        # Do not echo raw file lines on failures.
        alerts = []
        with args.input.open(encoding="utf-8") as handle:
            for line in handle:
                alerts.extend(analyze_line(line.rstrip("\r\n"), service=args.service, config=config))
        grouped = group_alerts(alerts, int(config.get("dedup_window_minutes", 15)))
        rendered = "".join(json.dumps(item, sort_keys=True) + "\n" for item in grouped)
        if args.output:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(rendered, encoding="utf-8")
        else:
            sys.stdout.write(rendered)
        print(f"Analyzed log; found {len(alerts)} findings, emitted {len(grouped)} grouped sanitized alert(s).", file=sys.stderr)
        return 0
    except (OSError, ValueError, json.JSONDecodeError) as error:
        print(f"Detector could not complete: {type(error).__name__}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
