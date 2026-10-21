"""Run with: python -m unittest discover -v"""

from __future__ import annotations

import json
import tempfile
import unittest
from datetime import date
from pathlib import Path

from detector import RULE_CVC, RULE_PAN, analyze_line, group_alerts, load_config, luhn_valid

ROOT = Path(__file__).resolve().parent
CONFIG = load_config(ROOT / "config.json")
FIXTURES = json.loads((ROOT / "fixtures/lab_cases.json").read_text(encoding="utf-8"))


class LuhnTests(unittest.TestCase):
    def test_valid_and_invalid_card_numbers(self) -> None:
        self.assertTrue(luhn_valid("4111111111111111"))
        self.assertTrue(luhn_valid("5500005555555559"))
        self.assertFalse(luhn_valid("4111111111111112"))

    def test_rejects_non_pan_inputs(self) -> None:
        for value in ("1234", "4111 1111 1111 1111", "x4111111111111111", "12345678901234567890"):
            with self.subTest(value=value):
                self.assertFalse(luhn_valid(value))


class DetectionTests(unittest.TestCase):
    def test_every_labelled_fixture(self) -> None:
        for fixture in FIXTURES:
            with self.subTest(case_id=fixture["id"]):
                results = analyze_line(
                    fixture["log"], service=fixture["service"], config=CONFIG,
                    today=date(2026, 10, 20),
                )
                actual = sorted(item["rule_id"] for item in results)
                self.assertEqual(actual, sorted(fixture["expected_rule_ids"]))

    def test_pan_severity_for_valid_vs_invalid_luhn(self) -> None:
        high = analyze_line("pan=4111111111111111", config=CONFIG)
        medium = analyze_line("pan=4111111111111112", config=CONFIG)
        self.assertEqual((high[0]["rule_id"], high[0]["severity"]), (RULE_PAN, "High"))
        self.assertEqual((medium[0]["rule_id"], medium[0]["severity"]), (RULE_PAN, "Medium"))

    def test_cvc_critical_and_routed(self) -> None:
        alerts = analyze_line('CVV="123"', config=CONFIG)
        self.assertEqual(alerts[0]["rule_id"], RULE_CVC)
        self.assertEqual(alerts[0]["severity"], "Critical")
        self.assertEqual(alerts[0]["route"], "soc-urgent")

    def test_must_never_include_secrets_or_raw_line(self) -> None:
        line = "2026-10-11T09:15:10Z card=4111111111111111 cvc=123 phone=+61400123456"
        alerts = analyze_line(line, config=CONFIG)
        output = json.dumps(alerts)
        self.assertEqual(len(alerts), 2)
        for forbidden in ("4111111111111111", "cvc=123", "+61400123456", line):
            self.assertNotIn(forbidden, output)

    def test_allowlist_requires_approval_and_unexpired_date(self) -> None:
        line = "card=4111111111111111"
        self.assertEqual(analyze_line(
            line, service="synthetic-fixture-service", config=CONFIG,
            today=date(2026, 12, 1),
        ), [])
        self.assertEqual(len(analyze_line(
            line, service="synthetic-fixture-service", config=CONFIG,
            today=date(2027, 1, 2),
        )), 1)
        cfg = {"allowlist": [{"service": "synthetic-fixture-service", "rule_id": RULE_PAN,
                              "expires_on": "2029-01-01", "reason": "missing approver"}]}
        self.assertEqual(len(analyze_line(line, service="synthetic-fixture-service", config=cfg)), 1)

    def test_allowlist_scopes_to_service_and_rule(self) -> None:
        line = "card=4111111111111111 cvc=123"
        alerts = analyze_line(
            line, service="synthetic-fixture-service", config=CONFIG,
            today=date(2026, 10, 20),
        )
        self.assertEqual([a["rule_id"] for a in alerts], [RULE_CVC])
        self.assertEqual(len(analyze_line(line, service="payments-svc", config=CONFIG)), 2)

    def test_non_card_identifier_valid_luhn_is_not_a_pan(self) -> None:
        self.assertEqual(analyze_line("order_id=4111111111111111", config=CONFIG), [])

    def test_time_window_grouping_and_no_secret_in_group_key(self) -> None:
        examples = [
            "2026-10-11T09:16:01Z card=4111111111111111",
            "2026-10-11T09:16:02Z card=5500005555555559",
            "2026-10-11T09:31:02Z card=4111111111111111",
        ]
        alerts = [a for line in examples for a in analyze_line(line, config=CONFIG)]
        groups = group_alerts(alerts, window_minutes=15)
        self.assertEqual(len(groups), 2)
        self.assertEqual(sorted(x["event_count"] for x in groups), [1, 2])
        self.assertNotIn("4111111111111111", json.dumps(groups))
        self.assertEqual(len({x["dedup_key"] for x in groups}), 2)

    def test_missing_timestamp_does_not_group_different_log_lines(self) -> None:
        alerts = [a for line in ("card=4111111111111111", "card=5500005555555559")
                  for a in analyze_line(line, config=CONFIG)]
        self.assertEqual(len(group_alerts(alerts)), 2)

    def test_input_error_not_returned_as_raw_value(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "empty.json"
            path.write_text("[]", encoding="utf-8")
            with self.assertRaises(ValueError):
                load_config(path)


if __name__ == "__main__":
    unittest.main()
