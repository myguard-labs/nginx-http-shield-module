"""Validate the operator kit against the status renderer's metric contract."""

import json
import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


class OperatorKitTest(unittest.TestCase):
    def test_dashboard_schema_and_metric_names(self):
        dashboard = json.loads((ROOT / "contrib/grafana-dashboard.json").read_text())
        source = (ROOT / "src/ngx_http_shield_status.h").read_text()
        descriptors = re.findall(
            r"(?:NGX_SHIELD_METRIC\([^,]+,\s*|\{\s*NULL,\s*)"
            r'"(shield_[a-z_]+)"\s*,\s*"[^"]+"\s*,\s*([01])',
            source,
        )
        emitted = {
            name + ("_total" if counter == "1" else "") for name, counter in descriptors
        }
        self.assertEqual(
            emitted,
            {
                "shield_hits_total",
                "shield_blocked_total",
                "shield_bans_total",
                "shield_zone_nodes",
                "shield_banned_clients",
                "shield_requests_total",
                "shield_ban_refusals_total",
                "shield_zone_evictions_total",
                "shield_zone_alloc_failures_total",
                "shield_zone_used_bytes",
                "shield_zone_size_bytes",
                "shield_detections_total",
                "shield_source_hits_total",
                "shield_body_uninspected_total",
            },
        )
        self.assertIsInstance(dashboard["schemaVersion"], int)
        self.assertTrue(dashboard["title"])
        ids = set()
        for panel in dashboard["panels"]:
            self.assertNotIn(panel["id"], ids)
            ids.add(panel["id"])
            self.assertEqual(panel["type"], "timeseries")
            self.assertEqual(panel["datasource"]["type"], "prometheus")
            self.assertTrue(all(panel["gridPos"][key] >= 0 for key in ("x", "y")))
            self.assertTrue(all(panel["gridPos"][key] > 0 for key in ("w", "h")))
            for target in panel["targets"]:
                names = set(re.findall(r"\bshield_[a-z_]+\b", target["expr"]))
                self.assertTrue(names, panel["title"])
                self.assertFalse(names - emitted, (panel["title"], names - emitted))
                self.assertNotRegex(target["expr"], r"\{[^}]+\}")

    def test_documented_mapping_and_bounded_labels(self):
        readme = (ROOT / "README.md").read_text()
        source = (ROOT / "src/ngx_http_shield_status.h").read_text()
        for token in (
            "shield_zone_nodes",
            "shield_blocked_total",
            "shield_bans_total",
            "shield_requests_total",
            "shield_ban_refusals_total",
            "shield_zone_evictions_total",
            "shield_zone_alloc_failures_total",
            "shield_zone_used_bytes",
            "shield_zone_size_bytes",
            "shield_body_uninspected_total{reason}",
            "shield_hits_total{category}",
            "shield_detections_total{category,mode}",
            "shield_source_hits_total{category,source}",
            "shield_banned_clients",
        ):
            self.assertIn(token, readme)
        for label in ("zone", "category", "mode", "source", "reason"):
            self.assertIn(label + r"=\"", source)
        for reason in ("too_large", "encoding", "error"):
            self.assertIn('"' + reason + '"', source)


if __name__ == "__main__":
    unittest.main()
