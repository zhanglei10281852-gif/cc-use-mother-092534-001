"""实现必须严格落在领域合同（domain/contract.json）定义的状态与事件内。"""
from __future__ import annotations

import json
import unittest
from pathlib import Path

from exportguard import events as event_module
from exportguard.aggregate import (
    STATE_APPROVED,
    STATE_AWAITING_APPROVAL,
    STATE_CLASSIFIED,
    STATE_COMPLETED,
    STATE_DELIVERING,
    STATE_DRAFT,
    STATE_EXPIRED,
    STATE_REVOKED,
)

ROOT = Path(__file__).resolve().parents[1]


class ContractConformanceTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.contract = json.loads((ROOT / "domain" / "contract.json").read_text("utf-8"))

    def test_event_types_match_contract_exactly(self):
        implemented = set(event_module.ALL_EVENT_TYPES)
        contracted = set(self.contract["event_types"])
        self.assertEqual(implemented, contracted)

    def test_states_used_by_aggregate_are_declared_in_contract(self):
        used = {
            STATE_DRAFT,
            STATE_CLASSIFIED,
            STATE_AWAITING_APPROVAL,
            STATE_APPROVED,
            STATE_DELIVERING,
            STATE_COMPLETED,
            STATE_REVOKED,
            STATE_EXPIRED,
        }
        declared = set(self.contract["states"])
        self.assertEqual(used, declared)

    def test_entities_cover_implementation_concepts(self):
        # 合同实体至少要能映射到实现中的关键概念。
        required = {
            "export_request",
            "manifest",
            "manifest_entry",
            "approval",
            "delivery_chunk",
            "audit_record",
        }
        self.assertTrue(required <= set(self.contract["entities"]))

    def test_rules_cover_core_invariants(self):
        rules_text = "；".join(self.contract["rules"])
        for keyword in ("清单哈希", "接收方", "有效期", "版本", "领取", "撤销", "过期"):
            self.assertIn(keyword, rules_text)


if __name__ == "__main__":
    unittest.main()
