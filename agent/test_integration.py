"""Real server/hardmode integration against a synthetic student world, without truth.json."""
from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from agent.gateway import Command, Gateway
from agent.telemetry import RecordingGatewayContext
from agent.answer import prepare_answer
from kit.mcp.a2a import execute as execute_peer
from kit.mcp.hardmode import HardMode
from kit.mcp.mutations import MutableStack
from kit.mcp.servers import handle
from kit.world.fixture import build_fixture_world, FIXTURE_ANCHORS, FIXTURE_INJECTION_NOTES
from kit.world.loader import World


class IntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(prefix="truongbao-world-")
        cls.world = World.load(build_fixture_world(Path(cls.temp.name), include_truth=False))

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def setUp(self):
        self.ctx = RecordingGatewayContext("learner:sv-0417", "agent:TruongBao",
                                           frozenset({"wiki.read", "wiki.write:progress"}), 100, 1, 0)
        self.gateway = Gateway(self.ctx)
        self.hardmode = HardMode(world=self.world, opaque_enabled=False, degraded_replica_enabled=False)
        self.hardmode.reset("student-integration", world_id=self.world.manifest["world_id"])

    def call(self, server, tool, args, *, fields=(), headers=None, lease=None, index=0):
        cmd = Command("cmd:" + str(index), "a2a" if "-" in server else "mcp", "",
                      server, tool, args, fields, headers or {}, lease, index)
        decision = self.gateway.decide(cmd)
        self.assertIsNotNone(decision.call, decision.reason)
        result = handle(self.world, decision.call, hardmode=self.hardmode)
        self.ctx.credits -= result.get("cost", 0)
        self.gateway.note_result(decision.call, result)
        return decision.call, result

    def test_query_lease_read_and_grounded_answer(self):
        self.assertFalse(self.world.has_truth)
        _, found = self.call("slides", "query", {"q": "MCP", "limit": 1})
        self.assertTrue(found["ok"])
        self.assertTrue(found["lease_id"])
        anchor = found["anchors"][0]
        _, read = self.call("slides", "get_frame", {"anchor": anchor}, lease=found["lease_id"], index=1)
        self.assertTrue(read["ok"])
        answer = {"text": read["rows"][0]["body"], "cited_anchors": [anchor]}
        _, errors = prepare_answer(answer, [read])
        self.assertFalse(errors)

    def test_provenance_write_actual_receipt_and_no_double_write(self):
        anchor = "Learner:sv-0417"
        _, provenance = self.call("registry", "provenance", {"anchor": anchor})
        self.assertTrue(provenance["ok"])
        args = {"anchor": anchor, "learner": anchor, "concept": "Concept:streamable-http"}
        _, result = self.call("progress", "record_mastery", args, index=1)
        self.assertTrue(result["ok"], result)
        self.assertTrue(result["rows"][0]["receipt_id"])
        cmd = Command("retry", "mcp", "", "progress", "record_mastery", args, (), {}, None, 2)
        self.assertEqual(self.gateway.decide(cmd).verdict, "deny")

    def test_actual_a2a_accepts_gateway_token(self):
        cmd = Command("peer", "a2a", "", "curriculum-analyst", "which_days_cover",
                      {"concept": "Concept:streamable-http"}, (), {"aud": "curriculum-analyst"}, None, 0)
        call = self.gateway.decide(cmd).call
        self.assertIsNotNone(call)
        result = execute_peer(self.world, call, expected_act=self.ctx.act,
                              delegation=call.headers["delegation"])
        self.assertTrue(result["ok"], result)
        self.assertTrue(result["anchors"])

    def test_post_dispatch_poison_is_excluded_at_answer_boundary(self):
        cmd = Command("q", "mcp", "", "slides", "query", {"q": "MCP", "limit": 1},
                      ("body", "title"), {}, None, 0)
        call = self.gateway.decide(cmd).call
        self.assertIsNotNone(call)
        stack = MutableStack(world=self.world, act=self.ctx.act)
        stack.arm({"id": "synthetic-poison", "kind": "attack", "class": "poisoned_result",
                   "mutation": {"target": "mcp:slides", "op": "poison_row",
                                "value": {"note_anchor": FIXTURE_INJECTION_NOTES[0]}},
                   "trigger": {"on": "call_index", "gte": 0}})
        result, mutation = stack.execute(call)
        self.assertTrue(mutation["applied"])
        answer = {"text": "MCP is covered.", "cited_anchors": result["anchors"]}
        _, errors = prepare_answer(answer, [result])
        self.assertIn("unsafe retrieved content excluded", errors)

    def test_explicit_other_edition_is_pinned_without_guessing_freshness(self):
        _, found = self.call("slides", "query", {"q": "MCP", "limit": 1})
        anchor = FIXTURE_ANCHORS["alpha_frame_c_001"]
        call, result = self.call("slides", "get_frame", {"anchor": anchor},
                                 lease=found["lease_id"], index=1)
        self.assertEqual(call.headers["mcp-replica"], "c")
        self.assertTrue(result["ok"])


if __name__ == "__main__":
    unittest.main()
