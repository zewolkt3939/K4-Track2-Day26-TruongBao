"""Pure gateway policy. No I/O, clocks, randomness, or tool execution."""
from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping

from kit.mcp.a2a import AGENT_CARDS, SKILL_ROUTES, admit_skill, mint_delegation, verify_delegation
from kit.mcp.specs import A2A_PEERS, TOOL_SPECS, cost_of
from kit.mcp.types import ToolCall
from kit.world.anchor import Anchor, AnchorSyntaxError

from agent.guardrails import scan_for_injected_instructions
from agent.strategy import cheap_mask, successor_of

NARROW_MASKS = {
    ("registry", "list_servers"): ("name",),
    ("glossary", "list_terms"): ("term", "sense"),
}


def learner_key(value: object) -> str:
    """Learner: and learner: name the same principal in the shipped kit."""
    text = str(value)
    prefix, sep, slug = text.partition(":")
    return prefix.casefold() + sep + slug if sep else text


class Policy:
    def __init__(self, ctx):
        self.ctx = ctx
        self.cards = dict(AGENT_CARDS)  # signed, registry-issued fixtures, not model input
        self.attested_cards = {}
        self.provenance = {}
        self.used_tokens = set()
        self.write_keys = set()
        self.write_operations = set()
        self.rates = {}
        self.round = None
        self.round_spend = 0
        self.round_allowance = 10
        self.remaining = int(ctx.credits)
        self.local_leases = {}

    def note_card(self, server, card):
        """Only the trusted arena may feed its admission result through this hook."""
        if isinstance(card, Mapping) and "signature" not in card:
            self.attested_cards[server] = dict(card)
        else:
            self.cards[server] = card
            self.attested_cards.pop(server, None)

    def note_provenance(self, anchor, etag, replica=None):
        self.provenance[str(anchor)] = (str(etag), replica, self.ctx.round)

    def note_result(self, call, result):
        """Optional trusted outcome hook; failed writes remain uncertain, not retried."""
        if not isinstance(result, Mapping) or not result.get("ok"):
            return
        if (call.server, call.tool) in {("slides", "query"), ("slides", "search")}:
            lease = result.get("lease_id")
            if lease:
                self.local_leases[str(lease)] = (self.ctx.round, call.call_index)
        if (call.server, call.tool) == ("registry", "provenance"):
            for row in result.get("rows", ()):
                if isinstance(row, Mapping) and row.get("etag"):
                    anchor = row.get("anchor") or call.args.get("anchor")
                    if anchor:
                        self.note_provenance(anchor, row["etag"], row.get("rev"))

    def _identity(self, cmd, headers):
        for name in ("x-server-fingerprint", "x-card-signature"):
            if name in headers:
                # The outgoing command cannot attest its own server identity.
                return "unattested identity marker in command headers"
        if cmd.server not in A2A_PEERS:
            if cmd.kind == "a2a":
                return "unknown A2A peer"
            return None
        if cmd.kind != "a2a":
            return "A2A peer must use an A2A command"
        aud = headers.get("aud")
        if aud not in (cmd.server, "a2a:" + cmd.server):
            return "delegation audience does not match the called peer"
        card = self.attested_cards.get(cmd.server)
        skills = card.get("skills", ()) if card is not None else None
        skill = cmd.tool
        if "skill" in cmd.args:
            skill = cmd.args["skill"]
            if not isinstance(skill, str) or SKILL_ROUTES.get(skill) != (cmd.server, cmd.tool):
                return "requested skill does not route to this tool"
        if skill == "lookup_learner" and cmd.server == "roster":
            if skills is None:
                skills = self.cards[cmd.server].skills
            skill = next((s for s in skills if SKILL_ROUTES.get(s) == (cmd.server, cmd.tool)), "")
        if card is not None:
            if card.get("verified") is not True or skill not in skills:
                return "peer card or declared skill is not admitted"
        elif not admit_skill(self.cards[cmd.server], skill).admitted:
            return "peer card signature or declared skill is invalid"
        token = headers.get("delegation") or headers.get("delegation-token")
        if token is not None:
            if not isinstance(token, Mapping):
                return "malformed delegation token"
            admitted = verify_delegation(token, aud="a2a:" + cmd.server,
                                         call_index=cmd.call_index, expected_act=self.ctx.act,
                                         seen_token_ids=self.used_tokens)
            if not admitted.admitted:
                return "delegation token failed signature, audience, act, expiry, or replay check"
        return None

    def decide(self, cmd):
        """Return (ToolCall | None, reason, quarantine)."""
        rnd = self.ctx.round
        if rnd != self.round:
            self.round = rnd
            self.round_spend = 0
            self.local_leases.clear()
            rounds_left = max(1, 11 - rnd)
            self.round_allowance = min(11, max(1, min(self.remaining, int(self.ctx.credits)) // rounds_left))
        self.remaining = min(self.remaining, int(self.ctx.credits))
        headers = {}
        for key, value in cmd.headers.items():
            name = str(key).lower()
            if name in headers and headers[name] != value:
                return None, "conflicting header aliases", False
            headers[name] = value
        ident_error = self._identity(cmd, headers)
        if ident_error:
            return None, ident_error, True
        act = learner_key(self.ctx.act)
        for key in ("learner", "learner_id", "act"):
            if cmd.args.get(key) and learner_key(cmd.args[key]) != act:
                return None, "target belongs to another learner; authority derives from ctx.act", True
        for key in ("subject", "target", "anchor"):
            target = cmd.args.get(key)
            if isinstance(target, str) and target.lower().startswith("learner:") and learner_key(target) != act:
                return None, "cross-learner access", True
        if any(key in cmd.args for key in ("route", "_route", "replica")) or "x-mcp-body-route" in headers:
            return None, "routing information must come from the transport header", True
        # Queries may legitimately discuss prompt injection; scan content-shaped fields only.
        for key in ("note", "body", "content", "instructions"):
            text = cmd.args.get(key)
            if isinstance(text, str) and scan_for_injected_instructions(text).suspicious:
                return None, "retrieved content attempts to direct privileged actions", True
        server, tool = successor_of(cmd.server, cmd.tool) or (cmd.server, cmd.tool)
        spec = TOOL_SPECS.get((server, tool))
        if spec is None:
            return None, "tool is absent from the frozen catalogue", False
        needed_scope = "wiki.write:" + server if spec.is_write else "wiki.read"
        if needed_scope not in self.ctx.scopes:
            return None, "required scope is not granted: " + needed_scope, False
        if spec.needs_lease:
            live = cmd.lease_id in self.ctx.leases if cmd.lease_id else False
            minted = self.local_leases.get(cmd.lease_id)
            if minted:
                live = minted[0] == rnd and 1 <= cmd.call_index - minted[1] <= 3
            if not live:
                return None, "get_frame requires a live lease from this exchange", False
        replica = headers.get("mcp-replica")
        if replica is not None and replica not in ("w", "c"):
            return None, "invalid replica header", False
        anchor = cmd.args.get("anchor")
        anchor_rev = None
        if isinstance(anchor, str):
            try:
                anchor_rev = Anchor.parse(anchor).rev
            except AnchorSyntaxError:
                return None, "malformed anchor", False
        if replica and anchor_rev and replica != anchor_rev:
            return None, "replica header disagrees with the requested anchor", True
        # Pin the requested edition. Freshness is determined by evidence in the answer,
        # never guessed from the letter c or the frame count.
        headers["mcp-replica"] = anchor_rev or replica or "w"
        fields = tuple(cmd.fields)
        if fields == ("*",) or not fields:
            fields = NARROW_MASKS.get((server, tool), spec.default_fields)
        if (cmd.server, cmd.tool) != (server, tool):
            fields = tuple(f for f in fields if f in spec.all_fields) or spec.default_fields
        if any(f not in spec.all_fields for f in fields):
            return None, "field mask contains an unsupported field", False
        fields = cheap_mask(server, tool, fields)
        args = dict(cmd.args)
        if "limit" in args:
            try:
                if isinstance(args["limit"], bool):
                    raise ValueError("boolean limit")
                args["limit"] = max(1, min(3, int(args["limit"])))
            except (ValueError, TypeError, OverflowError):
                return None, "limit must be an integer", False
        if server == "slides" and tool == "query" and "limit" not in args:
            args["limit"] = 3
        write_key = operation = None
        if spec.is_write:
            if not args.get("anchor"):
                return None, "write requires an anchor for its provenance precondition", False
            if server == "progress" and learner_key(args.get("learner", "")) != act:
                return None, "progress writes must explicitly name ctx.act", False
            provenance = self.provenance.get(str(args["anchor"]))
            if not provenance or provenance[2] != rnd:
                return None, "write requires trusted provenance from this round", False
            if headers.get("if-match") not in (None, provenance[0]):
                return None, "If-Match differs from the trusted provenance etag", False
            operation = json.dumps([server, tool, args], ensure_ascii=False, sort_keys=True)
            if operation in self.write_operations:
                return None, "write was already authorized; verify its outcome before any retry", False
            headers["if-match"] = provenance[0]
            write_key = headers.get("idempotency-key")
            if write_key is None:
                payload = operation + ":" + provenance[0] + ":" + str(self.ctx.sub)
                write_key = "write-" + hashlib.sha256(payload.encode()).hexdigest()[:24]
            if not isinstance(write_key, str) or not write_key or write_key in self.write_keys:
                return None, "invalid or previously authorized idempotency key", False
            headers["idempotency-key"] = write_key
        rate = spec.rate_limit
        recent = self.rates.get((server, tool), [])
        if rate and sum(1 for r in recent if rnd - rate[1] + 1 <= r <= rnd) >= rate[0]:
            return None, "tool rate window exhausted", False
        rows = args.get("limit", 1) if spec.row_weight else 0
        if (server, tool) == ("registry", "list_servers"):
            rows = 7
        draft = ToolCall(server=server, tool=tool, args=args, fields=fields,
                         headers=headers, lease_id=cmd.lease_id, call_index=cmd.call_index)
        cost = cost_of(draft, n_rows=rows)
        if cost > self.remaining or self.round_spend + cost > self.round_allowance:
            return None, "call exceeds available credits or the paced round allowance", False
        if server in A2A_PEERS:
            token = headers.get("delegation") or headers.get("delegation-token")
            if token is None:
                token = mint_delegation(act=self.ctx.act, sub=self.ctx.sub,
                                        aud="a2a:" + server, ttl=1, call_index=cmd.call_index,
                                        nonce=rnd).to_dict()
                headers["delegation"] = token
            self.used_tokens.add(token["token_id"])
        call = ToolCall(server=server, tool=tool, args=args, fields=fields,
                        headers=headers, lease_id=cmd.lease_id, call_index=cmd.call_index)
        if write_key:
            self.write_keys.add(write_key)
            self.write_operations.add(operation)
        self.rates.setdefault((server, tool), []).append(rnd)
        self.round_spend += cost
        self.remaining -= cost
        return call, "validated identity, authority, protocol and budget", False
