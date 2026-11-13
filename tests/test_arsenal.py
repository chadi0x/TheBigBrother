"""Offline regression tests for the VX Sovereign Arsenal."""
from __future__ import annotations

import asyncio
import json

from the_big_brother.modules.arsenal import get_registry, run_tool
from the_big_brother.modules.arsenal.common import is_domain, normalize_domain, root_domain
from the_big_brother.modules.arsenal.advanced import (
    NPM_TOP,
    _parse_schema,
    _type_ref,
    _typosquat_match,
)
from the_big_brother.modules.arsenal.identity import (
    _analyze_jwt,
    _luhn,
    _password_strength,
    _vin_check_digit,
)


def run(coro):
    return asyncio.get_event_loop().run_until_complete(coro)


def test_registry_has_twenty_unique_tools():
    reg = get_registry()
    assert reg["version"] == "10.1.0"
    assert reg["total"] >= 20
    ids = [t["id"] for t in reg["tools"]]
    assert len(ids) == len(set(ids))
    for tool in reg["tools"]:
        assert tool["name"]
        assert tool["description"]
        assert tool["fields"]
        assert tool["fields"][0]["name"] == "target"


def test_jwt_detects_weak_secret():
    token = (
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
        "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ."
        "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
    )
    data, findings, risk, summary = _analyze_jwt(token)
    assert data["algorithm"] == "HS256"
    assert data["weak_secret"] == "your-256-bit-secret"
    assert any(f["severity"] == "critical" for f in findings)
    assert risk >= 50


def test_jwt_detects_alg_none():
    token = "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJhZG1pbiIsImV4cCI6OTk5OTk5OTk5OX0."
    data, findings, risk, _ = _analyze_jwt(token)
    assert data["algorithm"] == "none"
    assert any("alg=none" in f["title"].lower() or "unsigned" in f["title"].lower() for f in findings)


def test_password_strength_common_password():
    result = _password_strength("password123")
    assert result["score"] < 30
    assert "is a top-common password" in result["issues"]


def test_luhn_validation():
    assert _luhn("4242424242424242") is True
    assert _luhn("4242424242424241") is False


def test_vin_check_digit():
    assert _vin_check_digit("1HGCM82633A004352")["valid"] is True


def test_domain_helpers():
    assert normalize_domain("https://www.Example.com/path?q=1") == "example.com"
    assert is_domain("example.com")
    assert root_domain("news.example.co.uk") == ("example", ".co.uk")


def test_offline_tool_envelope_contract():
    result = run(run_tool("jwt_analyzer", {"target": "not-a-token"}))
    for key in ("status", "tool", "target", "risk_score", "risk_tier", "grade", "summary", "findings", "iocs", "data"):
        assert key in result
    json.dumps(result)


def test_missing_input_returns_error_envelope():
    result = run(run_tool("dns_intel", {"target": ""}))
    assert result["status"] == "error"
    assert "Input required" in result["summary"]


def test_registry_includes_flagship_engines():
    reg = get_registry()
    ids = {t["id"] for t in reg["tools"]}
    assert {"attack_surface", "origin_unmasker", "graphql_inspector", "supply_chain_audit"} <= ids
    assert reg["total"] == 24


def test_typosquat_detection():
    assert _typosquat_match("loadsh", NPM_TOP) == "lodash"
    assert _typosquat_match("lodash", NPM_TOP) is None


def test_graphql_type_ref_and_schema_parse():
    ref = {"kind": "NON_NULL", "name": None, "ofType": {"kind": "SCALAR", "name": "String", "ofType": None}}
    assert _type_ref(ref) == "String!"
    schema = {
        "queryType": {"name": "Query"},
        "mutationType": {"name": "Mutation"},
        "subscriptionType": None,
        "types": [
            {"kind": "OBJECT", "name": "Query", "fields": [
                {"name": "users", "type": {"name": "User", "kind": "OBJECT"}, "args": []},
                {"name": "password", "type": {"name": "String", "kind": "SCALAR"}, "args": []},
            ]},
            {"kind": "OBJECT", "name": "Mutation", "fields": [
                {"name": "deleteUser", "type": {"name": "Boolean", "kind": "SCALAR"}, "args": [{"name": "id"}]},
            ]},
        ],
    }
    parsed = _parse_schema(schema)
    assert parsed["query_count"] == 2
    assert any(f["field"] == "password" for f in parsed["sensitive_fields"])
    assert any(m["name"] == "deleteUser" for m in parsed["destructive_mutations"])
