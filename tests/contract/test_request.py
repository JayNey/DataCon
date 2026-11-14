import json

import pytest

from datacon.contracts import DEFAULT_LIMITS, InvalidRequest, parse_request
from datacon.store import initial_state

REQUEST = {
    "schema_version": 1,
    "cve_id": "CVE-2099-0001",
    "target": {
        "kind": "source",
        "case_id": "fixture-c-parser",
        "goal": "验证固定输入在缺陷版触发预期 ASan 异常",
    },
}


def payload(**overrides):
    return json.dumps(REQUEST | overrides, ensure_ascii=False)


def test_defaults_are_filled_when_limits_are_omitted():
    assert parse_request(payload())["limits"] == DEFAULT_LIMITS


def test_oversized_request_is_rejected_before_parsing():
    oversized = payload(goal="x" * (64 * 1024))
    with pytest.raises(InvalidRequest, match="exceeds"):
        parse_request(oversized)
    with pytest.raises(InvalidRequest, match="exceeds"):
        parse_request(oversized.encode("utf-8"))


def test_partial_limits_are_merged_with_defaults():
    request = parse_request(payload(limits={"execute_seconds": 5, "replay_seconds": 5}))
    assert request["limits"] == DEFAULT_LIMITS | {
        "execute_seconds": 5,
        "replay_seconds": 5,
    }


@pytest.mark.parametrize("key", DEFAULT_LIMITS)
def test_each_budget_accepts_its_declared_maximum(key):
    request = parse_request(payload(limits={key: DEFAULT_LIMITS[key]}))
    assert request["limits"][key] == DEFAULT_LIMITS[key]


@pytest.mark.parametrize("key", DEFAULT_LIMITS)
def test_each_budget_rejects_one_above_its_maximum(key):
    with pytest.raises(InvalidRequest):
        parse_request(payload(limits={key: DEFAULT_LIMITS[key] + 1}))


@pytest.mark.parametrize(
    "overrides",
    [
        {"schema_version": True},
        {"schema_version": 2},
        {"schema_version": 1.0},
        {"schema_version": "1"},
        {"cve_id": "cve-2099-0001"},
        {"cve_id": "CVE-99-0001"},
        {"cve_id": "CVE-2099-001"},
        {"cve_id": "CVE-2099-0001x"},
        {"cve_id": "CVE-2099-0001\x00"},
        {"cve_id": ""},
        {"cve_id": 1},
        {"target": {"kind": "script", "case_id": "fixture-c-parser", "goal": "x"}},
        {"target": {"kind": "source", "case_id": "..", "goal": "x"}},
        {"target": {"kind": "source", "case_id": "fixture-c-parser", "goal": "  "}},
        {"target": {"kind": "source", "case_id": "fixture-c-parser", "goal": "x\x00y"}},
        {"target": {"kind": "source", "case_id": "fixture-c-parser"}},
        {"target": {"kind": "source", "case_id": "fixture-c-parser", "goal": "x", "extra": 1}},
        {"limits": None},
        {"limits": []},
        {"limits": {"cpu": True}},
        {"limits": {"cpu": 1.0}},
        {"limits": {"cpu": 0}},
        {"limits": {"cpu": -1}},
        {"limits": {"cpu": "2"}},
        {"limits": {"unknown": 1}},
        {"limits": {"execute_seconds": 9}},
        {"unknown": 1},
    ],
)
def test_invalid_values_are_rejected(overrides):
    with pytest.raises(InvalidRequest):
        parse_request(payload(**overrides))


def test_missing_required_fields_are_rejected():
    for key in ("schema_version", "cve_id", "target"):
        request = dict(REQUEST)
        del request[key]
        with pytest.raises(InvalidRequest):
            parse_request(json.dumps(request))


def test_binary_target_is_accepted_and_archived_as_blocked_on_submit():
    request = parse_request(payload(target=REQUEST["target"] | {"kind": "binary"}))
    assert request["target"]["kind"] == "binary"
    assert initial_state(request) == ("BLOCKED", "UNSUPPORTED_TARGET")


@pytest.mark.parametrize(
    "document",
    [
        '{"schema_version":1,"schema_version":1,"cve_id":"CVE-2099-0001",'
        '"target":{"kind":"source","case_id":"fixture-c-parser","goal":"x"}}',
        '{"schema_version":1,"cve_id":"CVE-2099-0001",'
        '"target":{"kind":"source","kind":"source","case_id":"fixture-c-parser","goal":"x"}}',
        '{"schema_version":1,"cve_id":"CVE-2099-0001",'
        '"target":{"kind":"source","case_id":"fixture-c-parser","goal":"x"},'
        '"limits":{"cpu":2,"cpu":2}}',
    ],
)
def test_duplicate_json_keys_are_rejected_at_every_level(document):
    with pytest.raises(InvalidRequest):
        parse_request(document)


@pytest.mark.parametrize(
    "document",
    [
        "[]",
        "null",
        '"request"',
        "{}",
        '{"schema_version":1,"cve_id":"CVE-2099-0001",'
        '"target":{"kind":"source","case_id":"fixture-c-parser","goal":NaN}}',
        '{"schema_version":1,"cve_id":"CVE-2099-0001",'
        '"target":{"kind":"source","case_id":"fixture-c-parser","goal":"x"}} trailing',
    ],
)
def test_malformed_documents_are_rejected(document):
    with pytest.raises(InvalidRequest):
        parse_request(document)


def test_invalid_utf8_bytes_are_rejected():
    with pytest.raises(InvalidRequest):
        parse_request(b'{"schema_version":1,"cve_id":"\xff"}')


def test_case_registry_must_match_the_cve():
    with pytest.raises(InvalidRequest):
        parse_request(payload(cve_id="CVE-2099-0002"))
