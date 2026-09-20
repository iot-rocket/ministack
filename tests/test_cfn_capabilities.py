"""The capability document and the README table it generates.

`GET /_ministack/cfn/capabilities` reports what the CloudFormation service
supports, read out of the package's own source with `ast`. These tests hold it
to that: the document has to match the registry, and the README's resource
table has to match the document, so neither can go stale while the other moves.
"""

import json
import re
import subprocess
import sys
import urllib.request
import uuid
from pathlib import Path

import pytest
from botocore.exceptions import ClientError
from conftest import ENDPOINT

from ministack.services.cloudformation import capabilities
from ministack.services.cloudformation.engine import (
    _apply_transforms,
    _resolve_parameters,
    _resolve_refs,
    validate_template_support,
)
from ministack.services.cloudformation.provisioners import (
    _RESOURCE_HANDLERS,
    _cfn_nested_stack_deploy,
)

REPO = Path(__file__).resolve().parents[1]


@pytest.fixture(scope="module")
def caps():
    return capabilities.build(REPO)


def test_capabilities_endpoint_serves_the_document():
    with urllib.request.urlopen(f"{ENDPOINT}/_ministack/cfn/capabilities") as resp:
        assert resp.status == 200
        assert resp.headers["Content-Type"] == "application/json"
        doc = json.loads(resp.read())
    assert doc["schema_version"] == capabilities._SCHEMA_VERSION
    for key in ("resource_types", "actions", "intrinsics", "pseudo_parameters", "features"):
        assert doc[key], f"{key} is empty"
    assert doc["resource_types"].keys() == set(_RESOURCE_HANDLERS)


def test_capabilities_endpoint_reports_the_health_version():
    """The document and `/_ministack/health` name the same build. A released
    image ships the package without `pyproject.toml`, so a version read from
    the manifest answered "unknown" there while health answered the release."""
    with urllib.request.urlopen(f"{ENDPOINT}/_ministack/cfn/capabilities") as resp:
        doc = json.loads(resp.read())
    with urllib.request.urlopen(f"{ENDPOINT}/_ministack/health") as resp:
        health = json.loads(resp.read())
    assert doc["ministack_version"] == health["version"]


def test_document_reports_the_running_version(monkeypatch):
    """The running package's version wins over a manifest beside it, so an
    image built with MINISTACK_VERSION reports that, as health does."""
    from ministack import app

    monkeypatch.setattr(app, "_VERSION", "0.0.0-capabilities-test")
    assert capabilities.build()["ministack_version"] == "0.0.0-capabilities-test"


def test_document_reports_the_registry_verbatim(caps):
    """Every registered type, with every verb its entry declares.

    Not a fixed three: `snapshot` arrived with `DeletionPolicy: Snapshot` in
    v1.5.14, and this is the assertion that makes the next one show up instead
    of being silently dropped. The `*_with_logical_id` flags are calling
    convention, so they are not verbs.
    """
    assert caps["resource_types"].keys() == set(_RESOURCE_HANDLERS)
    for rtype, entry in _RESOURCE_HANDLERS.items():
        verbs = set(caps["resource_types"][rtype]["verbs"])
        declared = {v for v in entry if v != "attributes" and not v.endswith("_with_logical_id")}
        assert verbs == declared, rtype


def test_a_verb_beyond_the_crud_three_is_reported(caps):
    """`snapshot` is in the document, not filtered out by a hardcoded list."""
    snapshot_types = {t for t, e in _RESOURCE_HANDLERS.items() if "snapshot" in e}
    assert snapshot_types, "no type declares snapshot any more; retarget this test"
    for rtype in snapshot_types:
        assert "snapshot" in caps["resource_types"][rtype]["verbs"], rtype


def test_readme_resource_table_matches_the_document(caps):
    """The generator is the gate: a type added to the registry without running
    `scripts/cfn_capabilities.py --readme` fails here rather than leaving the
    README quietly short, which is how it drifted to 93 rows for 143 types."""
    text = (REPO / "README.md").read_text()
    start = text.index("| Resource Type | Ref Returns | GetAtt |")
    end = text.index("\n\n", start)
    rows = text[start:end].splitlines()[2:]
    listed = [re.sub(r"\s*\(nested\)$", "", r.strip("|").split("|")[0].strip()).strip("`") for r in rows]
    assert listed == sorted(listed), "the table is not in type order"
    assert set(listed) == set(caps["resource_types"])


def test_generator_is_idempotent(tmp_path):
    """Exercise the CLI on a copy so tests never rewrite the checkout. The
    generator reads only the files it fingerprints and the README."""
    for rel in capabilities._FILES.values():
        (tmp_path / rel).parent.mkdir(parents=True, exist_ok=True)
        (tmp_path / rel).write_bytes((REPO / rel).read_bytes())
    before = (REPO / "README.md").read_bytes()
    (tmp_path / "README.md").write_bytes(before)
    subprocess.run(
        [sys.executable, str(REPO / "scripts" / "cfn_capabilities.py"), "--src", str(tmp_path), "--readme"],
        cwd=REPO, check=True, capture_output=True,
    )
    assert (tmp_path / "README.md").read_bytes() == before


def test_attributes_come_from_the_create_handlers(caps):
    """A type whose attributes are template-dependent reports None rather than
    an empty list, so a pre-flight can tell "no attributes" from "unknowable"."""
    for rtype in capabilities._DYNAMIC_ATTRIBUTE_TYPES & set(caps["resource_types"]):
        assert caps["resource_types"][rtype]["attributes"] is None
    sqs = caps["resource_types"]["AWS::SQS::Queue"]["attributes"]
    assert sqs is not None and "Arn" in sqs


def test_build_without_a_manifest_still_answers(tmp_path, monkeypatch):
    """The released images copy the package but not pyproject.toml. Read from
    such a tree, the running package still reports its own version; only a
    checkout named explicitly, which carries no manifest, has none to report."""
    from ministack import app

    (tmp_path / capabilities._PKG).mkdir(parents=True)
    for rel in capabilities._FILES.values():
        (tmp_path / rel).write_bytes((REPO / rel).read_bytes())
    monkeypatch.setattr(capabilities, "_DEFAULT_SRC", tmp_path)
    doc = capabilities.build()
    assert doc["ministack_version"] == app._version()
    assert doc["resource_types"].keys() == set(_RESOURCE_HANDLERS)
    assert capabilities.build(tmp_path)["ministack_version"] == "unknown"


def test_a_named_tree_is_described_by_its_own_declarations(caps):
    """`--src` reads the named tree's feature table, which for this checkout
    is the one the running package serves."""
    assert caps["features"] == capabilities.build()["features"]
    assert caps["features"]["ResourceImport"]["support"] == "unsupported"


def test_an_older_source_reports_what_it_lacks_as_unknown(tmp_path):
    """A tree from before a structure this module reads (no resolver
    functions, no SSM prefix, no feature table, missing files) still yields a
    document: the missing parts are None or empty, the rest is read."""
    pkg = tmp_path / capabilities._PKG
    pkg.mkdir(parents=True)
    (pkg / "provisioners.py").write_text(
        "def _create_queue(logical_id, props, stack_name):\n"
        "    return 'q', {'Arn': 'arn', 'QueueName': 'q'}\n\n"
        "_RESOURCE_HANDLERS = {'AWS::SQS::Queue': {'create': _create_queue}}\n")
    (pkg / "handlers.py").write_text("_ACTION_HANDLERS = {'CreateStack': None}\n")
    (pkg / "engine.py").write_text("def _unrelated():\n    return None\n")
    doc = capabilities.build(tmp_path)
    assert doc["resource_types"]["AWS::SQS::Queue"]["attributes"] == ["Arn", "QueueName"]
    assert doc["actions"] == ["CreateStack"]
    assert doc["intrinsics"] == {"resolve": None, "conditions": None}
    assert doc["pseudo_parameters"] == {"Ref": None, "Fn::Sub": None}
    assert doc["parameter_types"]["resolved_prefix"] is None
    assert doc["parameter_types"]["validated"] is None
    assert doc["features"] == {}
    assert set(doc["source"]["files_sha256"]) == {
        str(capabilities._FILES[k]) for k in ("provisioners", "engine", "handlers")}


def test_unrecognized_resource_type_is_reported_and_rejected_preflight(caps):
    assert caps["features"]["UnrecognizedResourceType"]["support"] == "rejected-preflight"
    template = {"Resources": {"Thing": {"Type": "AWS::Nope::Thing"}}}
    with pytest.raises(ValueError, match=r"Unrecognized resource types: \[AWS::Nope::Thing\]"):
        validate_template_support(template, {})


def test_unknown_getatt_is_reported_and_fails_resolution(caps):
    assert caps["features"]["GetAttUnknownAttribute"]["support"] == "stack-fails-at-resolution"
    resources = {"Queue": {"PhysicalResourceId": "q", "ResourceType": "AWS::SQS::Queue",
                           "Attributes": {"Arn": "arn:aws:sqs:us-east-1:000000000000:q"}}}
    with pytest.raises(ValueError):
        _resolve_refs({"Fn::GetAtt": ["Queue", "Nope"]}, resources, {}, {}, {}, "s", "id")


def test_nested_stack_is_reported_and_requires_a_template_url(caps):
    assert caps["features"]["NestedStacks"] == {"support": "supported", "note": "TemplateURL only"}
    assert "AWS::CloudFormation::Stack" in caps["resource_types"]
    with pytest.raises(ValueError, match="requires TemplateURL"):
        _cfn_nested_stack_deploy("Child", {"TemplateBody": "{}"}, "parent")


def test_rules_are_reported_and_enforced(caps, cfn):
    assert caps["features"]["Rules"]["support"] == "supported"
    template = {
        "Parameters": {"Env": {"Type": "String"}},
        "Rules": {"ProdOnly": {"Assertions": [{
            "Assert": {"Fn::Equals": [{"Ref": "Env"}, "prod"]},
            "AssertDescription": "Env must be prod",
        }]}},
        "Resources": {"Handle": {"Type": "AWS::CloudFormation::WaitConditionHandle"}},
    }
    name = f"caps-rules-{uuid.uuid4().hex[:8]}"
    with pytest.raises(ClientError, match="Env must be prod"):
        cfn.create_stack(StackName=name, TemplateBody=json.dumps(template),
                         Parameters=[{"ParameterKey": "Env", "ParameterValue": "dev"}])


def test_an_update_without_changes_is_reported_and_rejected(caps, cfn):
    assert caps["features"]["UpdateNoChanges"]["support"] == "rejected"
    body = json.dumps({"Resources": {"Handle": {"Type": "AWS::CloudFormation::WaitConditionHandle"}}})
    name = f"caps-noop-{uuid.uuid4().hex[:8]}"
    cfn.create_stack(StackName=name, TemplateBody=body)
    try:
        cfn.get_waiter("stack_create_complete").wait(
            StackName=name, WaiterConfig={"Delay": 1, "MaxAttempts": 30})
        with pytest.raises(ClientError, match="No updates are to be performed"):
            cfn.update_stack(StackName=name, TemplateBody=body)
    finally:
        cfn.delete_stack(StackName=name)


def test_language_extensions_are_reported_and_applied(caps):
    assert "AWS::LanguageExtensions" in caps["features"]["Transform"]["supported"]
    result = _apply_transforms({
        "Transform": "AWS::LanguageExtensions",
        "Resources": {"Fn::ForEach::Queues": ["Id", ["One", "Two"], {
            "Queue${Id}": {"Type": "AWS::SQS::Queue"},
        }]},
    })
    assert set(result["Resources"]) == {"QueueOne", "QueueTwo"}


def test_include_is_reported_and_applied(caps, monkeypatch):
    from ministack.services.cloudformation import engine

    assert "AWS::Include" in caps["features"]["Transform"]["supported"]
    snippet = {"Queue": {"Type": "AWS::SQS::Queue"}}
    monkeypatch.setattr(engine, "_fetch_include_snippet", lambda location: snippet)
    result = _apply_transforms({"Resources": {"Fn::Transform": {
        "Name": "AWS::Include", "Parameters": {"Location": "s3://test/snippet.json"},
    }}})
    assert result["Resources"] == snippet


def test_list_number_validation_is_reported_and_enforced(caps):
    assert "List<Number>" in caps["parameter_types"]["validated"]
    template = {"Parameters": {"Values": {"Type": "List<Number>"}}}
    with pytest.raises(ValueError, match="List<Number>"):
        _resolve_parameters(template, [{"Key": "Values", "Value": "1,wrong"}])


def test_malformed_registry_raises_an_endpoint_catchable_error():
    mod = capabilities._Module("_RESOURCE_HANDLERS = build_registry()", "example.py")
    with pytest.raises(ValueError, match="literal dict"):
        capabilities._registry(mod)
