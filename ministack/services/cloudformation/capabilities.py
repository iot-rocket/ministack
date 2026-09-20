# Copyright (c) 2026 MiniStack Contributors. SPDX-License-Identifier: MIT
# Copies or substantial portions, including AI-assisted ports or rewrites, must retain this notice (see LICENSE).
"""
What the CloudFormation service supports, derived from its own source.

Reads this package with ``ast`` (executes nothing) and reports:

* every registered resource type with the verbs its registry entry declares
  (create, update, delete, snapshot) and the attributes its create handler
  returns,
* the API actions the service dispatches,
* the intrinsic functions and pseudo parameters the resolver understands,
* the maintained template-feature summary declared below.

Registry entries are extracted mechanically. Feature semantics are the
hand-maintained ``_TEMPLATE_FEATURE_SUPPORT`` declarations, not inferred from
comments or symbol names; ``tests/test_cfn_capabilities.py`` ties the
declarations it names to behavior.

A source tree read by ``build(src)`` may predate a structure this module reads
(a resolver function, a declared constant): that part of the document is then
``None`` (or empty), rather than the whole build failing.

The attribute sets are what MiniStack's create handlers return, which is what
``Fn::GetAtt`` resolves here. They are not AWS's GetAtt surface and are not
checked against it: a type can offer an attribute AWS does not document (the
Auto Scaling group's ``Arn``) or lack one AWS has. ``attributes_exact`` says the
extraction saw every return path, not that the set agrees with AWS.

Served by ``GET /_ministack/cfn/capabilities`` so tooling can ask a running
emulator what a template may use, and consumed by ``scripts/cfn_capabilities.py``
which also regenerates the README "Supported Resource Types" table from it.
"""

from __future__ import annotations

import ast
import hashlib
import re
from pathlib import Path

_PKG = Path("ministack/services/cloudformation")
# The tree to read. Defaults to this package's own, so a running emulator
# reports itself; a caller may point `build()` at any other source root.
_DEFAULT_SRC = Path(__file__).resolve().parents[3]
_FILES = {
    "provisioners": _PKG / "provisioners.py",
    "engine": _PKG / "engine.py",
    "handlers": _PKG / "handlers.py",
    "changesets": _PKG / "changesets.py",
    "stacks": _PKG / "stacks.py",
    "capabilities": _PKG / "capabilities.py",
}
_SCHEMA_VERSION = 1
# Types whose attributes depend on the template (nested stack outputs, custom
# resource Data) or on runtime state; the pre-flight skips GetAtt checks for them.
_DYNAMIC_ATTRIBUTE_TYPES = {
    "AWS::CloudFormation::Stack",
    "AWS::CloudFormation::CustomResource",
}

# Semantic limits of the service, maintained by hand alongside the
# implementation: a symbol's presence is not evidence that the corresponding
# operation is supported. Tests tie Transform, UnrecognizedResourceType,
# GetAttUnknownAttribute, Rules, UpdateNoChanges and NestedStacks to behavior;
# the other entries are declarations only.
_TEMPLATE_FEATURE_SUPPORT = {
    "UnrecognizedResourceType": {"support": "rejected-preflight"},
    "GetAttUnknownAttribute": {"support": "stack-fails-at-resolution"},
    "DynamicReferences": {
        "support": "supported",
        "note": "ssm, ssm-secure and secretsmanager references",
    },
    "Rules": {"support": "supported"},
    "DeletionPolicy": {"support": "supported"},
    "UpdateReplacePolicy": {"support": "supported"},
    "Capabilities": {
        "support": "enforced-with-auth",
        "note": "Reported in both modes; enforced when AUTH=true",
    },
    "Metadata": {"support": "supported"},
    "ParameterConstraints": {"support": "supported"},
    "Transform": {
        "support": "partial",
        "supported": ["AWS::Include", "AWS::LanguageExtensions", "AWS::Serverless-2016-10-31"],
        "note": "Include supports embedded Fn::Transform; SAM requires aws-sam-translator; custom macros are not executed",
    },
    "ResourceImport": {"support": "unsupported"},
    "UpdateNoChanges": {"support": "rejected"},
    "NestedStacks": {"support": "supported", "note": "TemplateURL only"},
    "CustomResources": {
        "support": "partial",
        "note": "Lambda-backed; SNS-backed unsupported",
    },
}


# ---------------------------------------------------------------- helpers
def _dict_keys(node: ast.AST) -> tuple[set[str], bool]:
    """Constant string keys of a dict literal; exact=False on any dynamic key."""
    keys: set[str] = set()
    exact = True
    if not isinstance(node, ast.Dict):
        return keys, False
    for k in node.keys:
        if isinstance(k, ast.Constant) and isinstance(k.value, str):
            keys.add(k.value)
        else:
            exact = False  # **spread or computed key
    return keys, exact


class _Module:
    def __init__(self, source: str, filename: str):
        self.tree = ast.parse(source, filename=filename)
        self.functions: dict[str, ast.FunctionDef] = {
            n.name: n for n in self.tree.body if isinstance(n, ast.FunctionDef)
        }
        self.assigns: dict[str, ast.AST] = {}
        for n in self.tree.body:
            if isinstance(n, ast.Assign):
                for t in n.targets:
                    if isinstance(t, ast.Name):
                        self.assigns[t.id] = n.value


def _returns(func: ast.FunctionDef) -> list[ast.AST]:
    """Return statements of a function, ignoring nested defs/lambdas."""
    out: list[ast.AST] = []

    def walk(node: ast.AST) -> None:
        for child in ast.iter_child_nodes(node):
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
                continue
            if isinstance(child, ast.Return) and child.value is not None:
                out.append(child.value)
            walk(child)

    walk(func)
    return out


def _name_bindings(func: ast.FunctionDef, name: str) -> tuple[set[str], bool]:
    """Keys a local dict variable can carry: literal assignment, ``d["k"] = v``
    and ``d.update({...})`` anywhere in the body. Exact only when every binding
    is a literal."""
    keys: set[str] = set()
    exact = True
    seen = False
    for node in ast.walk(func):
        if isinstance(node, ast.Assign):
            for t in node.targets:
                if isinstance(t, ast.Name) and t.id == name:
                    seen = True
                    k, e = _dict_keys(node.value)
                    keys |= k
                    exact &= e
                elif (
                    isinstance(t, ast.Subscript)
                    and isinstance(t.value, ast.Name)
                    and t.value.id == name
                ):
                    seen = True
                    if isinstance(t.slice, ast.Constant) and isinstance(
                        t.slice.value, str
                    ):
                        keys.add(t.slice.value)
                    else:
                        exact = False
        elif (
            isinstance(node, ast.Expr)
            and isinstance(node.value, ast.Call)
            and isinstance(node.value.func, ast.Attribute)
            and isinstance(node.value.func.value, ast.Name)
            and node.value.func.value.id == name
            and node.value.func.attr == "update"
        ):
            seen = True
            for arg in node.value.args:
                k, e = _dict_keys(arg)
                keys |= k
                exact &= e
            for kw in node.value.keywords:
                if kw.arg:
                    keys.add(kw.arg)
                else:
                    exact = False
    return keys, exact and seen


def _attrs_of_expr(
    expr: ast.AST, func: ast.FunctionDef, mod: _Module, depth: int
) -> tuple[set[str], bool]:
    """Attribute keys an expression evaluating to the attributes dict yields."""
    if isinstance(expr, ast.Dict):
        return _dict_keys(expr)
    if isinstance(expr, ast.Name):
        return _name_bindings(func, expr.id)
    if isinstance(expr, ast.Call) and isinstance(expr.func, ast.Name) and depth < 3:
        helper = mod.functions.get(expr.func.id)
        if helper is not None:
            return _attrs_of_returns(helper, mod, depth + 1, tuple_pos=None)
    return set(), False


def _attrs_of_returns(
    func: ast.FunctionDef, mod: _Module, depth: int, tuple_pos: int | None
) -> tuple[set[str], bool]:
    """Union of attribute keys over all return paths. ``tuple_pos=1`` takes the
    second element of a returned ``(physical_id, attrs)`` tuple; ``None`` means the
    function returns the attrs dict itself (or a tuple whose 2nd element is)."""
    keys: set[str] = set()
    exact = True
    rets = _returns(func)
    if not rets:
        return keys, False
    for value in rets:
        target = value
        if isinstance(value, ast.Tuple):
            if len(value.elts) == 2:
                target = value.elts[1]
            else:
                exact = False
                continue
        elif tuple_pos == 1:
            # ``return helper(...)`` / ``return name`` where the value is the tuple
            if isinstance(value, ast.Call) and isinstance(value.func, ast.Name):
                helper = mod.functions.get(value.func.id)
                if helper is not None and depth < 3:
                    k, e = _attrs_of_returns(helper, mod, depth + 1, tuple_pos=1)
                    keys |= k
                    exact &= e
                    continue
            exact = False
            continue
        k, e = _attrs_of_expr(target, func, mod, depth)
        keys |= k
        exact &= e
    return keys, exact


def _registry(mod: _Module) -> dict[str, dict]:
    node = mod.assigns.get("_RESOURCE_HANDLERS")
    if not isinstance(node, ast.Dict):
        raise ValueError("_RESOURCE_HANDLERS is not a literal dict")
    out: dict[str, dict] = {}
    for key, value in zip(node.keys, node.values):
        if not (
            isinstance(key, ast.Constant)
            and isinstance(key.value, str)
            and isinstance(value, ast.Dict)
        ):
            raise ValueError(
                f"non-literal registry entry near line {getattr(key, 'lineno', '?')}"
            )
        entry: dict[str, ast.AST] = {}
        for k, v in zip(value.keys, value.values):
            if isinstance(k, ast.Constant):
                entry[k.value] = v
        # Every verb the entry declares, not a fixed list: v1.5.14 added
        # `snapshot` for DeletionPolicy: Snapshot, and a document that names
        # three verbs would have gone quietly stale the day it landed. The
        # `*_with_logical_id` flags are calling convention, not capability.
        verbs = sorted(v for v in entry if v != "attributes" and not v.endswith("_with_logical_id"))
        create = entry.get("create")
        attrs: set[str] = set()
        exact = False
        if isinstance(create, ast.Name) and create.id in mod.functions:
            attrs, exact = _attrs_of_returns(
                mod.functions[create.id], mod, 0, tuple_pos=1
            )
        elif isinstance(create, ast.Lambda):
            body = create.body
            if isinstance(body, ast.Tuple) and len(body.elts) == 2:
                attrs, exact = _dict_keys(body.elts[1])
        declared = entry.get("attributes")
        if declared is not None:
            # Use a declared attribute list when available.
            if isinstance(declared, ast.Constant) and declared.value is None:
                attrs, exact = set(), False
            else:
                d, de = set(), True
                for elt in getattr(declared, "elts", []):
                    if isinstance(elt, ast.Constant):
                        d.add(elt.value)
                    else:
                        de = False
                attrs, exact = d, de
        if key.value in _DYNAMIC_ATTRIBUTE_TYPES:
            exact = False
        out[key.value] = {
            "verbs": verbs,
            "attributes": sorted(attrs) if exact else None,
            "attributes_exact": exact,
            "attributes_seen": sorted(attrs),
        }
    return out


def _actions(mod: _Module) -> list[str]:
    node = mod.assigns.get("_ACTION_HANDLERS")
    if not isinstance(node, ast.Dict):
        raise ValueError("_ACTION_HANDLERS is not a literal dict")
    return sorted(k.value for k in node.keys if isinstance(k, ast.Constant))


def _membership_constants(func: ast.FunctionDef | None) -> list[str] | None:
    """``"Fn::X" in value`` tests inside a function -> the constants; ``None``
    when the source has no such function."""
    if func is None:
        return None
    found: set[str] = set()
    for node in ast.walk(func):
        if (
            isinstance(node, ast.Compare)
            and isinstance(node.left, ast.Constant)
            and isinstance(node.left.value, str)
            and len(node.ops) == 1
            and isinstance(node.ops[0], ast.In)
            and (
                node.left.value.startswith("Fn::")
                or node.left.value in ("Ref", "Condition")
            )
        ):
            found.add(node.left.value)
    return sorted(found)


def _pseudo_maps(func: ast.FunctionDef | None) -> list[list[str]]:
    maps: list[list[str]] = []
    if func is None:
        return maps
    for node in ast.walk(func):
        if isinstance(node, ast.Assign) and any(
            isinstance(t, ast.Name) and t.id == "pseudo" for t in node.targets
        ):
            keys, _ = _dict_keys(node.value)
            maps.append(sorted(keys))
    return maps


def _features(declaring: _Module) -> dict[str, dict]:
    """The feature declarations of another tree's copy of this module; a
    source without them (older than the table) has an empty summary."""
    declared = declaring.assigns.get("_TEMPLATE_FEATURE_SUPPORT")
    return ast.literal_eval(declared) if declared is not None else {}


def _parameter_types(engine: _Module) -> dict:
    """Parameter types with an explicit conversion branch in the resolver.
    Either half is ``None`` when the source predates what it is read from."""
    resolver = engine.functions.get("_resolve_parameters")
    validated: set[str] | None = None
    if resolver is not None:
        validated = set()
        for node in ast.walk(resolver):
            if (isinstance(node, ast.Compare) and isinstance(node.left, ast.Name)
                    and node.left.id == "ptype" and len(node.ops) == 1
                    and isinstance(node.ops[0], ast.Eq)
                    and isinstance(node.comparators[0], ast.Constant)):
                validated.add(node.comparators[0].value)
    prefix = engine.assigns.get("_SSM_PARAMETER_VALUE_PREFIX")
    return {
        "resolved_prefix": ast.literal_eval(prefix) if prefix is not None else None,
        "validated": sorted(validated) if validated is not None else None,
        "note": "Other types retain string values; constraints may still apply",
    }


def build(src: Path | None = None) -> dict:
    """The document for the source root ``src``, or for the running package."""
    explicit = src is not None
    src = Path(src) if explicit else _DEFAULT_SRC
    # A file an older tree lacks is left out of the fingerprint; the registry
    # and the action table are required, so their absence still fails below.
    texts = {k: (src / p).read_text() for k, p in _FILES.items() if (src / p).is_file()}
    prov = _Module(texts.get("provisioners", ""), str(_FILES["provisioners"]))
    engine = _Module(texts.get("engine", ""), str(_FILES["engine"]))
    handlers = _Module(texts.get("handlers", ""), str(_FILES["handlers"]))
    resolve = engine.functions.get("_resolve_refs")
    conditions = engine.functions.get("_evaluate_conditions")
    pseudo = _pseudo_maps(resolve)
    if explicit:
        # Another tree's declarations, not this module's: a checkout named by
        # the caller is described by its own source throughout.
        features = _features(
            _Module(texts.get("capabilities", ""), str(_FILES["capabilities"])))
    else:
        features = _TEMPLATE_FEATURE_SUPPORT
    if explicit:
        version = "unknown"
        try:
            # A checkout named by the caller declares its own version; one
            # without the manifest reports "unknown" rather than failing the
            # whole document over the version line.
            m = re.search(
                r'^version\s*=\s*"([^"]+)"', (src / "pyproject.toml").read_text(), re.M
            )
        except OSError:
            m = None
        if m:
            version = m.group(1)
    else:
        # The running package reports what /_ministack/health reports. The
        # released images copy the package without pyproject.toml and set
        # MINISTACK_VERSION instead, so the manifest cannot answer there.
        from ministack.app import _version

        version = _version()
    return {
        "schema_version": _SCHEMA_VERSION,
        "ministack_version": version,
        "source": {
            "files_sha256": {
                str(p): hashlib.sha256(texts[k].encode()).hexdigest()[:16]
                for k, p in _FILES.items() if k in texts
            }
        },
        "resource_types": _registry(prov),
        "fallthrough": {
            "Custom::*": "custom",
            "AWS::CloudFormation::*": "unsupported",
            "*": "unsupported",
        },
        "actions": _actions(handlers),
        "intrinsics": {
            "resolve": _membership_constants(resolve),
            "conditions": _membership_constants(conditions),
        },
        "pseudo_parameters": {
            "Ref": pseudo[0] if pseudo else None,
            "Fn::Sub": pseudo[1] if len(pseudo) > 1 else None,
        },
        "parameter_types": _parameter_types(engine),
        "features": features,
    }


_CACHE: dict | None = None


def cached() -> dict:
    """The capability document for the running package (computed once)."""
    global _CACHE
    if _CACHE is None:
        _CACHE = build()
    return _CACHE
