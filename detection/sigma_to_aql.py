#!/usr/bin/env python3
"""sigma_to_aql.py — Convert Sigma rules to IBM QRadar AQL with pySigma.

Conversion engine behind detection/sigma-to-aql.sh. It drives the same
backend and pipelines as `sigma convert -t q_radar_aql` (pySigma 0.11.x,
pySigma-backend-QRadar-AQL 0.3.2) and adds two things sigma-cli cannot:

  --mapping FILE   extend the backend's Sigma -> QRadar field table with
                   environment-specific properties (custom event properties
                   such as SysmonQueryName, or native columns such as
                   sourceip). Without it the backend treats those Sigma
                   fields as unsupported: the payload pipeline degrades them
                   to `LOWER(UTF8(payload)) LIKE`, the fields pipeline
                   refuses the rule.
  CIDR workaround  backend 0.3.2 crashes on every `|cidr` value
                   ("'SigmaCIDRExpression' object has no attribute
                   'contains_special'") although it can render INCIDR().
                   The guard below skips the host-field value rewrite for
                   non-string values so INCIDR() is emitted. Disable with
                   --no-cidr-workaround to reproduce stock behaviour.

Usage:   sigma_to_aql.py [--pipeline payload|fields] [--mapping FILE]
                         [--no-cidr-workaround] RULE_FILE
         sigma_to_aql.py --self-check

Version:   0.1.0
Author:    Pavol Kluka | https://github.com/pavolkluka/soc-toolkit
Date:      2026-11-05

stdout carries only the generated AQL (one query per line); diagnostics
and pySigma warnings go to stderr. Exit codes: 0 converted, 1 conversion
failed, 2 bad arguments / missing input / missing toolchain.
"""

import argparse
import io
import sys
import warnings
from contextlib import redirect_stderr

PIPELINES = ("payload", "fields")
VERSION = "0.1.0"


def load_toolchain():
    """Import pySigma and the QRadar backend; exit 2 with a clear message if absent."""
    try:
        import sigma.mapping.fields as fields
        import sigma.pipelines.QRadarAQL.QRadarAQL as qradar_pipeline
        from sigma.backends.QRadarAQL import QRadarAQLBackend
        from sigma.collection import SigmaCollection
        from sigma.pipelines.QRadarAQL import (
            QRadarAQL_fields_pipeline,
            QRadarAQL_payload_pipeline,
        )
        from sigma.types import SigmaString
    except ImportError as exc:  # pragma: no cover - environment error
        print(f"[ERROR] pySigma QRadar toolchain not importable: {exc}", file=sys.stderr)
        print("[ERROR] Run venv-setup/setup.sh first.", file=sys.stderr)
        sys.exit(2)
    return {
        "fields": fields,
        "pipeline_module": qradar_pipeline,
        "backend": QRadarAQLBackend,
        "collection": SigmaCollection,
        "pipelines": {"payload": QRadarAQL_payload_pipeline, "fields": QRadarAQL_fields_pipeline},
        "SigmaString": SigmaString,
    }


def load_mapping(path):
    """Read a YAML mapping file: {field_mapping: {SigmaField: QRadarProperty | [..]}}."""
    import yaml  # dependency of pySigma, always present in the venv

    with open(path, encoding="utf-8") as handle:
        data = yaml.safe_load(handle) or {}
    mapping = data.get("field_mapping")
    if not isinstance(mapping, dict) or not mapping:
        raise ValueError(f"{path}: expected a non-empty 'field_mapping' dictionary")
    for sigma_field, target in mapping.items():
        ok = isinstance(target, str) or (
            isinstance(target, list) and target and all(isinstance(t, str) for t in target)
        )
        if not isinstance(sigma_field, str) or not ok:
            raise ValueError(
                f"{path}: '{sigma_field}' must map to a string or a list of strings"
            )
    return mapping


def apply_mapping(tc, mapping):
    """Extend the backend's shared field table in place.

    pySigma-backend-QRadar-AQL builds its pipelines around one module-level
    dict (sigma.mapping.fields.aql_field_mapping): the field-rename step, the
    fields-pipeline "unsupported field" check and the payload-pipeline
    degradation all look at that same object, so updating it in place is
    enough for every code path to accept the added fields.
    """
    tc["fields"].aql_field_mapping.update(mapping)


def apply_cidr_workaround(tc):
    """Guard HostFieldsValueTransformation.apply_value against non-string values."""
    transformation = tc["pipeline_module"].HostFieldsValueTransformation
    if getattr(transformation, "_soc_toolkit_patched", False):
        return
    original = transformation.apply_value
    sigma_string = tc["SigmaString"]

    def apply_value(self, field, val):
        if not isinstance(val, sigma_string):
            return None
        return original(self, field, val)

    transformation.apply_value = apply_value
    transformation._soc_toolkit_patched = True


def convert(tc, rule_text, pipeline_name):
    """Return the list of AQL queries for one rule file's text."""
    pipeline = tc["pipelines"][pipeline_name]()
    backend = tc["backend"](pipeline)
    collection = tc["collection"].from_yaml(rule_text)
    captured = io.StringIO()
    with warnings.catch_warnings(record=True) as caught, redirect_stderr(captured):
        warnings.simplefilter("always")
        queries = backend.convert(collection)
    for warning in caught:
        if issubclass(warning.category, DeprecationWarning):
            continue  # pyparsing/pySigma API deprecations are noise for rule authors
        print(f"[WARN] {warning.message}", file=sys.stderr)
    if captured.getvalue().strip():
        print(captured.getvalue().rstrip(), file=sys.stderr)
    return queries


def self_check(tc):
    """Convert a minimal inline rule through both pipelines; exit 1 on failure."""
    rule = (
        "title: self-check\n"
        "logsource: {category: process_creation, product: windows}\n"
        "detection:\n"
        "  selection: {Image|endswith: '\\\\x.exe'}\n"
        "  filter: {CommandLine|contains: 'ok'}\n"
        "  condition: selection and not filter\n"
    )
    for name in PIPELINES:
        try:
            query = convert(tc, rule, name)[0]
        except Exception as exc:  # noqa: BLE001 - report any failure
            print(f"[ERROR] self-check ({name}): {type(exc).__name__}: {exc}", file=sys.stderr)
            print(
                "[ERROR] A rule with `not` failed to parse — check the pyparsing pin "
                "(requirements.txt, docs/tool-deps.md).",
                file=sys.stderr,
            )
            return 1
        if "NOT" not in query:
            print(f"[ERROR] self-check ({name}): NOT missing in: {query}", file=sys.stderr)
            return 1
    print("[INFO] self-check OK: `not` conditions parse, both pipelines convert.", file=sys.stderr)
    return 0


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Convert a Sigma rule to IBM QRadar AQL (pySigma engine).",
        add_help=True,
    )
    parser.add_argument("rule", nargs="?", help="Sigma rule file (*.yml / *.yaml)")
    parser.add_argument("--pipeline", choices=PIPELINES, default="payload",
                        help="qradar-aql-payload (default) or qradar-aql-fields")
    parser.add_argument("--mapping", metavar="FILE",
                        help="YAML file with field_mapping: {SigmaField: QRadarProperty}")
    parser.add_argument("--no-cidr-workaround", action="store_true",
                        help="do not patch the backend's |cidr crash (stock behaviour)")
    parser.add_argument("--self-check", action="store_true",
                        help="convert a built-in rule with `not` and exit")
    parser.add_argument("--version", action="version", version=f"%(prog)s {VERSION}")
    args = parser.parse_args(argv)

    tc = load_toolchain()
    if not args.no_cidr_workaround:
        apply_cidr_workaround(tc)
    if args.mapping:
        try:
            mapping = load_mapping(args.mapping)
        except (OSError, ValueError) as exc:
            print(f"[ERROR] mapping file: {exc}", file=sys.stderr)
            return 2
        apply_mapping(tc, mapping)
        print(f"[INFO] Field mapping extended with {len(mapping)} entries from {args.mapping}",
              file=sys.stderr)

    if args.self_check:
        return self_check(tc)
    if not args.rule:
        parser.print_usage(sys.stderr)
        print("[ERROR] Missing rule file.", file=sys.stderr)
        return 2
    try:
        with open(args.rule, encoding="utf-8") as handle:
            rule_text = handle.read()
    except OSError as exc:
        print(f"[ERROR] Cannot read rule: {exc}", file=sys.stderr)
        return 2
    try:
        queries = convert(tc, rule_text, args.pipeline)
    except Exception as exc:  # noqa: BLE001 - any pySigma error is a conversion failure
        print(f"[ERROR] Conversion failed: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1
    for query in queries:
        print(query)
    return 0


if __name__ == "__main__":
    sys.exit(main())
