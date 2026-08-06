#!/usr/bin/env python3
"""
soc-lookup.py — Combined IntelOwl + Yeti IOC lookup CLI for the F6 toolkit
                 layer (one observable, both sources, in parallel).

Usage:     soc-lookup <observable> [--type ip|domain|hash|url|generic]
                       [--json] [--yeti-only|--intelowl-only]
                       [--playbook WB_Lookup] [--timeout 300] [--no-wait]
                       [--force]

Tested on: py_compile / --help / doctest only (unit level). This script has
           NEVER been run against a live IntelOwl or Yeti instance: per
           handoff-f6-toolkit.md §3/§8/§9, those APIs are bound to
           127.0.0.1 on the user's notebook and are unreachable from this
           container or the REMnux VM used for QA. See the clearly delimited
           "UNVERIFIED AGAINST LIVE API" block below for every value that
           depends on a live-instance response shape.
Version:   0.1.0
Author:    Pavol Kluka | https://github.com/pavolkluka/soc-toolkit
Date:      2026-08-06
Platforms: Linux (Python 3.10+, run inside venv-setup/venv)

Environment variables:
    SOC_YETI_URL          Yeti base URL, e.g. http://127.0.0.1:8089
                           (required for the Yeti branch)
    SOC_YETI_APIKEY        Yeti API key, from Yeti UI profile -> API key
                           (required for the Yeti branch)
    SOC_INTELOWL_URL       IntelOwl base URL, e.g. http://127.0.0.1:8082
                           (required for the IntelOwl branch)
    SOC_INTELOWL_TOKEN     IntelOwl API token, from IntelOwl UI "API Access"
                           (required for the IntelOwl branch)

    Any of the above may instead be set in secrets/soc-lookup.env
    (KEY=VALUE lines, gitignored) as a fallback — see load_env_file().
    Real process environment variables always take precedence over the
    file (os.environ.setdefault() semantics).
"""

from __future__ import annotations

from concurrent.futures import Future, ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any, Optional
import ipaddress
import json
import os
import sys
import time
import urllib.parse

import click
import requests
from rich.console import Console
from rich.table import Table

# All human-readable rendering goes to stderr, always — regardless of
# --json — so that `soc-lookup ... --json | jq` only ever sees the JSON
# document written to stdout by render_output().
console = Console(stderr=True)


### CONFIG

REQUIRED_VARS: dict[str, list[str]] = {
    "yeti": ["SOC_YETI_URL", "SOC_YETI_APIKEY"],
    "intelowl": ["SOC_INTELOWL_URL", "SOC_INTELOWL_TOKEN"],
}

# soc-lookup.py lives at <repo>/lookup/soc-lookup.py, so parent.parent is
# the repo root. (While staged under temp/lookup/ this resolves to
# temp/secrets/soc-lookup.env instead — expected: the file becomes
# functional at its final promoted location, per the promotion gate.)
ENV_FILE: Path = Path(__file__).resolve().parent.parent / "secrets" / "soc-lookup.env"

# handoff-f6-toolkit.md §3 request-body example uses a hardcoded "CLEAR"
# TLP value and does not expose a --tlp CLI flag, so this is a fixed
# constant rather than a click option.
DEFAULT_TLP: str = "CLEAR"


def load_env_file(path: Path) -> None:
    """Load simple KEY=VALUE lines from `path` into os.environ.

    Blank lines and lines starting with '#' are skipped. Surrounding single
    or double quotes on the value are stripped. Uses os.environ.setdefault()
    so a real environment variable already set always wins over the file.
    Pure Python-side parsing — this never shells out to `source`. Silently
    does nothing if `path` does not exist (the file is an optional
    fallback, not a requirement).
    """
    if not path.is_file():
        return

    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if "=" not in line:
            continue

        key, _, value = line.partition("=")
        key = key.strip()
        value = value.strip()

        if len(value) >= 2 and value[0] == value[-1] and value[0] in ("'", '"'):
            value = value[1:-1]

        if key:
            os.environ.setdefault(key, value)


def get_config(need_yeti: bool, need_intelowl: bool) -> dict[str, str]:
    """Validate and return config for only the requested branch(es).

    Loads ENV_FILE first (as a fallback source), then checks only the
    REQUIRED_VARS entries for the branches actually requested (so
    --yeti-only validates only SOC_YETI_*, never SOC_INTELOWL_*). On any
    missing variable, prints the exact missing variable name(s) plus setup
    guidance via the rich stderr console and exits with code 3. This
    function is called synchronously before any ThreadPoolExecutor is
    created, so a config error can never be mistaken for a branch API
    failure.
    """
    load_env_file(ENV_FILE)

    wanted_vars: list[str] = []
    if need_yeti:
        wanted_vars.extend(REQUIRED_VARS["yeti"])
    if need_intelowl:
        wanted_vars.extend(REQUIRED_VARS["intelowl"])

    config: dict[str, str] = {}
    missing: list[str] = []
    for var in wanted_vars:
        value = os.environ.get(var)
        if not value:
            missing.append(var)
        else:
            config[var] = value

    if missing:
        console.print(
            f"[bold red]Missing required environment variable(s): "
            f"{', '.join(missing)}[/bold red]"
        )
        console.print(
            "Set them as environment variables, or add them to "
            f"[bold]{ENV_FILE}[/bold] (gitignored) as KEY=VALUE lines, e.g.:"
        )
        for var in missing:
            console.print(f"  {var}=<value>")
        sys.exit(3)

    return config


### TYPE DETECTION


def _is_valid_hostname_label(label: str) -> bool:
    """Return True if `label` is a valid DNS hostname label (relaxed RFC 1123)."""
    if not label or len(label) > 63:
        return False
    if label.startswith("-") or label.endswith("-"):
        return False
    return all(c.isalnum() or c == "-" for c in label)


def detect_type(value: str) -> str:
    """Autodetect the observable type: ip|domain|hash|url|generic.

    IP detection uses ipaddress.ip_address() in a try/except rather than a
    regex — a deliberate, observable-behaviour-preserving improvement over
    the handoff's literal "regex IP" wording (handoff-f6-toolkit.md §3,
    step 1): it correctly handles both IPv4 and IPv6 (including compressed
    forms) with no extra code, which a hand-rolled regex would not.

    --type on the CLI always overrides this function entirely; detect_type
    is not called at all when --type is given.

    >>> detect_type("8.8.8.8")
    'ip'
    >>> detect_type("2001:db8::1")
    'ip'
    >>> detect_type("example.com")
    'domain'
    >>> detect_type("d41d8cd98f00b204e9800998ecf8427e")
    'hash'
    >>> detect_type("da39a3ee5e6b4b0d3255bfef95601890afd80709")
    'hash'
    >>> detect_type("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
    'hash'
    >>> detect_type("http://example.com/path")
    'url'
    >>> detect_type("not an observable!!")
    'generic'
    """
    try:
        ipaddress.ip_address(value)
        return "ip"
    except ValueError:
        pass

    if len(value) in (32, 40, 64) and all(c in "0123456789abcdefABCDEF" for c in value):
        return "hash"

    split = urllib.parse.urlsplit(value)
    if split.scheme and split.netloc:
        return "url"

    if "." in value and " " not in value:
        labels = value.split(".")
        if len(labels) >= 2 and all(_is_valid_hostname_label(label) for label in labels):
            return "domain"

    return "generic"


# ============================================================================
# UNVERIFIED AGAINST LIVE API -- START
#
# soc-lookup has never been run against a live IntelOwl or Yeti instance:
# per handoff-f6-toolkit.md §3/§8/§9, those APIs are bound to 127.0.0.1 on
# the user's notebook and are unreachable from this container or the REMnux
# VM used for QA. Every literal request/response field or key name that
# could not be confirmed from handoff-f6-toolkit.md, the F5 handoff it
# cites, or a reachable upstream source lives in this block — one item per
# single-purpose function/constant, each tagged # TODO-VERIFY (handoff §3).
# A post-live-test fix should only ever need to touch this block, never the
# orchestration logic in yeti_branch() / intelowl_branch() / run_lookup().
# ============================================================================


def YETI_SEARCH_BODY(value: str) -> dict[str, Any]:
    """Build the Yeti POST /api/v2/observables/search request body.

    # CONFIRMED (handoff §8B live acceptance test, 2026-08-06): this exact
    # shape ({"query": {"value": ...}}) was verified against a live Yeti
    # instance -- --yeti-only returned exit 0 with real results. No longer a
    # TODO-VERIFY item; left in this block anyway (rather than moved out) so
    # the request/response contract for the whole Yeti auth+search round
    # trip stays documented together in one place.
    """
    return {"query": {"value": value}}


# CONFIRMED-PARTIAL (handoff §8B live acceptance test, 2026-08-06): the auth
# exchange (POST /api/v2/auth/api-token with header x-yeti-apikey, returning
# a Bearer token) succeeded live -- one of the two candidate keys below did
# match the real response and authentication worked end-to-end. The live
# result did not tell us which of the two matched (only that auth
# succeeded), so both candidates stay in place rather than dropping one on a
# guess; extract_yeti_token() already tries them in order and this is
# behaviourally correct either way.
YETI_TOKEN_KEYS: tuple[str, ...] = ("access_token", "token")


def extract_yeti_token(auth_response: dict[str, Any]) -> str:
    """Extract the bearer token from a Yeti auth-exchange JSON response.

    Tries each key in YETI_TOKEN_KEYS in order. Raises ValueError naming the
    keys actually present in the response if neither candidate is found —
    never guesses silently or returns an empty/placeholder token.
    """
    for key in YETI_TOKEN_KEYS:
        if key in auth_response and auth_response[key]:
            return str(auth_response[key])
    raise ValueError(f"unexpected auth response shape: {sorted(auth_response.keys())}")


def extract_yeti_search_results(
    search_response: dict[str, Any],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Extract (observables, entities) lists from a Yeti search JSON response.

    # CONFIRMED (live Yeti 2.5.1, 2026-08-06): the top-level "observables"
    # key is correct -- the live search response returned real observable
    # dicts under it.
    # DISPROVEN (live Yeti 2.5.1, 2026-08-06): the "entities" key does NOT
    # exist in the /observables/search response at all -- the real response
    # shape is only {"observables": [...], "total": N}. Related nodes
    # (including entity-kind ones) come from a separate call instead --
    # POST /api/v2/graph/search, see YETI_GRAPH_SEARCH_BODY() and the
    # "related"/graph-search handling in yeti_branch(). The .get("entities",
    # []) below is kept anyway as a harmless no-op against the real shape
    # (rather than removed), so a future response that unexpectedly did
    # include the key would still be picked up instead of silently ignored.
    # Absent/malformed keys degrade to empty lists (a legitimate "not found"
    # 0-exit result per handoff §3.4) rather than raising, matching
    # yeti_branch()'s never-raises contract.
    """
    observables = search_response.get("observables", [])
    entities = search_response.get("entities", [])
    if not isinstance(observables, list):
        observables = []
    if not isinstance(entities, list):
        entities = []
    return observables, entities


def extract_yeti_item_id(item: dict[str, Any]) -> Optional[str]:
    """Extract the id of a single Yeti observable/entity search-result item.

    # CONFIRMED for observables (live Yeti 2.5.1, 2026-08-06): the live
    # search response's observable dict had a real top-level "id" field
    # (e.g. "id": "62307").
    # The "entities" list this is also called on (from
    # extract_yeti_search_results()) is now known to always be empty in
    # practice, since that top-level key doesn't exist in the real
    # /observables/search response (see that function's DISPROVEN note) --
    # so the entity branch of that loop in yeti_branch() is effectively
    # unreachable against this endpoint. Related entity-kind nodes are
    # identified a different way instead, via
    # yeti_source_ref_for_vertex_key() on graph-search "vertices" keys, not
    # via this function. Kept here regardless as a generic, still-correct
    # item.get("id") fallback: returns None rather than guessing if the key
    # is absent, so the caller skips building a source_ref for that item
    # instead of fabricating one.
    """
    item_id = item.get("id")
    return str(item_id) if item_id is not None else None


# CONFIRMED (live Yeti 2.5.1, 2026-08-06): related nodes are NOT included in
# /observables/search or an observable detail endpoint -- they require a
# separate call, POST /api/v2/graph/search. "source" MUST be
# "<collection>/<id>" (e.g. "observables/62307") -- a bare id was tried live
# and failed. "graph"="links", "direction"="any", "hops"=1 are the exact
# parameters verified live.
YETI_GRAPH_SEARCH_GRAPH: str = "links"
YETI_GRAPH_SEARCH_DIRECTION: str = "any"
YETI_GRAPH_SEARCH_HOPS: int = 1


def YETI_GRAPH_SEARCH_BODY(source_ref: str, count: int) -> dict[str, Any]:
    """Build the Yeti POST /api/v2/graph/search request body.

    # CONFIRMED (live Yeti 2.5.1, 2026-08-06): this exact shape was
    # verified against a live instance. `source_ref` must already be in
    # "<collection>/<id>" form -- yeti_branch() builds it as
    # f"observables/{obs_id}".
    """
    return {
        "source": source_ref,
        "graph": YETI_GRAPH_SEARCH_GRAPH,
        "direction": YETI_GRAPH_SEARCH_DIRECTION,
        "include_original": False,
        "hops": YETI_GRAPH_SEARCH_HOPS,
        "count": count,
    }


# Yeti graph-search "vertices" dict keys have the form "<collection>/<id>".
# "observables" -> "observable" and "entities" -> "entity" are the two
# source_ref kinds handoff §3 names explicitly; any other collection prefix
# encountered is passed through under its own name (yeti:<collection>/<id>)
# rather than dropped, so a node kind never observed live is never silently
# discarded. CONFIRMED (live Yeti 2.5.1, 2026-08-06): the live sample's only
# neighbour was itself an "observables/..." vertex -- no entity-kind or
# other-collection vertex has been observed live yet, so this mapping is
# extrapolated from the two kinds the handoff names, not fully exercised.
_YETI_GRAPH_KIND_MAP: dict[str, str] = {
    "observables": "observable",
    "entities": "entity",
}


def yeti_source_ref_for_vertex_key(vertex_key: str) -> Optional[str]:
    """Build a "yeti:<kind>/<id>" source_ref from a graph-search vertices key.

    Returns None (rather than guessing) if `vertex_key` isn't a string or
    doesn't have the expected "<collection>/<id>" form.
    """
    if not isinstance(vertex_key, str) or "/" not in vertex_key:
        return None
    collection, _, node_id = vertex_key.partition("/")
    if not collection or not node_id:
        return None
    kind = _YETI_GRAPH_KIND_MAP.get(collection, collection)
    return f"yeti:{kind}/{node_id}"


def extract_yeti_graph_neighbors(
    graph_response: dict[str, Any], origin_ref: str
) -> list[dict[str, Any]]:
    """Extract a compact list of related nodes from a graph-search response.

    # CONFIRMED (live Yeti 2.5.1, 2026-08-06): "vertices" is a dict keyed by
    # "<collection>/<id>"; "paths" is a list of hop-lists, each hop a dict
    # with (at least) "source"/"target"/"type"/"description" -- relationship
    # metadata between two vertex keys, not the node/vertex data itself.
    # `origin_ref` is the same "<collection>/<id>" string sent as "source"
    # in the request -- used to identify, per hop, which side is the
    # neighbour, so its relationship type/description can be attached to
    # the right vertex. Defensive throughout: malformed/missing keys are
    # skipped rather than raising, matching yeti_branch()'s never-raises
    # contract.
    """
    vertices = graph_response.get("vertices")
    paths = graph_response.get("paths")
    if not isinstance(vertices, dict):
        vertices = {}
    if not isinstance(paths, list):
        paths = []

    rel_by_neighbor: dict[str, dict[str, Any]] = {}
    for path in paths:
        if not isinstance(path, list):
            continue
        for hop in path:
            if not isinstance(hop, dict):
                continue
            src, tgt = hop.get("source"), hop.get("target")
            if src == origin_ref and tgt is not None:
                neighbor = tgt
            elif tgt == origin_ref and src is not None:
                neighbor = src
            else:
                # direction "any" with hops > 1 could produce a hop where
                # neither endpoint is the origin directly -- skip rather
                # than guess which side is relevant (hops is fixed to 1
                # here, so this is defensive headroom, not an active case).
                continue
            rel_by_neighbor[neighbor] = {
                "type": hop.get("type"),
                "description": hop.get("description"),
            }

    neighbors: list[dict[str, Any]] = []
    for vertex_key in vertices:
        if vertex_key == origin_ref:
            continue
        rel = rel_by_neighbor.get(vertex_key, {})
        neighbors.append(
            {
                "vertex_key": vertex_key,
                "source_ref": yeti_source_ref_for_vertex_key(vertex_key),
                "rel_type": rel.get("type"),
                "rel_description": rel.get("description"),
            }
        )
    return neighbors


def INTELOWL_OBSERVABLES_BODY(
    obs_type: str, value: str, playbook: str, tlp: str
) -> dict[str, Any]:
    """Build the IntelOwl POST /api/playbook/analyze_multiple_observables body.

    # CONFIRMED (live IntelOwl v6.7.0, 2026-08-06): the "observables"
    # ([[type, value]]) and "tlp" shapes passed validation on a live
    # instance -- the 400 Bad Request seen there was solely about
    # "playbook_requested" naming a playbook that did not yet exist under
    # the handoff's hyphenated spelling (see the --playbook click option's
    # comment; playbook names are restricted to [A-Za-z0-9_]). The
    # playbook has since been created live as "WB_Lookup" (id 17).
    # CONFIRMED (live IntelOwl v6.7.0, 2026-08-06): the SUCCESS response
    # shape from this endpoint is now confirmed too -- see
    # _extract_submit_result() / extract_job_id().
    """
    return {
        "observables": [[obs_type, value]],
        "playbook_requested": playbook,
        "tlp": tlp,
    }


# CONFIRMED-CORRECTED (live IntelOwl v6.7.0, 2026-08-06): handoff-f6-toolkit.md
# §3 step 5's candidate name, "check_analysis_availability", is now proven
# WRONG -- measured by submitting the same observable to the same playbook
# three times and reading results[0].already_exists from each response:
#   plain submit                             -> job_id 8, already_exists: true  (cache reused)
#   {"scan_mode": 1}                         -> job_id 9, already_exists: false (fresh analysis forced)
#   {"check_analysis_availability": false}   -> job_id 9, already_exists: true  (cache reused --
#                                                run AFTER job 9 had already completed, so this
#                                                was a clean test, not a race)
# "check_analysis_availability" is SILENTLY IGNORED by the live API -- worse
# than being rejected, since --force would have appeared to work while
# quietly still returning cached results. The real field is "scan_mode"
# (an int mode, not a boolean): 1 = force new analysis, 2 = reuse previous
# analysis within scan_check_time (the playbook's own configured default --
# this is the mechanism behind handoff §9's "soc-lookup vracia stary
# vysledok" / stale-result row).
INTELOWL_FORCE_FIELD: str = "scan_mode"
INTELOWL_FORCE_VALUE: int = 1


def _extract_submit_result(submit_response: dict[str, Any]) -> dict[str, Any]:
    """Return results[0] from an IntelOwl submit response, or raise clearly.

    # CONFIRMED (live IntelOwl v6.7.0, 2026-08-06): the real submit response
    # shape is {"results": [{"job_id": ..., "status": ..., "already_exists":
    # ..., "analyzers_running": [...], "connectors_running": [...],
    # "visualizers_running": [...], "playbook_running": ...,
    # "investigation": ...}], "count": N}. Supersedes the earlier
    # candidate-based guess (top-level "job_id", top-level "id", or first
    # element of "results" tried generically) -- the confirmed path is
    # specifically results[0], not the response root.
    """
    results = submit_response.get("results")
    if isinstance(results, list) and results and isinstance(results[0], dict):
        return results[0]
    raise ValueError(f"unexpected submit response shape: {sorted(submit_response.keys())}")


def extract_job_id(submit_response: dict[str, Any]) -> str:
    """Extract the IntelOwl job id from an analyze_multiple_observables response.

    # CONFIRMED (live IntelOwl v6.7.0, 2026-08-06): job_id is at
    # results[0].job_id -- see _extract_submit_result(). Raises ValueError
    # naming the keys actually present (top-level, or within results[0] if
    # that much matched) rather than silently returning a placeholder, if
    # the shape doesn't match or job_id itself is missing/null.
    """
    result = _extract_submit_result(submit_response)
    if result.get("job_id") is not None:
        return str(result["job_id"])
    raise ValueError(f"unexpected submit response shape: results[0] keys {sorted(result.keys())}")


def extract_already_exists(submit_response: dict[str, Any]) -> Optional[bool]:
    """Extract results[0].already_exists: True = cached, False = fresh analysis.

    # CONFIRMED (live IntelOwl v6.7.0, 2026-08-06): already_exists is a bool
    # at results[0].already_exists -- this is the field that tells an
    # analyst whether they're looking at a cached or a freshly run analysis
    # (see INTELOWL_FORCE_FIELD's comment for the measurement that
    # confirmed it). Never raises: returns None ("unknown", not a guessed
    # True/False) if the submit response shape doesn't match or the key is
    # absent/wrong-typed.
    """
    if not isinstance(submit_response, dict):
        return None
    try:
        result = _extract_submit_result(submit_response)
    except ValueError:
        return None
    value = result.get("already_exists")
    return value if isinstance(value, bool) else None


def extract_analyzers_running(submit_response: dict[str, Any]) -> list[str]:
    """Extract results[0].analyzers_running as a list of strings (best-effort).

    # CONFIRMED (live IntelOwl v6.7.0, 2026-08-06): analyzers_running is a
    # list at results[0].analyzers_running. Never raises: returns [] if the
    # submit response shape doesn't match or the key is absent/malformed,
    # rather than fabricating analyzer names.
    """
    if not isinstance(submit_response, dict):
        return []
    try:
        result = _extract_submit_result(submit_response)
    except ValueError:
        return []
    analyzers = result.get("analyzers_running")
    return [str(a) for a in analyzers] if isinstance(analyzers, list) else []


# ============================================================================
# UNVERIFIED AGAINST LIVE API -- END
# ============================================================================


### SHARED HTTP ERROR HANDLING
# (generic error-body extraction, not an API-shape guess -- used by both
# yeti_branch() and intelowl_branch(), submit and poll paths alike)


def _http_error_detail(exc: requests.exceptions.HTTPError) -> str:
    """Extract a truncated, self-diagnosing detail string from an HTTPError.

    Both IntelOwl and Yeti put the actual validation error in the response
    body (JSON validation errors, sometimes plain text) -- raise_for_status()
    on its own discards that body and leaves only the status line, which
    turns a one-round-trip diagnosis into guesswork. (Concretely: the live
    2026-08-06 acceptance run hit a 400 Bad Request from IntelOwl's
    /api/playbook/analyze_multiple_observables and, before this helper
    existed, that body was discarded.) Never raises itself: falls back
    gracefully if exc.response is None or .json() fails; truncates to
    ~2000 chars so a large HTML error page cannot flood the terminal.
    """
    response = getattr(exc, "response", None)
    if response is None:
        return str(exc)
    try:
        detail = json.dumps(response.json(), default=str)
    except Exception:
        detail = response.text or ""
    return detail[:2000]


def _http_error_message(exc: requests.exceptions.HTTPError) -> str:
    """Build the "HTTP <code>: <body detail>" error string for a result dict."""
    response = getattr(exc, "response", None)
    status_code = response.status_code if response is not None else "?"
    return f"HTTP {status_code}: {_http_error_detail(exc)}"


### YETI CLIENT

# Cap on how many observables from the search result get a follow-up
# POST /api/v2/graph/search call for related nodes. Locally chosen (not
# specified by the handoff) so a broad/generic search can't spawn dozens of
# sequential graph-search calls; when it truncates, this is made visible
# rather than silent -- see "graph_search_truncated" in yeti_branch()'s
# result dict and the note render_yeti_table() prints when it's True.
YETI_GRAPH_SEARCH_MAX_OBSERVABLES: int = 10

# Page-size cap sent as "count" in each graph-search request body -- 50 is
# the exact value used (and verified to work) during the live 2026-08-06
# acceptance run.
YETI_GRAPH_SEARCH_COUNT: int = 50


def yeti_branch(base_url: str, apikey: str, observable: str, timeout: int) -> dict[str, Any]:
    """Run the Yeti auth-exchange + search + related-nodes branch for one observable.

    Always returns a result dict and NEVER raises — any transport error
    (requests.exceptions.RequestException) or any other unexpected error is
    caught and turned into {"ok": False, "branch": "yeti", "error_kind":
    "api", "error": "..."}. On success returns {"ok": True, "branch":
    "yeti", "observables": [...], "entities": [...], "related": {...},
    "graph_search_truncated": bool, "source_refs": [...]} with source_refs
    formatted as "yeti:observable/<id>" and "yeti:entity/<id>" -- the
    latter now actually reachable via graph-search neighbours (see below),
    since the search response's own "entities" key does not exist (see
    extract_yeti_search_results()'s DISPROVEN note).

    After a successful /observables/search, calls
    POST /api/v2/graph/search for up to YETI_GRAPH_SEARCH_MAX_OBSERVABLES
    of the found observables to discover related nodes (handoff §3's
    "entity" requirement). A graph-search failure for one observable does
    NOT fail the whole branch -- it degrades to "no related nodes" for that
    observable and processing continues with the rest.
    """
    try:
        base = base_url.rstrip("/")

        auth_resp = requests.post(
            f"{base}/api/v2/auth/api-token",
            headers={"x-yeti-apikey": apikey},
            timeout=timeout,
        )
        auth_resp.raise_for_status()
        token = extract_yeti_token(auth_resp.json())
        auth_headers = {"Authorization": f"Bearer {token}"}

        search_resp = requests.post(
            f"{base}/api/v2/observables/search",
            headers=auth_headers,
            json=YETI_SEARCH_BODY(observable),
            timeout=timeout,
        )
        search_resp.raise_for_status()
        search_response = search_resp.json()
        observables, entities = extract_yeti_search_results(search_response)

        source_refs: list[str] = []
        for obs in observables:
            obs_id = extract_yeti_item_id(obs)
            if obs_id is not None:
                source_refs.append(f"yeti:observable/{obs_id}")
        for ent in entities:
            ent_id = extract_yeti_item_id(ent)
            if ent_id is not None:
                source_refs.append(f"yeti:entity/{ent_id}")

        # Related nodes (handoff §3's "entity" requirement): a second call
        # per observable, capped at YETI_GRAPH_SEARCH_MAX_OBSERVABLES. Each
        # observable's graph-search call is independently wrapped so one
        # failure can't take down the whole branch.
        graph_raw: dict[str, Any] = {}
        related: dict[str, list[dict[str, Any]]] = {}
        observables_to_expand = observables[:YETI_GRAPH_SEARCH_MAX_OBSERVABLES]
        graph_search_truncated = len(observables) > YETI_GRAPH_SEARCH_MAX_OBSERVABLES

        for obs in observables_to_expand:
            obs_id = extract_yeti_item_id(obs)
            if obs_id is None:
                continue
            origin_ref = f"observables/{obs_id}"
            try:
                graph_resp = requests.post(
                    f"{base}/api/v2/graph/search",
                    headers=auth_headers,
                    json=YETI_GRAPH_SEARCH_BODY(origin_ref, YETI_GRAPH_SEARCH_COUNT),
                    timeout=timeout,
                )
                graph_resp.raise_for_status()
                graph_response = graph_resp.json()
            except requests.exceptions.HTTPError as exc:
                graph_raw[origin_ref] = {"error": _http_error_message(exc)}
                continue
            except requests.exceptions.RequestException as exc:
                graph_raw[origin_ref] = {"error": f"{type(exc).__name__}: {exc}"}
                continue
            except Exception as exc:  # never-raises contract — catch-all by design
                graph_raw[origin_ref] = {"error": f"{type(exc).__name__}: {exc}"}
                continue

            graph_raw[origin_ref] = graph_response
            if not isinstance(graph_response, dict):
                continue

            neighbors = extract_yeti_graph_neighbors(graph_response, origin_ref)
            related[origin_ref] = neighbors
            for neighbor in neighbors:
                neighbor_ref = neighbor.get("source_ref")
                if neighbor_ref:
                    source_refs.append(neighbor_ref)

        # Dedup while preserving first-seen order -- the searched
        # observable can legitimately reappear as a neighbour of a sibling
        # observable found in the same search batch.
        source_refs = list(dict.fromkeys(source_refs))

        return {
            "ok": True,
            "branch": "yeti",
            "observables": observables,
            "entities": entities,
            "related": related,
            "graph_search_truncated": graph_search_truncated,
            # Full parsed JSON from /observables/search, kept alongside the
            # (candidate-key-derived) observables/entities lists above. This
            # is NOT debug output — do not strip it. extract_yeti_search_results()
            # and extract_yeti_item_id() parse this response using unverified
            # candidate key names (see the UNVERIFIED AGAINST LIVE API block).
            # If the real Yeti response shape differs, those lists silently
            # degrade to empty rather than raising, so without "raw" the
            # user's one live acceptance run (handoff §8B criterion 1) would
            # show "nothing found" with no way to tell a genuine empty result
            # apart from a wrong key guess, and nothing to correct the guess
            # from. Captured here (and only here, in the --json aggregate —
            # never rendered in the rich table) so that single run is enough.
            "raw": search_response,
            # Same diagnostic rationale as "raw" above, but per-observable
            # graph-search responses (or a captured {"error": ...} dict, per
            # observable, if that particular call failed). --json is the
            # only place this appears -- render_yeti_table() only reads the
            # already-extracted "related" list above, never this.
            "graph_raw": graph_raw,
            "source_refs": source_refs,
        }
    except requests.exceptions.HTTPError as exc:
        # Must be caught before the broader RequestException below --
        # HTTPError is a subclass of it, so this handler would never be
        # reached if the order were reversed.
        return {
            "ok": False,
            "branch": "yeti",
            "error_kind": "api",
            "error": _http_error_message(exc),
        }
    except requests.exceptions.RequestException as exc:
        return {
            "ok": False,
            "branch": "yeti",
            "error_kind": "api",
            "error": f"{type(exc).__name__}: {exc}",
        }
    except Exception as exc:  # never-raises contract — catch-all by design
        return {
            "ok": False,
            "branch": "yeti",
            "error_kind": "api",
            "error": f"{type(exc).__name__}: {exc}",
        }


### INTELOWL CLIENT

# Polling cadence for GET /api/jobs/<id> while waiting for a submitted
# IntelOwl job to reach a terminal status. handoff-f6-toolkit.md §3 does
# not specify a poll interval — 5s is a locally chosen default, not a
# confirmed value; safe to tune later without touching orchestration logic.
POLL_INTERVAL: int = 5

# Terminal statuses per handoff-f6-toolkit.md §3 step 2 (IntelOwl branch).
INTELOWL_DONE_STATUSES: tuple[str, ...] = ("reported_without_fails", "reported_with_fails")


def intelowl_branch(
    base_url: str,
    token: str,
    obs_type: str,
    observable: str,
    playbook: str,
    tlp: str,
    timeout: int,
    no_wait: bool,
    force: bool,
) -> dict[str, Any]:
    """Submit an IntelOwl playbook analysis and (optionally) poll it to completion.

    NEVER raises — any transport error or other unexpected error is caught
    and turned into an {"ok": False, ...} result dict, exactly like
    yeti_branch(). With no_wait=True, returns immediately after a
    successful submit with the job id/URL and "source_ref":
    "intelowl:job/<id>", ok True. Otherwise polls GET /api/jobs/<id> every
    POLL_INTERVAL seconds (using a time.monotonic() deadline of `timeout`
    seconds) until the job status is one of INTELOWL_DONE_STATUSES, or
    returns {"ok": False, "error_kind": "timeout", ...} if the deadline is
    reached first.

    `force` sets INTELOWL_FORCE_FIELD ("scan_mode") to INTELOWL_FORCE_VALUE
    (1 = force a fresh analysis) in the submit body when passed; the field
    is only included at all when --force is passed, to avoid touching
    default server behaviour otherwise. This was CONFIRMED correct (and the
    handoff §3 step 5 candidate name proven wrong) by live measurement --
    see INTELOWL_FORCE_FIELD's comment.

    The submit response's results[0].already_exists (True = cached result,
    False = fresh analysis -- see extract_already_exists()) is carried into
    the result dict on both the no_wait and terminal-status success paths,
    so the caller/analyst can tell a cached hit from a fresh run rather
    than the two being indistinguishable.
    """
    base = base_url.rstrip("/")
    headers = {"Authorization": f"Token {token}"}

    try:
        body = INTELOWL_OBSERVABLES_BODY(obs_type, observable, playbook, tlp)
        if force:
            body[INTELOWL_FORCE_FIELD] = INTELOWL_FORCE_VALUE

        submit_resp = requests.post(
            f"{base}/api/playbook/analyze_multiple_observables",
            headers=headers,
            json=body,
            timeout=timeout,
        )
        submit_resp.raise_for_status()
        submit_response = submit_resp.json()
        job_id = extract_job_id(submit_response)
        already_exists = extract_already_exists(submit_response)
        job_url = f"{base}/api/jobs/{job_id}"

        if no_wait:
            return {
                "ok": True,
                "branch": "intelowl",
                "job_id": job_id,
                "job_url": job_url,
                "status": "submitted",
                "already_exists": already_exists,
                "analyzers_running": extract_analyzers_running(submit_response),
                "source_refs": [f"intelowl:job/{job_id}"],
            }

        deadline = time.monotonic() + timeout
        status = "submitted"
        last_job: dict[str, Any] = {}
        while time.monotonic() < deadline:
            poll_resp = requests.get(job_url, headers=headers, timeout=timeout)
            poll_resp.raise_for_status()
            last_job = poll_resp.json()
            status = str(last_job.get("status", status))
            if status in INTELOWL_DONE_STATUSES:
                return {
                    "ok": True,
                    "branch": "intelowl",
                    "job_id": job_id,
                    "job_url": job_url,
                    "status": status,
                    "already_exists": already_exists,
                    "job": last_job,
                    "source_refs": [f"intelowl:job/{job_id}"],
                }
            time.sleep(POLL_INTERVAL)

        return {
            "ok": False,
            "branch": "intelowl",
            "error_kind": "timeout",
            "error": (
                f"job {job_id} did not reach a terminal status within "
                f"{timeout}s (last status: {status})"
            ),
            "job_id": job_id,
            "job_url": job_url,
        }
    except requests.exceptions.HTTPError as exc:
        # Must be caught before the broader RequestException below --
        # HTTPError is a subclass of it, so this handler would never be
        # reached if the order were reversed. Covers both the submit
        # request and the poll-loop GET /api/jobs/<id> requests, since both
        # are inside this same try block.
        return {
            "ok": False,
            "branch": "intelowl",
            "error_kind": "api",
            "error": _http_error_message(exc),
        }
    except requests.exceptions.RequestException as exc:
        return {
            "ok": False,
            "branch": "intelowl",
            "error_kind": "api",
            "error": f"{type(exc).__name__}: {exc}",
        }
    except Exception as exc:  # never-raises contract — catch-all by design
        return {
            "ok": False,
            "branch": "intelowl",
            "error_kind": "api",
            "error": f"{type(exc).__name__}: {exc}",
        }


### ORCHESTRATION


def run_lookup(
    observable: str,
    obs_type: str,
    yeti_only: bool,
    intelowl_only: bool,
    playbook: str,
    timeout: int,
    no_wait: bool,
    force: bool,
) -> tuple[dict[str, Any], int]:
    """Validate config, run the requested branch(es) in parallel, and aggregate.

    Determines which branches were requested, validates their config
    synchronously via get_config() (which exits with code 3 before any
    thread is spawned if config is missing), then runs the requested
    branch(es) via a ThreadPoolExecutor(max_workers=2) — always 2 workers
    per handoff §3, even when only one branch is requested. Each future's
    .result() call is wrapped in its own try/except so an unexpected
    future-level exception becomes an error dict instead of killing the
    sibling branch's already-collected result.

    Returns (aggregate, exit_code). Exit code precedence: any timeout (2)
    outranks any api/auth error (1), which outranks all-ok (0). A branch
    that legitimately finds nothing ("not found") is still ok=True and
    contributes 0, per handoff §3.4.
    """
    want_yeti = not intelowl_only
    want_intelowl = not yeti_only

    config = get_config(need_yeti=want_yeti, need_intelowl=want_intelowl)

    aggregate: dict[str, Any] = {
        "observable": observable,
        "type": obs_type,
        "yeti": None,
        "intelowl": None,
        "source_refs": [],
    }

    with ThreadPoolExecutor(max_workers=2) as executor:
        futures: dict[Future, str] = {}

        if want_yeti:
            futures[
                executor.submit(
                    yeti_branch,
                    config["SOC_YETI_URL"],
                    config["SOC_YETI_APIKEY"],
                    observable,
                    timeout,
                )
            ] = "yeti"

        if want_intelowl:
            futures[
                executor.submit(
                    intelowl_branch,
                    config["SOC_INTELOWL_URL"],
                    config["SOC_INTELOWL_TOKEN"],
                    obs_type,
                    observable,
                    playbook,
                    DEFAULT_TLP,
                    timeout,
                    no_wait,
                    force,
                )
            ] = "intelowl"

        branch_results: dict[str, dict[str, Any]] = {}
        for future in as_completed(futures):
            branch_name = futures[future]
            try:
                branch_results[branch_name] = future.result()
            except Exception as exc:  # future-level exception, not branch-level
                branch_results[branch_name] = {
                    "ok": False,
                    "branch": branch_name,
                    "error_kind": "api",
                    "error": f"unexpected future error: {type(exc).__name__}: {exc}",
                }

    exit_code = 0
    for branch_name, result in branch_results.items():
        aggregate[branch_name] = result
        aggregate["source_refs"].extend(result.get("source_refs", []))
        if not result.get("ok", False):
            error_kind = result.get("error_kind")
            exit_code = max(exit_code, 2 if error_kind == "timeout" else 1)

    return aggregate, exit_code


### OUTPUT


# Longer observable values (e.g. SHA256 hashes) are truncated to this many
# characters in the Yeti table so the row stays readable at normal terminal
# width; the full untruncated value is always available via --json (from
# "raw" and from the "value" key inside each observables[] dict).
_YETI_VALUE_DISPLAY_MAXLEN = 40


def _truncate_for_display(value: str, maxlen: int = _YETI_VALUE_DISPLAY_MAXLEN) -> str:
    """Truncate `value` to `maxlen` chars for table display, keeping both ends visible."""
    if len(value) <= maxlen:
        return value
    head = maxlen - 3 - 12
    return f"{value[:head]}...{value[-12:]}"


def _format_yeti_neighbor(neighbor: dict[str, Any]) -> str:
    """Format one graph-search neighbour for the "Related" table cell.

    Prefers "<rel_type> (<rel_description>)" (e.g. "sha256
    (AbuseCHMalwareBazaaar)") since paths[][].type/.description are what
    tell an analyst WHY two nodes are linked; falls back to whatever's
    available (type only, description only, or the source_ref/vertex key)
    rather than an empty cell.
    """
    rel_type = neighbor.get("rel_type")
    rel_description = neighbor.get("rel_description")
    if rel_type and rel_description:
        return f"{rel_type} ({rel_description})"
    if rel_type:
        return str(rel_type)
    if rel_description:
        return str(rel_description)
    return str(neighbor.get("source_ref") or neighbor.get("vertex_key") or "?")


def render_yeti_table(result: Optional[dict[str, Any]]) -> None:
    """Render the Yeti branch result as a rich table on stderr. No-op if None.

    Columns for observables (value/type/id/tags/context source/related)
    read the real Yeti observable and graph-search shapes, CONFIRMED
    against a live Yeti 2.5.1 instance (2026-08-06) -- see
    extract_yeti_search_results(), extract_yeti_item_id() and
    extract_yeti_graph_neighbors() for exactly which keys are confirmed.
    Every field read here is defensive regardless: a missing, renamed, or
    wrong-typed key degrades to an empty cell, it never raises (the
    never-raises contract on the whole branch still applies). The
    "entities" list from the search response is now known to always be
    empty (see extract_yeti_search_results()'s DISPROVEN note) so its rows
    stay minimal (id lookup only); related entity-kind nodes surface
    instead through the "Related" column, sourced from "related" (already
    extracted by yeti_branch() via extract_yeti_graph_neighbors() -- the
    raw graph-search payloads in "graph_raw" are never read here).
    """
    if result is None:
        return

    table = Table(title="Yeti")
    if not result.get("ok"):
        table.add_column("Status")
        table.add_row(f"[red]ERROR ({result.get('error_kind')}): {result.get('error')}[/red]")
        console.print(table)
        return

    table.add_column("Kind")
    table.add_column("Value")
    table.add_column("Type")
    table.add_column("ID")
    table.add_column("Tags")
    table.add_column("Context sources")
    table.add_column("Related")

    observables = result.get("observables", [])
    if not isinstance(observables, list):
        observables = []
    entities = result.get("entities", [])
    if not isinstance(entities, list):
        entities = []
    related_map = result.get("related")
    if not isinstance(related_map, dict):
        related_map = {}

    if not observables and not entities:
        table.add_row("(no results)", "", "", "", "", "", "")

    for obs in observables:
        if not isinstance(obs, dict):
            table.add_row("observable", str(obs), "", "", "", "", "")
            continue

        raw_value = obs.get("value")
        value_cell = _truncate_for_display(str(raw_value)) if raw_value is not None else ""

        raw_type = obs.get("type")
        type_cell = str(raw_type) if raw_type is not None else ""

        id_cell = extract_yeti_item_id(obs) or ""

        tags = obs.get("tags")
        tag_names = (
            ", ".join(
                str(tag["name"])
                for tag in tags
                if isinstance(tag, dict) and tag.get("name")
            )
            if isinstance(tags, list)
            else ""
        )

        context = obs.get("context")
        sources = (
            ", ".join(
                str(ctx["source"])
                for ctx in context
                if isinstance(ctx, dict) and ctx.get("source")
            )
            if isinstance(context, list)
            else ""
        )

        origin_ref = f"observables/{id_cell}" if id_cell else None
        neighbors = related_map.get(origin_ref) if origin_ref else None
        related_cell = (
            ", ".join(_format_yeti_neighbor(n) for n in neighbors if isinstance(n, dict))
            if isinstance(neighbors, list)
            else ""
        )

        table.add_row(
            "observable", value_cell, type_cell, id_cell, tag_names, sources, related_cell
        )

    for ent in entities:
        # The search response's "entities" key is DISPROVEN (see
        # extract_yeti_search_results()) -- this list is always empty in
        # practice, so this loop is defensive headroom, not an active case.
        ent_id = extract_yeti_item_id(ent) if isinstance(ent, dict) else None
        table.add_row("entity", "", "", ent_id or "", "", "", "")

    console.print(table)

    if result.get("graph_search_truncated"):
        console.print(
            f"[yellow]Note: related-node lookup (graph search) ran for only "
            f"the first {YETI_GRAPH_SEARCH_MAX_OBSERVABLES} observable(s) "
            f"found; the search itself matched more.[/yellow]"
        )


def render_intelowl_table(result: Optional[dict[str, Any]]) -> None:
    """Render the IntelOwl branch result as a rich table(s) on stderr. No-op if None.

    Beyond the job_id/job_url/status summary, renders a per-analyzer
    breakdown from job["analyzer_reports"] plus job-level warnings/errors --
    CONFIRMED live shape (live IntelOwl v6.7.0, 2026-08-06):
    analyzer_reports is a list of {"name", "status", "errors": [...],
    "report": {...}, ...} dicts (status values observed live: "SUCCESS",
    "FAILED" -- treated as an open, not closed, set: anything else is
    passed through as plain text rather than assumed impossible);
    job["warnings"] / job["errors"] are lists of strings. This closes most
    of the handoff §3.3 "IntelOwl: analyzer -> verdict/finding" gap; a
    SUCCESS analyzer's "report" payload itself is NOT interpreted here --
    its internal shape varies per analyzer and was never verified, so only
    its presence/size is indicated and the full content is left to --json.
    job's raw content is never dumped wholesale here or anywhere else in
    this function -- only these specific extracted fields are rendered.
    Every field read is defensive: missing/renamed/wrong-typed keys degrade
    to empty cells or are skipped, never raise.

    Also renders "already_exists" (results[0].already_exists from the
    submit response, CONFIRMED live 2026-08-06 -- see
    extract_already_exists()) in plain words rather than a bare
    true/false, since a cached result is otherwise indistinguishable from
    a fresh one -- exactly the failure mode --force exists to avoid.
    """
    if result is None:
        return

    table = Table(title="IntelOwl")
    if not result.get("ok"):
        table.add_column("Status")
        table.add_row(f"[red]ERROR ({result.get('error_kind')}): {result.get('error')}[/red]")
        console.print(table)
        return

    already_exists = result.get("already_exists")
    if already_exists is True:
        already_exists_cell = "cached result (already_exists=true)"
    elif already_exists is False:
        already_exists_cell = "fresh analysis (already_exists=false)"
    else:
        already_exists_cell = "unknown"

    table.add_column("Field")
    table.add_column("Value")
    table.add_row("job_id", str(result.get("job_id")))
    table.add_row("job_url", str(result.get("job_url")))
    table.add_row("status", str(result.get("status")))
    table.add_row("result", already_exists_cell)
    console.print(table)

    job = result.get("job")
    if not isinstance(job, dict):
        return

    analyzer_reports = job.get("analyzer_reports")
    if isinstance(analyzer_reports, list) and analyzer_reports:
        analyzer_table = Table(title="IntelOwl analyzer reports")
        analyzer_table.add_column("Analyzer")
        analyzer_table.add_column("Status")
        analyzer_table.add_column("Detail")
        for entry in analyzer_reports:
            if not isinstance(entry, dict):
                continue
            name = str(entry.get("name")) if entry.get("name") is not None else "(unknown)"
            status = str(entry.get("status")) if entry.get("status") is not None else "(unknown)"

            errors = entry.get("errors")
            error_text = (
                "; ".join(str(e) for e in errors) if isinstance(errors, list) and errors else ""
            )

            # Presence/size only -- report's internal shape is
            # analyzer-specific and unverified; full content is in --json.
            report = entry.get("report")
            report_marker = ""
            if isinstance(report, dict) and report:
                report_marker = f"report: {len(report)} field(s) (see --json)"
            elif isinstance(report, list) and report:
                report_marker = f"report: {len(report)} item(s) (see --json)"

            detail = " | ".join(part for part in (error_text, report_marker) if part)
            analyzer_table.add_row(name, status, detail)
        console.print(analyzer_table)

    warnings = job.get("warnings")
    if isinstance(warnings, list) and warnings:
        warnings_table = Table(title="IntelOwl warnings (requested analyzers skipped)")
        warnings_table.add_column("Warning")
        for warning in warnings:
            warnings_table.add_row(str(warning))
        console.print(warnings_table)

    job_errors = job.get("errors")
    if isinstance(job_errors, list) and job_errors:
        errors_table = Table(title="IntelOwl job errors")
        errors_table.add_column("Error")
        for job_error in job_errors:
            errors_table.add_row(str(job_error))
        console.print(errors_table)


def render_summary(aggregate: dict[str, Any], exit_code: int) -> None:
    """Print a one-line human-readable summary on stderr."""
    status = "OK" if exit_code == 0 else f"EXIT {exit_code}"
    refs = len(aggregate.get("source_refs", []))
    console.print(
        f"[bold]{aggregate['observable']}[/bold] ({aggregate['type']}) -- "
        f"{status}, {refs} source_ref(s)"
    )


def render_output(aggregate: dict[str, Any], exit_code: int, json_output: bool) -> None:
    """Render human tables + summary (always, stderr) and optionally raw JSON (stdout).

    With --json, the aggregate is additionally written as a single JSON
    document to stdout and nothing else goes to stdout in that mode — this
    separation is what makes `soc-lookup ... --json | jq` work.
    """
    render_yeti_table(aggregate.get("yeti"))
    render_intelowl_table(aggregate.get("intelowl"))
    render_summary(aggregate, exit_code)

    if json_output:
        click.echo(json.dumps(aggregate, indent=2, default=str))


### CLI


@click.command()
@click.argument("observable")
@click.option(
    "--type",
    "obs_type_override",
    type=click.Choice(["ip", "domain", "hash", "url", "generic"]),
    default=None,
    help="Override observable type autodetection.",
)
@click.option(
    "--json",
    "json_output",
    is_flag=True,
    default=False,
    help="Emit the aggregate result as JSON on stdout (human output stays on stderr).",
)
@click.option("--yeti-only", is_flag=True, default=False, help="Only run the Yeti branch.")
@click.option(
    "--intelowl-only", is_flag=True, default=False, help="Only run the IntelOwl branch."
)
@click.option(
    "--playbook",
    # NOT "WB-Lookup" (handoff-f6-toolkit.md §3's literal spelling) --
    # IntelOwl playbook names are restricted to [A-Za-z0-9_], hyphens are
    # rejected at validation ("Your name should match the [A-Za-z0-9_]
    # characters"). Verified against a live IntelOwl v6.7.0 instance,
    # 2026-08-06: the handoff's hyphenated name could never have existed on
    # a real instance. The playbook was (re-)created there as "WB_Lookup"
    # (id 17; analyzers: Cymru_Hash_Registry_Get_Observable, Feodo_Tracker,
    # MalwareBazaar_Get_Observable, TalosReputation, ThreatFox, URLhaus,
    # YARAify_Generics) -- do not "correct" this back to the hyphenated
    # spelling.
    default="WB_Lookup",
    show_default=True,
    help="IntelOwl playbook to request.",
)
@click.option(
    "--timeout",
    default=300,
    show_default=True,
    type=int,
    help="Per-branch HTTP timeout / IntelOwl job-poll deadline, in seconds.",
)
@click.option(
    "--no-wait",
    is_flag=True,
    default=False,
    help="Submit to IntelOwl and return immediately (do not poll for job completion).",
)
@click.option(
    "--force",
    is_flag=True,
    default=False,
    help="Bypass IntelOwl's cached-analysis check (see handoff-f6-toolkit.md §3 step 5).",
)
def main(
    observable: str,
    obs_type_override: Optional[str],
    json_output: bool,
    yeti_only: bool,
    intelowl_only: bool,
    playbook: str,
    timeout: int,
    no_wait: bool,
    force: bool,
) -> None:
    """Look up OBSERVABLE in Yeti and/or IntelOwl in parallel and print an aggregate result."""
    if yeti_only and intelowl_only:
        console.print(
            "[bold red]--yeti-only and --intelowl-only are mutually exclusive.[/bold red]"
        )
        sys.exit(3)

    obs_type = obs_type_override if obs_type_override is not None else detect_type(observable)

    aggregate, exit_code = run_lookup(
        observable=observable,
        obs_type=obs_type,
        yeti_only=yeti_only,
        intelowl_only=intelowl_only,
        playbook=playbook,
        timeout=timeout,
        no_wait=no_wait,
        force=force,
    )

    render_output(aggregate, exit_code, json_output)
    sys.exit(exit_code)


if __name__ == "__main__":
    main()
