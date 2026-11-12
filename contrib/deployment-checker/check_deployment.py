#!/usr/bin/env python3
# Copyright (C) 2026 Thijs Eilander
# SPDX-License-Identifier: BSD-2-Clause
"""Bounded, read-only nginx deployment inspection under an explicit site contract."""

import argparse
import json
import os
import re
import stat
import sys
from dataclasses import dataclass
from pathlib import PurePosixPath

MAX_FILE = 65536
MAX_TOTAL = 1048576
MAX_FILES = 64
MAX_TOKENS = 32768
MAX_TOKEN = 4096
MAX_NODES = 8192
MAX_DEPTH = 32
MAX_INCLUDES = 8
MAX_ITEMS = 128
MAX_DIAGNOSTICS = 2048
BRACED_VARIABLE = re.compile(r"\$\{[A-Za-z0-9_]+\}")
CATEGORIES = frozenset(
    [
        "sqli",
        "xss",
        "traversal",
        "overlong",
        "cmdi",
        "lfi",
        "crlf",
        "nullbyte",
        "template",
        "deserial",
        "shellshock",
        "php_rce",
        "java_rce",
        "java_eval",
        "rails_yaml",
        "drupal",
        "vbulletin",
        "xmlrpc",
        "ssi",
        "imagetragick",
        "sensitive_file",
        "webshell",
        "ssrf_meta",
        "nosql",
        "ssti",
        "exploit_path",
        "httpoxy",
        "range_dos",
        "ctrl_char",
        "dotfile",
    ]
)
NO_BODY = frozenset(
    [
        "xss",
        "traversal",
        "cmdi",
        "lfi",
        "template",
        "php_rce",
        "java_rce",
        "java_eval",
        "sensitive_file",
        "exploit_path",
        "httpoxy",
        "range_dos",
        "ctrl_char",
        "dotfile",
    ]
)
VARIABLES = frozenset(
    [
        "uri",
        "request_uri",
        "document_uri",
        "document_root",
        "realpath_root",
        "request_filename",
        "fastcgi_script_name",
        "query_string",
        "args",
        "is_args",
        "request_method",
        "content_type",
        "content_length",
        "server_protocol",
        "scheme",
        "https",
        "remote_addr",
        "remote_port",
        "server_addr",
        "server_port",
        "server_name",
    ]
)
MESSAGES = {
    "INPUT": "Read a regular UTF-8 file inside the selected root; no symlinks.",
    "LIMIT": "Reduce input to the documented byte, file, token or nesting limits.",
    "SYNTAX": "Correct the configuration syntax at this input position.",
    "INCLUDE": "Use a literal root-relative include; globs and variables are unsupported.",
    "CYCLE": "Remove the include cycle.",
    "INCLUDED": "An included input begins here; related_file identifies it.",
    "CONTRACT": "Correct the deployment contract schema and declared invariants.",
    "UNKNOWN": "Review an unsupported directive, context, variable or value locally.",
    "DUPLICATE": "Remove a duplicate singleton directive at this scope.",
    "SCOPE": "Effective policy for this configuration scope.",
    "SKIP_LOCAL": "This scope skips this category in every inspected source.",
    "SKIP_INHERITED": "This scope inherits this category skip from its parent.",
    "SKIP_REPLACED": "Local category skips replace the entire inherited mask.",
    "COVERAGE": "A required category is skipped or Shield is not in block mode.",
    "BODY": "A required body category is disabled or has no body scanner.",
    "PUBLIC_INTERNAL": "Add internal to the declared internal route or status handler.",
    "MISSING_INTERNAL": "A declared internal route has no analyzed location.",
    "PHP_SCRIPT": "Use a declared constant script outside nonexec trees or the declared final guard.",
    "PHP_PARAMS": "Supply exactly one SCRIPT_FILENAME in the effective parameter list.",
    "PARAMS_REPLACED": "Local FastCGI parameters replace the entire inherited list.",
    "HANDOFF": "Route every FastCGI handler directly to an isolated declared block-mode guard.",
    "GUARDED_DYNAMIC": "Final script membership is enforced by the declared guard, not URI inference.",
    "GUARD_POLICY": "Align the final guard policy with approved scripts and nonexec trees.",
    "GUARD_VECTOR": "Align constant privileged parameters with the declared final policy vector.",
    "PRIVATE_DAC": "Establish the private-destination worker, DAC and trusted-writer contract.",
    "PRIVATE_MAPPING": "This mapping can reach a declared private tree; retain verified DAC.",
    "FILE_CACHE": "Retain open_file_cache off under the private-destination contract.",
    "SYMLINK_POLICY": "The private recipe preserves public symlinks with disable_symlinks off.",
    "EMPTY": "Supply an HTTP context with at least one server to analyze.",
}


class Problem(Exception):
    """A fixed-code input failure; never carry input text in diagnostics."""

    def __init__(self, code, file=0, line=0):
        self.code, self.file, self.line = code, file, line


@dataclass
class Node:
    name: str
    args: list
    children: object
    file: int
    line: int


class Reader:
    """Bound I/O and refuse special files, symlinks and traversal at every component."""

    def __init__(self, root):
        self.root = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        self.total = 0
        self.files = 0

    def close(self):
        os.close(self.root)

    def read(self, path):
        parts = PurePosixPath(path).parts
        if (
            not parts
            or PurePosixPath(path).is_absolute()
            or ".." in parts
            or "\0" in path
        ):
            raise Problem("INPUT")
        self.files += 1
        if self.files > MAX_FILES:
            raise Problem("LIMIT")
        fd = os.dup(self.root)
        try:
            for index, part in enumerate(parts):
                flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
                if index < len(parts) - 1:
                    flags |= os.O_DIRECTORY
                child = os.open(part, flags, dir_fd=fd)
                os.close(fd)
                fd = child
            if not stat.S_ISREG(os.fstat(fd).st_mode):
                raise Problem("INPUT")
            with os.fdopen(fd, "rb", closefd=False) as stream:
                raw = stream.read(MAX_FILE + 1)
            self.total += len(raw)
            if len(raw) > MAX_FILE or self.total > MAX_TOTAL:
                raise Problem("LIMIT")
            return raw.decode("utf-8")
        except (OSError, UnicodeError, ValueError) as exc:
            raise Problem("INPUT") from exc
        finally:
            os.close(fd)


def tokens(text, file):
    """Lex a conservative nginx subset, preserving regex backslashes and variables."""
    result = []
    i, line = 0, 1
    while i < len(text):
        c = text[i]
        if c in " \t\r\n":
            line += c == "\n"
            i += 1
            continue
        if c == "#":
            end = text.find("\n", i)
            i = len(text) if end < 0 else end
            continue
        start = line
        if c in ";{}":
            result.append((c, line, True))
            i += 1
        else:
            quote = c if c in "\"'" else None
            if quote:
                i += 1
            value, closed = [], False
            while i < len(text):
                c = text[i]
                if quote and c == quote:
                    i += 1
                    closed = True
                    if i < len(text) and not (text[i] in " \t\r\n" or text[i] in ";{}"):
                        raise Problem("SYNTAX", file, line)
                    break
                if not quote and (c in " \t\r\n" or c in ";{"):
                    break
                if not quote and c in "\"'":
                    raise Problem("SYNTAX", file, line)
                if c == "\\":
                    i += 1
                    if i == len(text):
                        raise Problem("SYNTAX", file, line)
                    c = text[i]
                    value.append(
                        {"t": "\t", "r": "\r", "n": "\n"}.get(
                            c, c if c in "\\\"'" else "\\" + c
                        )
                    )
                elif c == "$" and i + 1 < len(text) and text[i + 1] == "{":
                    match = BRACED_VARIABLE.match(text, i)
                    if match is None:
                        raise Problem("SYNTAX", file, line)
                    value.append(match.group())
                    i = match.end() - 1
                else:
                    value.append(c)
                line += c == "\n"
                i += 1
                if len(value) > MAX_TOKEN:
                    raise Problem("LIMIT", file, start)
            if quote and not closed:
                raise Problem("SYNTAX", file, start)
            word = "".join(value)
            if len(word) > MAX_TOKEN or any(
                ord(v) < 32 and v not in "\n\t\r" for v in word
            ):
                raise Problem("LIMIT", file, start)
            result.append((word, start, False))
        if len(result) > MAX_TOKENS:
            raise Problem("LIMIT", file, line)
    return result


class Parser:
    def __init__(self, reader, emit):
        self.reader, self.emit = reader, emit
        self.count = self.token_count = self.file_count = 0

    def parse(self, path, chain=(), depth=0, origin=None):
        if depth > MAX_DEPTH or len(chain) > MAX_INCLUDES:
            raise Problem("LIMIT")
        path = str(PurePosixPath(path))
        if path in chain:
            raise Problem("CYCLE")
        self.file_count += 1
        file = self.file_count
        if origin:
            self.emit("info", "INCLUDED", origin, related_file=file)
        data = tokens(self.reader.read(path), file)
        self.token_count += len(data)
        if self.token_count > MAX_TOKENS:
            raise Problem("LIMIT", file)
        pos = 0

        def block(level, nested=False):
            nonlocal pos
            if level > MAX_DEPTH:
                raise Problem("LIMIT", file)
            nodes = []
            while pos < len(data):
                name, line, punctuation = data[pos]
                pos += 1
                if punctuation:
                    if name == "}" and nested:
                        return nodes
                    raise Problem("SYNTAX", file, line)
                args = []
                while pos < len(data) and not data[pos][2]:
                    args.append(data[pos][0])
                    pos += 1
                if pos == len(data) or data[pos][0] == "}":
                    raise Problem("SYNTAX", file, line)
                delimiter = data[pos][0]
                pos += 1
                children = block(level + 1, True) if delimiter == "{" else None
                node = Node(name, args, children, file, line)
                self.count += 1
                if self.count > MAX_NODES:
                    raise Problem("LIMIT", file, line)
                if name == "include":
                    if (
                        children is not None
                        or len(args) != 1
                        or any(c in args[0] for c in "$*?[")
                    ):
                        raise Problem("INCLUDE", file, line)
                    try:
                        nodes.extend(self.parse(args[0], (*chain, path), level, node))
                    except Problem as exc:
                        if not exc.file:
                            exc.file, exc.line = file, line
                        raise
                else:
                    nodes.append(node)
            if nested:
                raise Problem("SYNTAX", file, data[-1][1] if data else 1)
            return nodes

        return block(depth)


def unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise Problem("CONTRACT")
        result[key] = value
    return result


def utf8(value):
    if not isinstance(value, str) or "\0" in value:
        return False
    try:
        value.encode("utf-8")
    except UnicodeError:
        return False
    return True


def absolute(path):
    return (
        utf8(path)
        and path.startswith("/")
        and not path.startswith("//")
        and not any(c in path for c in "$\0\n\r")
        and ".." not in PurePosixPath(path).parts
        and str(PurePosixPath(path)) == (path.rstrip("/") or "/")
    )


def within(path, root):
    return path == root or path.startswith(root.rstrip("/") + "/")


def load_contract(reader, path):
    """Validate all fields; external runtime/DAC assertions are explicit obligations."""
    contract = json.loads(reader.read(path), object_pairs_hook=unique)
    fields = {
        "version",
        "required_categories",
        "required_body_categories",
        "approved_scripts",
        "nonexec_roots",
        "private_roots",
        "private_dac_verified",
        "internal_routes",
        "handoffs",
    }
    if (
        not isinstance(contract, dict)
        or set(contract) != fields
        or type(contract["version"]) is not int
        or contract["version"] != 1
    ):
        raise Problem("CONTRACT")
    for key in fields - {"version", "private_dac_verified"}:
        if not isinstance(contract[key], list) or len(contract[key]) > MAX_ITEMS:
            raise Problem("CONTRACT")
    for key in ("required_categories", "required_body_categories"):
        if any(not isinstance(v, str) or v not in CATEGORIES for v in contract[key]):
            raise Problem("CONTRACT")
    for key in (
        "approved_scripts",
        "nonexec_roots",
        "private_roots",
        "internal_routes",
    ):
        if any(not absolute(v) for v in contract[key]):
            raise Problem("CONTRACT")
    if type(contract["private_dac_verified"]) is not bool:
        raise Problem("CONTRACT")
    if any(
        within(s, root)
        for s in contract["approved_scripts"]
        for root in contract["nonexec_roots"]
    ):
        raise Problem("CONTRACT")
    endpoints = set()
    for handoff in contract["handoffs"]:
        if not isinstance(handoff, dict) or set(handoff) != {
            "endpoint",
            "mode",
            "isolated",
            "policy",
        }:
            raise Problem("CONTRACT")
        endpoint = handoff["endpoint"]
        if (
            not isinstance(endpoint, str)
            or not endpoint.startswith("unix:")
            or not absolute(endpoint[5:])
            or endpoint in endpoints
        ):
            raise Problem("CONTRACT")
        endpoints.add(endpoint)
        if (
            handoff["mode"] not in ("block", "detect", "off")
            or type(handoff["isolated"]) is not bool
            or not isinstance(handoff["policy"], str)
        ):
            raise Problem("CONTRACT")
        policy = json.loads(reader.read(handoff["policy"]), object_pairs_hook=unique)
        if (
            not isinstance(policy, dict)
            or set(policy) != {"scripts"}
            or not isinstance(policy["scripts"], dict)
            or not policy["scripts"]
            or len(policy["scripts"]) > MAX_ITEMS
        ):
            raise Problem("CONTRACT")
        for script, settings in policy["scripts"].items():
            if (
                not absolute(script)
                or not isinstance(settings, dict)
                or set(settings) != {"PHP_VALUE", "PHP_ADMIN_VALUE"}
            ):
                raise Problem("CONTRACT")
            if any(
                not isinstance(v, list)
                or len(v) > MAX_ITEMS
                or any(not utf8(s) for s in v)
                for v in settings.values()
            ):
                raise Problem("CONTRACT")
        handoff["settings"] = policy["scripts"]
    return contract


# Only these otherwise inert directives are accepted. This is deliberately not
# a general nginx validator; every other construct keeps the verdict nonclean.
INERT = {
    "worker_processes": ("main", 1, 1),
    "user": ("main", 1, 2),
    "pid": ("main", 1, 1),
    "load_module": ("main", 1, 1),
    "worker_connections": ("events", 1, 1),
    "shield_stats_zone": ("http", 2, 2),
    "listen": ("server", 1, 8),
    "server_name": ("server", 1, 32),
    "access_log": ("http server location", 1, 4),
    "error_log": ("main http server location", 1, 3),
    "index": ("http server location", 1, 16),
    "try_files": ("server location", 2, 32),
    "rewrite": ("server location", 2, 3),
    "error_page": ("http server location", 2, 32),
    "return": ("server location", 1, 2),
    "default_type": ("http server location", 1, 1),
}
SINGLE = {
    "shield": ("off", "detect", "block"),
    "shield_body": ("on", "off"),
    "internal": (),
    "root": None,
    "alias": None,
    "fastcgi_pass": None,
    "fastcgi_keep_conn": ("on", "off"),
    "open_file_cache": None,
    "disable_symlinks": None,
    "stub_status": (),
    "shield_status": ("403", "404", "419", "429", "444"),
    "shield_ban_status": None,
}
DEFAULTS = {
    "shield": "off",
    "shield_body": "on",
    "internal": False,
    "open_file_cache": "off",
    "disable_symlinks": "off",
    "fastcgi_keep_conn": "off",
}


class Analyzer:
    def __init__(self, contract, emit):
        self.contract, self.emit = contract, emit
        self.scope = self.servers = 0
        self.routes = {}
        self.server = 0

    def variables(self, value, node, scope):
        # Variables are never expanded, evaluated, sourced or read from the environment.
        rest = re.sub(r"\$(?:\{[A-Za-z0-9_]+\}|[A-Za-z0-9_]+)", "", value)
        names = re.findall(r"\$(?:\{([A-Za-z0-9_]+)\}|([A-Za-z0-9_]+))", value)
        if "$" in rest or any((a or b) not in VARIABLES for a, b in names):
            self.emit("unknown", "UNKNOWN", node, scope=scope)

    def walk(self, nodes, parent=None, kind="main", owner=None):
        self.scope += 1
        scope = self.scope
        state = dict(parent or DEFAULTS)
        # Named/URI locations create new content handlers. The unsupported
        # anonymous if/limit_except contexts have separate nginx merge rules.
        for handler in ("fastcgi_pass", "stub_status", "shield_ban_status"):
            state.pop(handler, None)
        state["params"] = list(state.get("params", []))
        inherited_skip = set(state.get("skip", ()))
        local_skip, params, seen, children = set(), [], set(), []
        owner = owner or Node("main", [], None, 1, 1)
        for node in nodes:
            name, args = node.name, node.args
            if node.children is not None:
                allowed = (
                    (kind == "main" and name in ("http", "events") and not args)
                    or (kind == "http" and name == "server" and not args)
                    or (
                        kind in ("server", "location")
                        and name == "location"
                        and (
                            len(args) == 1
                            and args[0].startswith(("/", "@"))
                            or len(args) == 2
                            and args[0] in ("=", "^~", "~", "~*")
                        )
                    )
                )
                if not allowed:
                    self.emit("unknown", "UNKNOWN", node, scope=scope)
                else:
                    children.append(node)
                continue
            if name in INERT:
                contexts, low, high = INERT[name]
                if kind not in contexts.split() or not low <= len(args) <= high:
                    self.emit("unknown", "UNKNOWN", node, scope=scope)
                for value in args:
                    self.variables(value, node, scope)
                continue
            if kind not in ("http", "server", "location") or name not in {
                *SINGLE,
                "shield_skip",
                "fastcgi_param",
            }:
                self.emit("unknown", "UNKNOWN", node, scope=scope)
                continue
            if name == "shield_skip":
                if not args or any(v not in CATEGORIES for v in args):
                    self.emit("unknown", "UNKNOWN", node, scope=scope)
                else:
                    local_skip.update(args)
                continue
            if name == "fastcgi_param":
                if len(args) not in (2, 3) or (
                    len(args) == 3 and args[2] != "if_not_empty"
                ):
                    self.emit("unknown", "UNKNOWN", node, scope=scope)
                else:
                    params.append(args)
                    self.variables(args[1], node, scope)
                continue
            if name in seen:
                self.emit("unknown", "DUPLICATE", node, scope=scope)
            seen.add(name)
            choices = SINGLE[name]
            if (
                (choices == () and args)
                or (choices != () and len(args) != 1)
                or (choices and args and args[0] not in choices)
            ):
                self.emit("unknown", "UNKNOWN", node, scope=scope)
                continue
            if (
                name
                in (
                    "alias",
                    "fastcgi_pass",
                    "internal",
                    "stub_status",
                    "shield_ban_status",
                )
                and kind != "location"
            ):
                self.emit("unknown", "UNKNOWN", node, scope=scope)
            state[name] = args[0] if args else True
            if args:
                self.variables(args[0], node, scope)
        state["skip"] = local_skip or inherited_skip
        if params:
            if state["params"]:
                self.emit("info", "PARAMS_REPLACED", owner, scope=scope)
            state["params"] = params
        if local_skip and inherited_skip:
            self.emit("info", "SKIP_REPLACED", owner, scope=scope)
        for cat in sorted(state["skip"]):
            self.emit(
                "info",
                "SKIP_LOCAL" if local_skip else "SKIP_INHERITED",
                owner,
                scope=scope,
                category=cat,
            )
        if kind in ("server", "location"):
            self.emit("info", "SCOPE", owner, scope=scope)
            if kind == "server":
                self.servers += 1
                self.server = self.servers
                self.routes[self.server] = []
            for cat in sorted(
                set(self.contract["required_categories"])
                | set(self.contract["required_body_categories"])
            ):
                if state["shield"] != "block" or cat in state["skip"]:
                    self.emit("hole", "COVERAGE", owner, scope=scope, category=cat)
            for cat in sorted(set(self.contract["required_body_categories"])):
                if state["shield_body"] != "on" or cat in NO_BODY:
                    self.emit("hole", "BODY", owner, scope=scope, category=cat)
            route = owner.args[-1] if kind == "location" else ""
            named = len(owner.args) == 1 and route.startswith("@")
            declared = (
                route in self.contract["internal_routes"]
                and len(owner.args) <= 2
                and (len(owner.args) == 1 or owner.args[0] in ("=", "^~"))
            )
            if (
                declared or state.get("stub_status") or state.get("shield_ban_status")
            ) and not (state["internal"] or named):
                self.emit("hole", "PUBLIC_INTERNAL", owner, scope=scope)
            if kind == "location":
                self.routes[self.server].append(
                    (owner, state["internal"] or named, scope)
                )
            self.files(state, owner, scope)
            if state.get("fastcgi_pass"):
                self.php(state, owner, scope)
        for child in children:
            self.walk(
                child.children,
                state if child.name != "events" else None,
                child.name,
                child,
            )

    def files(self, state, owner, scope):
        roots = self.contract["private_roots"]
        for key in ("root", "alias"):
            value = state.get(key)
            if value is None:
                continue
            if not absolute(value):
                self.emit("unknown", "UNKNOWN", owner, scope=scope)
            elif any(within(value, root) or within(root, value) for root in roots):
                self.emit("info", "PRIVATE_MAPPING", owner, scope=scope)
        if roots:
            if not self.contract["private_dac_verified"]:
                self.emit("unknown", "PRIVATE_DAC", owner, scope=scope)
            if state["open_file_cache"] != "off":
                self.emit("hole", "FILE_CACHE", owner, scope=scope)
            if state["disable_symlinks"] != "off":
                self.emit("unknown", "SYMLINK_POLICY", owner, scope=scope)

    def php(self, state, owner, scope):
        params = state["params"]
        scripts = [p for p in params if p[0] == "SCRIPT_FILENAME"]
        guard = next(
            (
                g
                for g in self.contract["handoffs"]
                if g["endpoint"] == state["fastcgi_pass"]
            ),
            None,
        )
        guarded = (
            guard
            and guard["mode"] == "block"
            and guard["isolated"]
            and state["fastcgi_keep_conn"] == "off"
        )
        if not guarded:
            self.emit("hole", "HANDOFF", owner, scope=scope)
        if len(scripts) != 1 or len(scripts[0]) != 2:
            self.emit("hole", "PHP_PARAMS", owner, scope=scope)
            return
        script = scripts[0][1]
        if "$" in script:
            self.emit(
                "info" if guarded else "hole",
                "GUARDED_DYNAMIC" if guarded else "PHP_SCRIPT",
                owner,
                scope=scope,
            )
        elif script not in self.contract["approved_scripts"] or any(
            within(script, r) for r in self.contract["nonexec_roots"]
        ):
            self.emit("hole", "PHP_SCRIPT", owner, scope=scope)
        if guard:
            if any(
                s not in self.contract["approved_scripts"]
                or any(within(s, r) for r in self.contract["nonexec_roots"])
                for s in guard["settings"]
            ):
                self.emit("hole", "GUARD_POLICY", owner, scope=scope)
            if "$" in script:
                candidates = list(guard["settings"].values())
            else:
                settings = guard["settings"].get(script)
                if settings is None:
                    self.emit("hole", "GUARD_POLICY", owner, scope=scope)
                candidates = [settings] if settings is not None else []
            for key in ("PHP_VALUE", "PHP_ADMIN_VALUE"):
                entries = [p for p in params if p[0] == key]
                vector = [p[1] for p in entries]
                if any("$" in p[1] or len(p) == 3 for p in entries):
                    self.emit("unknown", "GUARD_VECTOR", owner, scope=scope)
                elif candidates and any(vector != s[key] for s in candidates):
                    # A dynamic script could select any declared entry. Mixed
                    # policy vectors need route evaluation beyond this subset.
                    possible = any(vector == s[key] for s in candidates)
                    self.emit(
                        "unknown" if possible else "hole",
                        "GUARD_VECTOR",
                        owner,
                        scope=scope,
                    )

    def finish(self):
        if not self.servers:
            self.emit("unknown", "EMPTY")
        # A declaration covers its URI and descendants. Public narrower exact
        # or prefix locations must not bypass it; regex overlap is undecidable
        # in this subset and remains unknown. Check every server independently.
        for routes in self.routes.values():
            for target in self.contract["internal_routes"]:
                matched = False
                for node, internal, scope in routes:
                    if len(node.args) == 2 and node.args[0] in ("~", "~*"):
                        if not internal:
                            self.emit("unknown", "UNKNOWN", node, scope=scope)
                        continue
                    route = node.args[-1]
                    if route == target and (
                        len(node.args) == 1 or node.args[0] == "^~"
                    ):
                        matched = True
                    if route.startswith(target) and not internal:
                        self.emit("hole", "PUBLIC_INTERNAL", node, scope=scope)
                if not matched:
                    self.emit("unknown", "MISSING_INTERNAL")


def inspect(root, config, contract):
    """Return only fixed diagnostic text and bounded numeric/source identifiers."""
    diagnostics = []

    def emit(level, code, node=None, **fields):
        if len(diagnostics) >= MAX_DIAGNOSTICS:
            diagnostics[-1] = {
                "level": "unknown",
                "code": "LIMIT",
                "message": MESSAGES["LIMIT"],
                "file": 0,
                "line": 0,
            }
            raise Problem("LIMIT")
        diagnostics.append(
            {
                "level": level,
                "code": code,
                "message": MESSAGES[code],
                "file": node.file if node else 0,
                "line": node.line if node else 0,
                **fields,
            }
        )

    reader = None
    try:
        reader = Reader(root)
        policy = load_contract(reader, contract)
        nodes = Parser(reader, emit).parse(config)
        analyzer = Analyzer(policy, emit)
        analyzer.walk(nodes)
        analyzer.finish()
    except Problem as exc:
        if len(diagnostics) < MAX_DIAGNOSTICS:
            emit("unknown", exc.code, Node("", [], None, exc.file, exc.line))
    except (OSError, ValueError, TypeError, KeyError, RecursionError):
        emit("unknown", "CONTRACT" if reader else "INPUT")
    finally:
        if reader:
            reader.close()
    return {
        "status": "nonclean"
        if any(d["level"] != "info" for d in diagnostics)
        else "clean",
        "contract": "static-config-and-operator-obligations-v1",
        "diagnostics": diagnostics,
    }


class Arguments(argparse.ArgumentParser):
    def error(self, message):
        self.exit(2, "Invalid checker arguments; use --help.\n")


def main():
    parser = Arguments(description=__doc__)
    parser.add_argument(
        "--root", required=True, help="explicit configuration input directory"
    )
    parser.add_argument(
        "--config", required=True, help="root-relative nginx configuration"
    )
    parser.add_argument(
        "--contract", required=True, help="root-relative deployment contract JSON"
    )
    args = parser.parse_args()
    result = inspect(args.root, args.config, args.contract)
    print(json.dumps(result, sort_keys=True))
    return int(result["status"] != "clean")


if __name__ == "__main__":
    sys.exit(main())
