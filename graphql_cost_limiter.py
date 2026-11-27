"""GraphQL admission control: depth, field cost, alias amplification, fragment cycles."""

from __future__ import annotations

import threading
from dataclasses import dataclass


_PUNCTUATORS = set("!$():=@[]{}|.&")
_IGNORED = set(" \t,\n\r")
_SNAPSHOT_VERSION = 1
_LIMIT_KEYS = ("max_cost", "max_depth", "max_aliases", "introspection_budget")
_INTROSPECTION_ROOTS = frozenset(("__schema", "__type"))


class GraphqlError(ValueError):
    """Raised when a query cannot be parsed or its fragments cannot be resolved."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class Field:
    name: str
    alias: str | None
    directives: tuple[str, ...]
    selection: tuple
    excluded: bool = False


@dataclass(frozen=True)
class Spread:
    name: str
    directives: tuple[str, ...]
    excluded: bool = False


@dataclass(frozen=True)
class InlineFragment:
    type_name: str | None
    directives: tuple[str, ...]
    selection: tuple
    excluded: bool = False


@dataclass(frozen=True)
class Fragment:
    name: str
    type_name: str
    selection: tuple
    excluded: bool = False


@dataclass(frozen=True)
class Document:
    operation: str
    name: str | None
    selections: tuple
    fragments: dict


@dataclass(frozen=True)
class Expanded:
    operation: str
    name: str | None
    selections: tuple


@dataclass(frozen=True)
class CostReport:
    fields: int
    cost: int
    depth: int
    aliases: int
    introspection: int


@dataclass(frozen=True)
class Admission:
    allowed: bool
    reason: str | None
    report: CostReport
    limits: dict


class _Tokenizer:
    """Hand-written lexer producing (kind, value, offset) tokens."""

    def __init__(self, text: str) -> None:
        self.text = text
        self.pos = 0
        self.length = len(text)

    def _error(self, offset: int | None = None) -> "_GraphqlSyntaxError":
        return _GraphqlSyntaxError(offset if offset is not None else self.pos)

    def _skip_ignored(self) -> None:
        text = self.text
        while self.pos < self.length:
            char = text[self.pos]
            if char in _IGNORED:
                self.pos += 1
            elif char == "#":
                while self.pos < self.length and text[self.pos] not in "\n\r":
                    self.pos += 1
            else:
                break

    def next_token(self):
        self._skip_ignored()
        if self.pos >= self.length:
            return ("eof", None, self.length)
        offset = self.pos
        char = self.text[self.pos]
        if char == "." and self.text.startswith("...", self.pos):
            self.pos += 3
            return ("punct", "...", offset)
        if char in _PUNCTUATORS:
            self.pos += 1
            return ("punct", char, offset)
        if char == '"':
            return ("string", self._read_string(), offset)
        if char == "-" or char.isdigit():
            return ("number", self._read_number(), offset)
        if char == "_" or char.isalpha():
            return ("name", self._read_name(), offset)
        raise self._error(offset)

    def _read_name(self) -> str:
        start = self.pos
        text = self.text
        while self.pos < self.length:
            char = text[self.pos]
            if char == "_" or char.isalnum():
                self.pos += 1
            else:
                break
        return text[start:self.pos]

    def _read_number(self) -> str:
        start = self.pos
        text = self.text
        if text[self.pos] == "-":
            self.pos += 1
        self._consume_digits()
        if self.pos < self.length and text[self.pos] == ".":
            self.pos += 1
            self._consume_digits()
        if self.pos < self.length and text[self.pos] in "eE":
            self.pos += 1
            if self.pos < self.length and text[self.pos] in "+-":
                self.pos += 1
            self._consume_digits()
        return text[start:self.pos]

    def _consume_digits(self) -> None:
        text = self.text
        if self.pos >= self.length or not text[self.pos].isdigit():
            raise self._error()
        while self.pos < self.length and text[self.pos].isdigit():
            self.pos += 1

    def _read_string(self) -> str:
        text = self.text
        if text.startswith('"""', self.pos):
            return self._read_block_string()
        self.pos += 1
        chars = []
        while self.pos < self.length:
            char = text[self.pos]
            if char == '"':
                self.pos += 1
                return "".join(chars)
            if char in "\n\r":
                raise self._error(self.pos)
            if char == "\\":
                chars.append(self._read_escape())
            else:
                chars.append(char)
                self.pos += 1
        raise self._error(self.length)

    def _read_block_string(self) -> str:
        text = self.text
        self.pos += 3
        chars = []
        while self.pos < self.length:
            if text.startswith('"""', self.pos):
                self.pos += 3
                return "".join(chars)
            if text.startswith('\\"""', self.pos):
                chars.append('"""')
                self.pos += 4
                continue
            chars.append(text[self.pos])
            self.pos += 1
        raise self._error(self.length)

    def _read_escape(self) -> str:
        text = self.text
        self.pos += 1
        if self.pos >= self.length:
            raise self._error(self.length)
        simple = {
            '"': '"',
            "\\": "\\",
            "/": "/",
            "b": "\b",
            "f": "\f",
            "n": "\n",
            "r": "\r",
            "t": "\t",
        }
        char = text[self.pos]
        if char in simple:
            self.pos += 1
            return simple[char]
        if char == "u":
            self.pos += 1
            hex_part = text[self.pos:self.pos + 4]
            if len(hex_part) != 4 or any(digit not in "0123456789abcdefABCDEF" for digit in hex_part):
                raise self._error(self.pos)
            self.pos += 4
            return chr(int(hex_part, 16))
        raise self._error(self.pos)


class _GraphqlSyntaxError(Exception):
    def __init__(self, offset: int) -> None:
        super().__init__(f"syntax error at offset {offset}")
        self.offset = offset


def _is_excluded_directive(name: str, arguments: dict) -> bool:
    if name == "skip":
        return arguments.get("if") is True
    if name == "include":
        return arguments.get("if") is False
    return False


class _Parser:
    """Parses the supported GraphQL subset into immutable document nodes."""

    def __init__(self, text: str) -> None:
        self.tokenizer = _Tokenizer(text)
        self.text_length = len(text)
        self.tokens = []
        self.index = 0
        while True:
            token = self.tokenizer.next_token()
            self.tokens.append(token)
            if token[0] == "eof":
                break

    def error(self):
        token = self.tokens[min(self.index, len(self.tokens) - 1)]
        return _GraphqlSyntaxError(token[2])

    def peek(self):
        return self.tokens[self.index]

    def advance(self):
        token = self.tokens[self.index]
        if token[0] == "eof":
            raise self.error()
        self.index += 1
        return token

    def expect_punct(self, value: str):
        token = self.peek()
        if token[0] != "punct" or token[1] != value:
            raise self.error()
        self.index += 1

    def expect_name(self) -> str:
        token = self.peek()
        if token[0] != "name":
            raise self.error()
        self.index += 1
        return token[1]

    def accept_punct(self, value: str) -> bool:
        token = self.peek()
        if token[0] == "punct" and token[1] == value:
            self.index += 1
            return True
        return False

    def parse_document(self) -> Document:
        operation = None
        operation_name = None
        selections = ()
        fragments = {}
        while self.peek()[0] != "eof":
            kind, value, _ = self.peek()
            if kind == "punct" and value == "{":
                if operation is not None:
                    raise self.error()
                operation = "query"
                operation_name = None
                selections = self.parse_selection_set()
            elif kind == "name" and value in ("query", "mutation", "subscription"):
                if operation is not None:
                    raise self.error()
                operation = value
                self.advance()
                operation_name = None
                if self.peek()[0] == "name":
                    operation_name = self.advance()[1]
                self.skip_variable_definitions()
                self.parse_directives()
                selections = self.parse_selection_set()
            elif kind == "name" and value == "fragment":
                fragment = self.parse_fragment_definition()
                if fragment.name in fragments:
                    raise _DuplicateFragment(fragment.name)
                fragments[fragment.name] = fragment
            else:
                raise self.error()
        if operation is None:
            raise self.error()
        return Document(operation, operation_name, selections, fragments)

    def skip_variable_definitions(self) -> None:
        if not self.accept_punct("("):
            return
        depth = 1
        while depth:
            token = self.advance()
            if token[0] == "punct" and token[1] == "(":
                depth += 1
            elif token[0] == "punct" and token[1] == ")":
                depth -= 1

    def parse_fragment_definition(self) -> Fragment:
        self.expect_name()
        name = self.expect_name()
        on_token = self.expect_name()
        if on_token != "on":
            raise self.error()
        type_name = self.expect_name()
        directives, excluded = self.parse_directives()
        selections = self.parse_selection_set()
        return Fragment(name, type_name, selections, excluded)

    def parse_selection_set(self) -> tuple:
        self.expect_punct("{")
        selections = []
        while not (self.peek()[0] == "punct" and self.peek()[1] == "}"):
            if self.peek()[0] == "eof":
                raise self.error()
            selections.append(self.parse_selection())
        self.expect_punct("}")
        return tuple(selections)

    def parse_selection(self):
        token = self.peek()
        if token[0] == "punct" and token[1] == "...":
            self.advance()
            next_kind, next_value, _ = self.peek()
            if next_kind == "name" and next_value == "on":
                self.advance()
                type_name = self.expect_name()
                directives, excluded = self.parse_directives()
                selection = self.parse_selection_set()
                return InlineFragment(type_name, directives, selection, excluded)
            if next_kind == "name":
                spread_name = self.advance()[1]
                directives, excluded = self.parse_directives()
                return Spread(spread_name, directives, excluded)
            if next_kind == "punct" and next_value == "{":
                directives, excluded = self.parse_directives()
                selection = self.parse_selection_set()
                return InlineFragment(None, directives, selection, excluded)
            if next_kind == "punct" and next_value == "@":
                directives, excluded = self.parse_directives()
                selection = self.parse_selection_set()
                return InlineFragment(None, directives, selection, excluded)
            raise self.error()
        return self.parse_field()

    def parse_field(self) -> Field:
        first = self.expect_name()
        alias = None
        name = first
        if self.peek()[0] == "punct" and self.peek()[1] == ":":
            self.advance()
            alias = first
            name = self.advance()[1]
        self.parse_arguments()
        directives, excluded = self.parse_directives()
        selection = ()
        if self.peek()[0] == "punct" and self.peek()[1] == "{":
            selection = self.parse_selection_set()
        return Field(name, alias, directives, selection, excluded)

    def parse_arguments(self) -> dict:
        arguments = {}
        if not self.accept_punct("("):
            return arguments
        while not (self.peek()[0] == "punct" and self.peek()[1] == ")"):
            if self.peek()[0] == "eof":
                raise self.error()
            key = self.expect_name()
            self.expect_punct(":")
            arguments[key] = self.parse_value()
        self.expect_punct(")")
        return arguments

    def parse_directives(self) -> tuple[tuple[str, ...], bool]:
        names = []
        excluded = False
        while self.peek()[0] == "punct" and self.peek()[1] == "@":
            self.advance()
            name = self.expect_name()
            arguments = self.parse_arguments()
            names.append(name)
            if _is_excluded_directive(name, arguments):
                excluded = True
        return tuple(names), excluded

    def parse_value(self):
        kind, value, _ = self.peek()
        if kind == "punct" and value == "$":
            self.advance()
            return {"$var": self.expect_name()}
        if kind == "number":
            self.advance()
            if "." in value or "e" in value or "E" in value:
                return float(value)
            return int(value)
        if kind == "string":
            self.advance()
            return value
        if kind == "name":
            self.advance()
            if value == "true":
                return True
            if value == "false":
                return False
            if value == "null":
                return None
            return {"enum": value}
        if kind == "punct" and value == "[":
            self.advance()
            items = []
            while not (self.peek()[0] == "punct" and self.peek()[1] == "]"):
                items.append(self.parse_value())
            self.expect_punct("]")
            return items
        if kind == "punct" and value == "{":
            self.advance()
            obj = {}
            while not (self.peek()[0] == "punct" and self.peek()[1] == "}"):
                key = self.expect_name()
                self.expect_punct(":")
                obj[key] = self.parse_value()
            self.expect_punct("}")
            return obj
        raise self.error()


class _DuplicateFragment(Exception):
    def __init__(self, name: str) -> None:
        super().__init__(name)
        self.name = name


class GraphqlCostLimiter:
    """Decide whether a query is cheap enough to reach the executor."""

    def __init__(self, *, max_cost: int = 1000, max_depth: int = 10,
                 max_aliases: int = 25, introspection_budget: int = 50) -> None:
        self._lock = threading.RLock()
        self._limits = {
            "max_cost": max_cost,
            "max_depth": max_depth,
            "max_aliases": max_aliases,
            "introspection_budget": introspection_budget,
        }
        self._clients: dict[str, dict] = {}
        self._counters = {
            "parsed": 0,
            "admitted": 0,
            "denied": 0,
            "restored": 0,
        }

    def parse(self, query: str) -> Document:
        with self._lock:
            if not isinstance(query, str):
                raise GraphqlError("GRAPHQL_PARSE_ERROR", {"offset": 0})
            try:
                return _Parser(query).parse_document()
            except _DuplicateFragment as exc:
                raise GraphqlError("GRAPHQL_DUPLICATE_FRAGMENT", {"name": exc.name})
            except _GraphqlSyntaxError as exc:
                raise GraphqlError("GRAPHQL_PARSE_ERROR", {"offset": exc.offset})

    def resolve_fragments(self, document: Document) -> Expanded:
        with self._lock:
            self._validate_spreads(document)
            self._detect_fragment_cycles(document)
            selections, _ = self._expand_selections(document, document.selections, {})
            return Expanded(document.operation, document.name, selections)

    def compute_depth(self, document: Document) -> int:
        with self._lock:
            selections = self._expanded_selections(document)
            return self._measure_depth(selections, 1)

    def compute_cost(self, document: Document) -> CostReport:
        with self._lock:
            selections = self._expanded_selections(document)
            tally = {"fields": 0, "cost": 0, "aliases": 0, "introspection": 0}
            for selection in selections:
                self._tally_selection(selection, tally, introspecting=False)
            depth = self._measure_depth(selections, 1)
            return CostReport(
                fields=tally["fields"],
                cost=tally["cost"],
                depth=depth,
                aliases=tally["aliases"],
                introspection=tally["introspection"],
            )

    def check_limits(self, document: Document, *, client: str | None = None) -> Admission:
        with self._lock:
            report = self.compute_cost(document)
            limits = self._effective_limits(client)
            reason = None
            if report.depth > limits["max_depth"]:
                reason = "GRAPHQL_DEPTH_EXCEEDED"
            elif report.cost > limits["max_cost"]:
                reason = "GRAPHQL_COST_EXCEEDED"
            elif report.aliases > limits["max_aliases"]:
                reason = "GRAPHQL_ALIAS_EXCEEDED"
            elif report.introspection > limits["introspection_budget"]:
                reason = "GRAPHQL_INTROSPECTION_EXCEEDED"
            return Admission(reason is None, reason, report, dict(limits))

    def admit(self, query: str, *, client: str | None = None) -> Admission:
        with self._lock:
            self._counters["parsed"] += 1
            document = self.parse(query)
            admission = self.check_limits(document, client=client)
            if admission.allowed:
                self._counters["admitted"] += 1
            else:
                self._counters["denied"] += 1
            return admission

    def set_client_limits(self, client: str, *, max_cost: int | None = None,
                          max_depth: int | None = None,
                          max_aliases: int | None = None,
                          introspection_budget: int | None = None) -> None:
        with self._lock:
            overrides = self._clients.setdefault(client, {})
            if max_cost is not None:
                overrides["max_cost"] = max_cost
            if max_depth is not None:
                overrides["max_depth"] = max_depth
            if max_aliases is not None:
                overrides["max_aliases"] = max_aliases
            if introspection_budget is not None:
                overrides["introspection_budget"] = introspection_budget

    def client_limits(self, client: str) -> dict:
        with self._lock:
            return dict(self._effective_limits(client))

    def clear_client_limits(self, client: str) -> None:
        with self._lock:
            self._clients.pop(client, None)

    def stats(self) -> dict:
        with self._lock:
            return dict(self._counters)

    def snapshot(self) -> dict:
        with self._lock:
            return {
                "version": _SNAPSHOT_VERSION,
                "limits": dict(self._limits),
                "clients": {
                    client: dict(overrides)
                    for client, overrides in self._clients.items()
                },
                "counters": dict(self._counters),
            }

    def restore(self, state: dict) -> None:
        with self._lock:
            self._validate_snapshot(state)
            limits = dict(state["limits"])
            clients = {
                client: dict(overrides)
                for client, overrides in state["clients"].items()
            }
            counters = dict(state["counters"])
            self._limits = limits
            self._clients = clients
            self._counters = counters
            self._counters["restored"] += 1

    def _effective_limits(self, client: str | None) -> dict:
        limits = dict(self._limits)
        if client is not None:
            overrides = self._clients.get(client)
            if overrides:
                limits.update(overrides)
        return limits

    def _expanded_selections(self, document) -> tuple:
        if isinstance(document, Expanded):
            return document.selections
        self._validate_spreads(document)
        self._detect_fragment_cycles(document)
        selections, _ = self._expand_selections(document, document.selections, {})
        return selections

    def _validate_spreads(self, document: Document) -> None:
        stack = [document.selections]
        for fragment in document.fragments.values():
            stack.append(fragment.selection)
        while stack:
            selections = stack.pop()
            for node in selections:
                if isinstance(node, Spread):
                    if node.name not in document.fragments:
                        raise GraphqlError(
                            "GRAPHQL_UNKNOWN_FRAGMENT", {"name": node.name}
                        )
                elif isinstance(node, (Field, InlineFragment)):
                    stack.append(node.selection)

    def _detect_fragment_cycles(self, document: Document) -> None:
        state: dict[str, int] = {}

        def visit(name: str, path: list[str]) -> None:
            state[name] = 1
            path.append(name)
            fragment = document.fragments[name]
            for child in self._spread_names(fragment.selection):
                child_state = state.get(child, 0)
                if child_state == 1:
                    start = path.index(child)
                    raise GraphqlError(
                        "GRAPHQL_FRAGMENT_CYCLE",
                        {"path": path[start:] + [child]},
                    )
                if child_state == 0:
                    visit(child, path)
            path.pop()
            state[name] = 2

        for fragment_name in document.fragments:
            if state.get(fragment_name, 0) == 0:
                visit(fragment_name, [])

    def _spread_names(self, selections) -> list[str]:
        names = []
        for node in selections:
            if isinstance(node, Spread):
                names.append(node.name)
            elif isinstance(node, (Field, InlineFragment)):
                names.extend(self._spread_names(node.selection))
        return names

    def _expand_selections(self, document: Document, selections, memo: dict):
        expanded = []
        for node in selections:
            if node.excluded:
                continue
            if isinstance(node, Field):
                child_selection, memo = self._expand_selections(
                    document, node.selection, memo
                )
                expanded.append(
                    Field(node.name, node.alias, node.directives, child_selection, False)
                )
            elif isinstance(node, InlineFragment):
                child_selection, memo = self._expand_selections(
                    document, node.selection, memo
                )
                expanded.append(
                    InlineFragment(
                        node.type_name, node.directives, child_selection, False
                    )
                )
            else:
                fragment = document.fragments[node.name]
                if fragment.excluded:
                    continue
                if fragment.name not in memo:
                    fragment_selection, memo = self._expand_selections(
                        document, fragment.selection, memo
                    )
                    memo[fragment.name] = fragment_selection
                expanded.extend(memo[fragment.name])
        return tuple(expanded), memo

    def _measure_depth(self, selections, depth: int) -> int:
        deepest = 0
        for node in selections:
            if isinstance(node, Field):
                if node.selection:
                    child_depth = self._measure_depth(node.selection, depth + 1)
                else:
                    child_depth = depth
                deepest = max(deepest, child_depth)
            elif isinstance(node, InlineFragment):
                child_depth = self._measure_depth(node.selection, depth)
                deepest = max(deepest, child_depth)
        return deepest

    def _tally_selection(self, node, tally: dict, *, introspecting: bool) -> None:
        if isinstance(node, InlineFragment):
            for child in node.selection:
                self._tally_selection(child, tally, introspecting=introspecting)
            return
        if not introspecting and node.name in _INTROSPECTION_ROOTS:
            self._tally_introspection_tree(node.selection, tally)
            tally["fields"] += 1
            tally["introspection"] += 1
            if node.alias is not None:
                tally["aliases"] += 1
            return
        tally["fields"] += 1
        if node.alias is not None:
            tally["aliases"] += 1
            if not introspecting:
                tally["cost"] += 2
        elif not introspecting:
            tally["cost"] += 1
        for child in node.selection:
            self._tally_selection(child, tally, introspecting=introspecting)

    def _tally_introspection_tree(self, selections, tally: dict) -> None:
        for node in selections:
            if isinstance(node, InlineFragment):
                self._tally_introspection_tree(node.selection, tally)
                continue
            tally["fields"] += 1
            tally["introspection"] += 1
            if node.alias is not None:
                tally["aliases"] += 1
            self._tally_introspection_tree(node.selection, tally)

    def _validate_snapshot(self, state: dict) -> None:
        if not isinstance(state, dict):
            raise GraphqlError("GRAPHQL_SNAPSHOT_INVALID", {"reason": "not_a_dict"})
        if state.get("version") != _SNAPSHOT_VERSION:
            raise GraphqlError("GRAPHQL_SNAPSHOT_INVALID", {"reason": "bad_version"})
        limits = state.get("limits")
        clients = state.get("clients")
        counters = state.get("counters")
        if not self._is_limit_mapping(limits):
            raise GraphqlError("GRAPHQL_SNAPSHOT_INVALID", {"reason": "bad_limits"})
        if not isinstance(clients, dict) or any(
            not isinstance(client, str) or not self._is_limit_mapping(overrides, partial=True)
            for client, overrides in clients.items()
        ):
            raise GraphqlError("GRAPHQL_SNAPSHOT_INVALID", {"reason": "bad_clients"})
        if not isinstance(counters, dict) or any(
            key not in self._counters
            or not isinstance(value, int)
            or isinstance(value, bool)
            for key, value in counters.items()
        ):
            raise GraphqlError("GRAPHQL_SNAPSHOT_INVALID", {"reason": "bad_counters"})
        if set(counters) != set(self._counters):
            raise GraphqlError("GRAPHQL_SNAPSHOT_INVALID", {"reason": "bad_counters"})

    def _is_limit_mapping(self, value, *, partial: bool = False) -> bool:
        if not isinstance(value, dict):
            return False
        keys = value.keys()
        if partial:
            if not keys:
                return False
        elif set(keys) != set(_LIMIT_KEYS):
            return False
        for key in keys:
            if key not in _LIMIT_KEYS:
                return False
            number = value[key]
            if not isinstance(number, int) or isinstance(number, bool):
                return False
        return True
