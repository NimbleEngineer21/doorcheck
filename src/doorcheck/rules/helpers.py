"""Bounded possible helper paths, without executing source or proving predicates."""

import ast
from dataclasses import dataclass

from doorcheck.rules.path_flow import State, Value, flow, qualified
from doorcheck.rules.project import Project, Unit, root_name
from doorcheck.rules.source import AnalysisLimit, check_deadline

MAX_DEPTH = 8
MAX_STEPS = 20_000
MAX_TRACE = 16
Function = ast.FunctionDef | ast.AsyncFunctionDef


@dataclass(frozen=True)
class Hit:
    site: ast.Call
    sink_path: str
    sink_line: int
    chain: tuple[tuple[str, int], ...]


@dataclass
class Outcome:
    continuing: State | None
    returned: list[Value]


def union(values: list[Value]) -> Value:
    return Value(
        any(v.tainted for v in values),
        bool(values) and all(v.absolute for v in values),
        calls=next((v.calls for v in values if v.tainted and v.calls), ()),
    )


def merge(states: list[State | None]) -> State | None:
    live = [s for s in states if s is not None]
    if not live:
        return None
    keys = set(live[0]).intersection(*(s.keys() for s in live[1:]))
    return {key: union([s[key] for s in live]) for key in keys}


def bindings(function: Function) -> set[str]:
    from doorcheck.capabilities.call_bindings import _stores

    return {
        name
        for node in ast.walk(function)
        if node is not function
        for name in ([node.arg] if isinstance(node, ast.arg) else _stores(node))
    }


def truth(node: ast.AST) -> bool | None:
    if isinstance(node, ast.Constant):
        return bool(node.value)
    if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.Not):
        value = truth(node.operand)
        return None if value is None else not value
    if isinstance(node, ast.BoolOp):
        values = [truth(value) for value in node.values]
        decisive = not isinstance(node.op, ast.And)
        if decisive in values:
            return decisive
        return None if None in values else not decisive
    return None


class Engine:
    def __init__(self, project: Project | None, deadline: float | None) -> None:
        self.project, self.deadline = project, deadline
        self.steps = 0
        self.stack: list[tuple[str, int]] = []
        self.sites: dict[ast.Call, str] = {}
        self.hits: dict[ast.Call, Hit] = {}

    def tick(self) -> None:
        check_deadline(self.deadline)
        self.steps += 1
        if self.steps > MAX_STEPS:
            raise AnalysisLimit("helper_steps")

    def evaluate(self, node: ast.AST, names: State, source: Unit, bound: set[str]) -> Value:
        self.tick()
        return flow(
            node,
            names,
            source.aliases,
            lambda call, awaited: self.call(call, awaited, names, source, bound),
        )

    def resolve(
        self, call: ast.Call, source: Unit, bound: set[str]
    ) -> tuple[Unit, Function] | None:
        name = root_name(call.func)
        if name in bound or name in source.patched:
            return None
        if isinstance(call.func, ast.Name) and name in source.functions:
            return source, source.functions[name]
        target = self.import_target(call, source)
        if target and self.project is not None:
            return self.project.function(target)
        return None

    def import_target(self, call: ast.Call, source: Unit) -> str:
        name = root_name(call.func)
        target = qualified(call.func, source.aliases)
        if name in source.relative and self.project is not None:
            node = source.relative[name]
            imported = next(a.name for a in node.names if (a.asname or a.name) == name)
            target = self.project.qualify(source, node, imported) or ""
            if isinstance(call.func, ast.Attribute):
                target += qualified(call.func, {name: "root"}).removeprefix("root")
        return target

    def call(
        self, call: ast.Call, awaited: bool, names: State, source: Unit, bound: set[str]
    ) -> Value:
        from doorcheck.rules.file_view import SINKS, _reads

        values = [self.evaluate(a, names, source, bound) for a in call.args]
        for keyword in call.keywords:
            self.evaluate(keyword.value, names, source, bound)
        if (
            qualified(call.func, source.aliases) in SINKS
            and values
            and _reads(call, source.aliases)
        ):
            self.record(call, values[0], source)
            return Value()
        if call.keywords or any(isinstance(a, ast.Starred) for a in call.args):
            return Value()
        resolved = self.resolve(call, source, bound)
        if resolved is None:
            return Value()
        target, function = resolved
        if isinstance(function, ast.AsyncFunctionDef) != awaited:
            return Value()
        args = function.args
        positional = [*args.posonlyargs, *args.args]
        if args.vararg or args.kwarg or args.kwonlyargs or len(positional) != len(values):
            return Value()
        self.sites[call] = source.path
        tagged = [self.tag(value, call) for value in values]
        # Length equality is checked above; strict only documents that invariant.
        pairs = zip(positional, tagged, strict=True)  # pragma: no mutate - lengths checked above
        arguments = {p.arg: value for p, value in pairs}
        return self.invoke(target, function, arguments)

    def tag(self, value: Value, call: ast.Call) -> Value:
        if not value.tainted:
            return value
        if len(value.calls) >= MAX_TRACE:
            raise AnalysisLimit("helper_trace")
        return Value(value.tainted, value.absolute, calls=(*value.calls, call))

    def record(self, sink: ast.Call, value: Value, source: Unit) -> None:
        if value.tainted and value.calls:
            site = value.calls[0]
            self.hits.setdefault(
                site,
                Hit(
                    site,
                    source.path,
                    sink.lineno,
                    tuple((self.sites[c], c.lineno) for c in value.calls),
                ),
            )

    def invoke(self, source: Unit, function: Function, names: State) -> Value:
        key = (source.path, function.lineno)
        if key in self.stack:
            raise AnalysisLimit("helper_recursion")
        if len(self.stack) >= MAX_DEPTH:
            raise AnalysisLimit("helper_depth")
        if any(isinstance(n, ast.NamedExpr) for n in ast.walk(function)):
            return Value()
        self.stack.append(key)
        try:
            result = self.block(function.body, names, source, bindings(function))
            return union(result.returned)
        finally:
            self.stack.pop()

    def block(self, body: list[ast.stmt], names: State, source: Unit, bound: set[str]) -> Outcome:
        result = Outcome(names, [])
        for statement in body:
            self.tick()
            if result.continuing is None:
                break
            step = self.statement(statement, result.continuing, source, bound)
            result.continuing = step.continuing
            result.returned.extend(step.returned)
        return result

    def statement(self, stmt: ast.stmt, names: State, source: Unit, bound: set[str]) -> Outcome:
        from doorcheck.rules.file_view import _unbind

        if isinstance(stmt, ast.If):
            return self.branch(stmt, names, source, bound)
        if isinstance(stmt, ast.Try):
            result = self.block(stmt.body, names.copy(), source, bound)
            return Outcome(None, result.returned)
        if isinstance(stmt, (ast.With, ast.AsyncWith)):
            return self.context(stmt, names, source, bound)
        if isinstance(stmt, ast.Assign):
            value = self.evaluate(stmt.value, names, source, bound)
            for target in stmt.targets:
                if isinstance(target, ast.Name):
                    names[target.id] = value
                else:
                    _unbind(target, names)
            return Outcome(names, [])
        return self.simple(stmt, names, source, bound)

    def context(
        self, stmt: ast.With | ast.AsyncWith, names: State, source: Unit, bound: set[str]
    ) -> Outcome:
        from doorcheck.rules.file_view import _unbind

        local = names.copy()
        for item in stmt.items:
            self.evaluate(item.context_expr, local, source, bound)
            if item.optional_vars is not None:
                _unbind(item.optional_vars, local)
        result = self.block(stmt.body, local, source, bound)
        return Outcome(None, result.returned)

    def simple(self, stmt: ast.stmt, names: State, source: Unit, bound: set[str]) -> Outcome:
        if isinstance(stmt, ast.Return):
            value = self.evaluate(stmt.value, names, source, bound) if stmt.value else Value()
            return Outcome(None, [value])
        if isinstance(stmt, ast.Raise):
            if stmt.exc:
                self.evaluate(stmt.exc, names, source, bound)
            return Outcome(None, [])
        if isinstance(stmt, ast.Expr):
            self.evaluate(stmt.value, names, source, bound)
            return Outcome(names, [])
        return Outcome(names if isinstance(stmt, ast.Pass) else None, [])

    def branch(self, stmt: ast.If, names: State, source: Unit, bound: set[str]) -> Outcome:
        self.evaluate(stmt.test, names, source, bound)
        known = truth(stmt.test)
        if known is not None:
            body = stmt.body if known else stmt.orelse
            return self.block(body, names.copy(), source, bound)
        yes = self.block(stmt.body, names.copy(), source, bound)
        no = self.block(stmt.orelse, names.copy(), source, bound)
        return Outcome(merge([yes.continuing, no.continuing]), yes.returned + no.returned)
