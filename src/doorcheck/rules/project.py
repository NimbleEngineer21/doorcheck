"""Bounded, source-only lookup of unambiguous helpers inside the selected tree."""

import ast
import json
import os
import stat
from collections import Counter
from contextlib import ExitStack
from dataclasses import dataclass
from pathlib import Path

from doorcheck.capabilities.call_bindings import _imports as import_bindings
from doorcheck.capabilities.call_bindings import _stores
from doorcheck.capabilities.model import ScanLimits
from doorcheck.rules.source import AnalysisLimit, check_deadline
from doorcheck.tree import entries

MAX_MODULES = 32
MAX_BYTES = 2_000_000
MAX_NODES = 100_000


@dataclass
class Unit:
    path: str
    aliases: dict[str, str]
    functions: dict[str, ast.FunctionDef | ast.AsyncFunctionDef]
    relative: dict[str, ast.ImportFrom]
    patched: set[str]


def root_name(node: ast.AST) -> str:
    while isinstance(node, ast.Attribute):
        node = node.value
    return node.id if isinstance(node, ast.Name) else ""


def _bound_names(
    tree: ast.Module, definitions: list[ast.FunctionDef | ast.AsyncFunctionDef]
) -> set[str]:
    top = {id(n) for n in tree.body if isinstance(n, (ast.Import, ast.ImportFrom))}
    own = {id(n) for n in definitions}
    bound = set()
    for node in ast.walk(tree):
        if id(node) not in own | top:
            bound.update(_stores(node))
        if isinstance(node, ast.arg):
            bound.add(node.arg)
    return bound


def _relative_imports(
    tree: ast.Module, bound: set[str], counts: Counter[str]
) -> dict[str, ast.ImportFrom]:
    result = {}
    for node in tree.body:
        if isinstance(node, ast.ImportFrom) and node.level:
            for name in node.names:
                local = name.asname or name.name
                if local not in bound and counts[local] == 1:
                    result[local] = node
    return result


def _functions(
    definitions: list[ast.FunctionDef | ast.AsyncFunctionDef], bound: set[str]
) -> dict[str, ast.FunctionDef | ast.AsyncFunctionDef]:
    counts = Counter(n.name for n in definitions)
    return {
        n.name: n
        for n in definitions
        if counts[n.name] == 1 and n.name not in bound and not n.decorator_list
    }


def unit(tree: ast.Module, path: str, aliases: dict[str, str]) -> Unit:
    if any(
        isinstance(n, ast.ImportFrom) and any(a.name == "*" for a in n.names)
        for n in ast.walk(tree)
    ):
        return Unit(path, {}, {}, {}, set())
    definitions = [n for n in tree.body if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))]
    imports = Counter(name for n in tree.body for name, _ in import_bindings(n))
    bound = _bound_names(tree, definitions)
    functions = _functions(definitions, bound | imports.keys())
    relative = _relative_imports(tree, bound | {n.name for n in definitions}, imports)
    trusted = {k: v for k, v in aliases.items() if k not in bound and imports[k] <= 1}
    return Unit(path, trusted, functions, relative, bound)


def module_name(relative: str) -> str | None:
    parts = list(Path(relative).with_suffix("").parts)
    if parts[-1] == "__init__":
        parts.pop()
    return ".".join(parts) if all(p.isascii() and p.isidentifier() for p in parts) else None


def read_source(root: Path, relative: str, limit: int) -> bytes:
    """Open only regular files beneath root, refusing links at every candidate component."""
    path = Path(relative)
    if path.is_absolute() or not path.parts or ".." in path.parts:
        raise ValueError("helper path must remain below the selected root")
    with ExitStack() as stack:
        parent = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        stack.callback(os.close, parent)
        for part in path.parts[:-1]:
            parent = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
            stack.callback(os.close, parent)
        descriptor = os.open(
            path.parts[-1], os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW, dir_fd=parent
        )
        with os.fdopen(descriptor, "rb") as handle:
            if not stat.S_ISREG(os.fstat(handle.fileno()).st_mode):
                raise OSError("helper source is not a regular file")
            return handle.read(limit)


class Project:
    def __init__(self, root: Path, limits: ScanLimits, deadline: float) -> None:
        self.root, self.limits, self.deadline = root, limits, deadline
        self.paths: dict[str, str] | None = None
        self.names: dict[str, str] = {}
        self.cache: dict[str, Unit] = {}
        self.size = 0
        self.nodes = 0

    def index(self) -> None:
        check_deadline(self.deadline)
        paths: dict[str, str] = {}
        duplicates = set()

        def failed(error: OSError) -> None:
            raise AnalysisLimit("helper_index") from error

        for count, entry in enumerate(entries(self.root, failed), 1):
            check_deadline(self.deadline)
            if count > self.limits.max_files:
                raise AnalysisLimit("helper_index")
            if entry.path.suffix == ".py" and (name := module_name(entry.relative)) is not None:
                if name in paths:
                    duplicates.add(name)
                paths[name] = entry.relative
        check_deadline(self.deadline)
        prefix = self.prefix() if "" in paths else ""
        check_deadline(self.deadline)
        self.paths = {
            (prefix + name).rstrip("."): path
            for name, path in paths.items()
            if name not in duplicates
        }
        self.names = {path: name for name, path in self.paths.items()}

    def prefix(self) -> str:
        # A selected HA integration is copied under an arbitrary private folder name.
        # Only its declared custom_components package name is mapped, never suffix matches.
        try:
            raw = read_source(self.root, "manifest.json", 65_537)
            data = json.loads(raw) if len(raw) <= 65_536 else None
        except (OSError, ValueError, UnicodeError):
            return ""
        domain = data.get("domain") if isinstance(data, dict) else None
        if isinstance(domain, str) and domain.isascii() and domain.isidentifier():
            return f"custom_components.{domain}."
        return ""

    def qualify(self, caller: Unit, node: ast.ImportFrom, imported: str) -> str | None:
        if self.paths is None:
            self.index()
        name = self.names.get(caller.path)
        if name is None:
            return None
        package = name if Path(caller.path).name == "__init__.py" else name.rpartition(".")[0]
        parts = package.split(".") if package else []
        if node.level > len(parts):
            return None
        base = parts[: len(parts) - node.level + 1]
        return ".".join([*base, *([node.module] if node.module else []), imported])

    def function(
        self, qualified: str
    ) -> tuple[Unit, ast.FunctionDef | ast.AsyncFunctionDef] | None:
        if self.paths is None:
            self.index()
        module, _, name = qualified.rpartition(".")
        assert self.paths is not None  # pragma: no mutate - index postcondition  # noqa: S101
        path = self.paths.get(module)
        if path is None:
            return None
        if path not in self.cache:
            self.cache[path] = self.load(path)
        source = self.cache[path]
        function = source.functions.get(name)
        return (source, function) if function is not None else None

    def load(self, relative: str) -> Unit:
        from doorcheck.rules.file_view import _imports

        check_deadline(self.deadline)
        if len(self.cache) >= MAX_MODULES:
            raise AnalysisLimit("helper_modules")
        cap = min(self.limits.max_python_bytes, self.limits.max_file_bytes)
        try:
            data = read_source(self.root, relative, cap + 1)
            if len(data) > cap or self.size + len(data) > MAX_BYTES:
                raise AnalysisLimit("helper_bytes")
            source = data.decode("utf-8")  # pragma: no mutate - codec names ignore case
            tree = ast.parse(source)
        except (OSError, SyntaxError, UnicodeError) as error:
            raise AnalysisLimit("helper_source") from error
        self.size += len(data)
        for _ in ast.walk(tree):
            check_deadline(self.deadline)
            self.nodes += 1
            if self.nodes > MAX_NODES:
                raise AnalysisLimit("helper_nodes")
        return unit(tree, relative, _imports(tree))
