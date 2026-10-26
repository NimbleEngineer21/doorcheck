"""Adapters are found through the `doorcheck.adapters` entry-point group, so a new
tool plugs in by declaring one in its own package; the pipeline doesn't change.

An installed package can add an adapter, so a broken one is reported by name
instead of stopping every other tool from running.
"""

from dataclasses import dataclass
from importlib.metadata import EntryPoint, entry_points

from doorcheck.adapters.base import Adapter, Audience

GROUP = "doorcheck.adapters"


@dataclass(frozen=True, slots=True)
class Loaded:
    adapters: dict[str, Adapter]
    problems: dict[str, str]  # entry-point name -> why it couldn't be loaded

    def selected(self, audience: Audience, experimental: bool = False) -> list[Adapter]:
        """The adapters for one audience; experimental ones only when asked for."""
        return [
            adapter
            for _, adapter in sorted(self.adapters.items())
            if adapter.audience is audience and (experimental or not adapter.experimental)
        ]


def load(points: tuple[EntryPoint, ...] | None = None) -> Loaded:
    adapters: dict[str, Adapter] = {}
    problems: dict[str, str] = {}
    for point in points if points is not None else tuple(entry_points(group=GROUP)):
        try:
            adapter = point.load()()
            problem = _problem(adapter, point.name)
        except Exception as error:  # a third-party plugin can fail in any way
            problems[point.name] = f"{type(error).__name__}: {error}"
            continue
        if problem:
            problems[point.name] = problem
            continue
        adapters[point.name] = adapter
    return Loaded(adapters, problems)


def _problem(adapter: object, name: str) -> str:
    called = getattr(adapter, "name", None)
    if called != name:
        return f"adapter calls itself {called!r}"
    if not isinstance(getattr(adapter, "audience", None), Audience):
        return "adapter doesn't say who its results are for (audience)"
    if not isinstance(getattr(adapter, "experimental", None), bool):
        return "adapter doesn't say whether it is experimental"
    for field in ("version", "executable"):
        value = getattr(adapter, field, None)
        if not isinstance(value, str) or not value:
            return f"adapter has no valid {field}"
    for method in ("version_command", "command", "parse"):
        if not callable(getattr(adapter, method, None)):
            return f"adapter has no callable {method}"
    return ""
