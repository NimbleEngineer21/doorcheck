import ast

from doorcheck.capabilities.python_scopes import scopes


def test_scope_groups_preserve_definition_headers_and_method_closures() -> None:
    tree = ast.parse(
        "def worker(x=outer()):\n    inner()\n"
        "class View:\n    body()\n"
        "    def method(self, y=header()):\n        work()\n"
    )
    groups = scopes(tree)
    root = groups[0]
    assert root.owner is tree
    assert root.parent is None
    actual = {
        (node.func.id, getattr(group.owner, "name", "module"))
        for group in groups
        for node in group.nodes
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
    }
    assert actual == {
        ("outer", "module"),
        ("inner", "worker"),
        ("body", "View"),
        ("header", "View"),
        ("work", "method"),
    }
    method = next(group for group in groups if getattr(group.owner, "name", None) == "method")
    assert method.parent is root
