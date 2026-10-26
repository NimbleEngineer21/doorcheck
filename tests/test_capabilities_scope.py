import pytest

from doorcheck.capabilities.model import Kind
from tests.test_capabilities_python import found


@pytest.mark.parametrize(
    ("source", "programs"),
    [
        (
            "import subprocess as sp\ndef unrelated():\n    import json as sp\nsp.run(['id'])",
            ["id"],
        ),
        (
            (
                "import json as sp\n"
                "def worker():\n"
                "    import subprocess as sp\n"
                "    sp.run(['id'])\n"
                "sp.run(['no'])"
            ),
            ["id"],
        ),
        (
            (
                "def one():\n"
                "    import subprocess as sp\n"
                "    sp.run(['one'])\n"
                "def two():\n"
                "    import json as sp\n"
                "    sp.run(['two'])"
            ),
            ["one"],
        ),
        (
            (
                "def outer():\n"
                "    import subprocess as sp\n"
                "    def nested():\n"
                "        import json as sp\n"
                "    sp.run(['id'])"
            ),
            ["id"],
        ),
        (
            "import subprocess as sp\ndef outer():\n    def nested():\n        sp.run(['id'])",
            ["id"],
        ),
        (
            (
                "import subprocess as sp\n"
                "class C:\n"
                "    import json as sp\n"
                "    def method(self):\n"
                "        sp.run(['id'])"
            ),
            ["id"],
        ),
        (
            (
                "import json as sp\n"
                "class C:\n"
                "    import subprocess as sp\n"
                "    probe = sp.run(['class'])\n"
                "    def method(self):\n"
                "        sp.run(['no'])"
            ),
            ["class"],
        ),
        (
            "import subprocess as sp\ndef worker(sp=sp.run(['default'])):\n    sp.run(['no'])",
            ["default"],
        ),
        ("import subprocess as sp\nf = lambda sp=sp.run(['default']): sp.run(['no'])", ["default"]),
        (
            (
                "def outer():\n"
                "    import subprocess as sp\n"
                "    class C:\n"
                "        import json as sp\n"
                "        class D:\n"
                "            def method(self):\n"
                "                sp.run(['id'])"
            ),
            ["id"],
        ),
        (
            (
                "import json as sp\n"
                "async def worker():\n"
                "    import subprocess as sp\n"
                "    sp.run(['id'])\n"
                "sp.run(['no'])"
            ),
            ["id"],
        ),
        (
            (
                "import subprocess as sp\n"
                "class C:\n"
                "    @sp.run(['decorator'])\n"
                "    def method(self, sp):\n"
                "        sp.run(['no'])"
            ),
            ["decorator"],
        ),
    ],
)
def test_import_aliases_belong_to_their_lexical_scope(source: str, programs: list[str]) -> None:
    assert found(source) == [(Kind.PROCESS, program) for program in programs]


@pytest.mark.parametrize(
    "definition",
    [
        "def worker(sp):\n    sp.run(['no'])",
        "async def worker(sp):\n    sp.run(['no'])",
        "def worker(sp, /):\n    sp.run(['no'])",
        "def worker(*, sp):\n    sp.run(['no'])",
        "def worker(*sp):\n    sp.run(['no'])",
        "def worker(**sp):\n    sp.run(['no'])",
        "worker = lambda sp: sp.run(['no'])",
    ],
)
def test_parameters_shadow_inherited_imports(definition: str) -> None:
    assert found(f"import subprocess as sp\n{definition}") == []


def test_an_import_can_replace_a_parameter_inside_its_own_function() -> None:
    assert found("def worker(sp):\n    import subprocess as sp\n    sp.run(['id'])") == [
        (Kind.PROCESS, "id")
    ]


def test_hass_aliases_do_not_leak_between_functions() -> None:
    source = "def one():\n    h = hass\n    h.auth\ndef two():\n    h.auth"
    assert found(source) == [(Kind.HA_AUTH, "hass.auth")]


def test_parameters_shadow_inherited_hass_aliases() -> None:
    assert found("h = hass\ndef worker(h):\n    h.auth") == []


def test_local_imports_shadow_inherited_hass_aliases() -> None:
    assert found("h = hass\ndef worker():\n    import json as h\n    h.auth") == []


@pytest.mark.parametrize(
    "source",
    [
        "import subprocess\ndef worker(subprocess):\n    subprocess.run(['no'])",
        "def worker(exec):\n    exec(code)",
        "from builtins import eval\ndef worker(eval):\n    eval(code)",
        "import subprocess\ndef worker(subprocess):\n    subprocess.run = replacement",
        "from . import subprocess\nsubprocess.run(['no'])",
        "from .subprocess import run\nrun(['no'])",
        "from .utils import exec\nexec(code)",
        "from .utils import getattr\ngetattr(module, name)",
    ],
)
def test_shadowed_library_and_builtin_spellings_are_not_reported_as_globals(source: str) -> None:
    assert found(source) == []


def test_parameters_shadow_module_date_constants() -> None:
    source = (
        "from datetime import datetime\n"
        "WHEN = datetime(2027, 1, 1)\n"
        "def worker(WHEN):\n"
        "    if datetime.now() > WHEN: pass"
    )
    assert found(source) == []


def test_a_parameter_used_as_a_class_base_is_not_a_home_assistant_view() -> None:
    assert found("def worker(base):\n    class View(base):\n        pass") == []


def test_relative_import_attribute_assignment_is_not_a_library_replacement() -> None:
    assert found("from . import local\nlocal.handler = replacement") == []
