"""Real Home Assistant fixtures in an isolated test environment."""

import pytest

pytest_plugins = ["pytest_homeassistant_custom_component"]


@pytest.fixture(autouse=True)
def custom_integration(enable_custom_integrations: None) -> None:
    """Permit loading this checkout's development integration."""
