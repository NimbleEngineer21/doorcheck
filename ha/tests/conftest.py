"""Real Home Assistant fixtures in an isolated test environment."""

import pytest

pytest_plugins = ["pytest_homeassistant_custom_component"]


@pytest.fixture(autouse=True)
def custom_integration(enable_custom_integrations: None) -> None:
    """Permit loading this checkout's development integration."""


@pytest.fixture(autouse=True)
def frontend_bundle():
    """Framework profiles omit HA's browser bundle; containers test real bootstrap."""
    from unittest.mock import patch

    with patch("homeassistant.components.frontend.async_setup", return_value=True):
        yield
