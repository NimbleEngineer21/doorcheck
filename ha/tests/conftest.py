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


@pytest.fixture(autouse=True)
def offline_status():
    """Tests never reach GitHub; test_status.py replaces this with its own mocks."""
    from unittest.mock import patch

    from custom_components.doorcheck import status

    with patch.object(status, "fetch", side_effect=status.FetchError("offline in tests")):
        yield
