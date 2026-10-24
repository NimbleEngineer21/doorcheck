"""A plain integration, used to record that scanning tools report nothing."""

DOMAIN = "clean_demo"


async def async_setup(hass, config):
    hass.data[DOMAIN] = {}
    return True
