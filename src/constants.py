"""Version and release defaults shared by the Vagruw modules."""

__version__ = "0.1.0"

# The Wazuh version used when the user does not choose another one. The value is
# deliberately explicit because installer flags and repository layout can change
# between Wazuh release families.
DEFAULT_WAZUH_VERSION = "4.14.9"

__all__ = ["DEFAULT_WAZUH_VERSION", "__version__"]
