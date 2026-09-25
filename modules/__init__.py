"""
Modules package — plug-and-play parser modules.

Each subdirectory in this package is a self-contained parser module.
To add a new log source, create a new subdirectory with:
  - __init__.py: A class implementing ParserModule
  - config.yaml: Patterns, mappings, and metadata (optional but recommended)

The registry auto-discovers all modules at startup.
"""
from modules.registry import ModuleRegistry

# Global registry instance — populated at startup
_registry: ModuleRegistry | None = None


def get_registry() -> ModuleRegistry:
    """Get the global module registry (lazy-initialized)."""
    global _registry
    if _registry is None:
        _registry = ModuleRegistry("modules")
        _registry.discover()
    return _registry


def reset_registry():
    """Reset the global registry (useful for testing or hot-reload)."""
    global _registry
    _registry = None
