"""
Module Registry — auto-discovers, loads, and manages parser modules.
Scans the modules/ directory for subpackages implementing ParserModule.
"""
from __future__ import annotations

import inspect
import importlib
import importlib.util
import os
import sys
from pathlib import Path
from typing import Any

from modules.interface import ParserModule


class ModuleRegistry:
    """
    Central registry for all parser modules.
    Auto-discovers modules from the modules/ directory.

    Usage:
        registry = ModuleRegistry("modules/")
        registry.discover()
        module = registry.match("some log line")
        parsed = module.parse(raw, format)
    """

    def __init__(self, modules_dir: str = "modules"):
        self.modules_dir = Path(modules_dir)
        self._modules: dict[str, ParserModule] = {}
        self._all_instances: list[ParserModule] = []

    def discover(self) -> list[ParserModule]:
        """
        Scan modules/ directory and load all parser modules.
        Finds any subpackage that has a class implementing ParserModule.

        Returns:
            List of loaded ParserModule instances.
        """
        self._modules = {}
        self._all_instances = []

        if not self.modules_dir.exists():
            print(f"[Registry] Modules directory not found: {self.modules_dir}")
            return []

        # Add modules/ to sys.path so imports work
        modules_parent = str(self.modules_dir.parent)
        if modules_parent not in sys.path:
            sys.path.insert(0, modules_parent)

        for entry in sorted(self.modules_dir.iterdir()):
            if not entry.is_dir():
                continue
            if entry.name.startswith("_") or entry.name == "interface":
                continue

            module_name = entry.name
            self._load_module(module_name, entry)

        print(f"[Registry] Discovered {len(self._all_instances)} modules: "
              f"{[m.name for m in self._all_instances]}")
        return self._all_instances

    def _load_module(self, module_name: str, module_path: Path):
        """
        Attempt to load a single module package.
        Looks for an __init__.py that defines classes implementing ParserModule.
        Also supports loading from config.yaml-only modules.
        """
        init_file = module_path / "__init__.py"
        config_file = module_path / "config.yaml"

        if not init_file.exists():
            if config_file.exists():
                # YAML-only module — load via generic config loader
                self._load_yaml_module(module_name, config_file)
            return

        try:
            # Import the module package
            spec = importlib.util.spec_from_file_location(
                f"modules.{module_name}",
                init_file,
                submodule_search_locations=[str(module_path)],
            )
            if spec is None or spec.loader is None:
                return

            module_pkg = importlib.util.module_from_spec(spec)
            sys.modules[f"modules.{module_name}"] = module_pkg
            spec.loader.exec_module(module_pkg)

            # Find all classes in the module that implement ParserModule
            for attr_name in dir(module_pkg):
                attr = getattr(module_pkg, attr_name)
                if (isinstance(attr, type)
                        and issubclass(attr, ParserModule)
                        and attr is not ParserModule):
                    # Skip abstract classes (like BaseParser)
                    if inspect.isabstract(attr):
                        continue
                    try:
                        instance = attr()
                        self._register(instance)
                    except TypeError as e:
                        # Abstract class without implementation — skip silently
                        if "abstract" not in str(e).lower():
                            print(f"[Registry] Could not instantiate {attr_name}: {e}")

        except Exception as e:
            print(f"[Registry] Failed to load module '{module_name}': {e}")

    def _load_yaml_module(self, module_name: str, config_path: Path):
        """Load a simple YAML-only module."""
        try:
            import yaml
            with open(config_path, "r") as f:
                config = yaml.safe_load(f)

            from modules.yaml_parser import YamlParserModule
            instance = YamlParserModule(config, module_name)
            self._register(instance)
        except Exception as e:
            print(f"[Registry] Failed to load YAML module '{module_name}': {e}")

    def _register(self, module: ParserModule):
        """Register a module instance."""
        if not module.name:
            module.name = getattr(module, "__module_name__", "unknown")
        self._all_instances.append(module)
        self._modules[module.name] = module

    # ── Query methods ───────────────────────────────────────────────

    def get(self, name: str) -> ParserModule | None:
        """Get a module by name."""
        return self._modules.get(name)

    def get_all(self) -> list[ParserModule]:
        """Get all registered modules."""
        return list(self._all_instances)

    def match(self, raw: str) -> tuple[ParserModule | None, str, float]:
        """
        Find the best matching module for a raw log line.

        Args:
            raw: Raw log line.

        Returns:
            (module, detected_format, confidence)
        """
        best_module = None
        best_confidence = 0.0
        best_format = "unknown"

        for module in self._all_instances:
            try:
                confidence, fmt = module.recognize(raw)
                if confidence > best_confidence:
                    best_confidence = confidence
                    best_module = module
                    best_format = fmt
            except Exception:
                continue

        return best_module, best_format, best_confidence

    def match_or_fallback(self, raw: str, fallback_name: str = "generic_syslog") -> tuple[ParserModule, str, bool]:
        """
        Match the best module for the raw log.
        Returns (module, format, is_fallback) where is_fallback=True means
        the generic fallback module was used (no specific module matched).
        Never returns None.
        """
        module, fmt, conf = self.match(raw)
        if module and conf >= 0.5:
            return module, fmt, False  # Specific module matched
        # Use generic fallback
        fallback = self._modules.get(fallback_name)
        if fallback:
            return fallback, "unknown", True  # Generic fallback
        if self._all_instances:
            return self._all_instances[0], "unknown", True
        raise RuntimeError("No modules registered")

    def get_by_format(self, format: str) -> list[ParserModule]:
        """Get all modules that support a given format."""
        return [m for m in self._all_instances if format in m.supported_formats]

    def __len__(self) -> int:
        return len(self._all_instances)

    def __repr__(self) -> str:
        return f"ModuleRegistry(modules={list(self._modules.keys())})"
