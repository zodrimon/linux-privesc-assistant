from typing import Type
from privesc_assistant.checks.base import BaseCheck

_CHECK_REGISTRY: list[Type[BaseCheck]] = []

def register_check(cls: Type[BaseCheck]) -> Type[BaseCheck]:
    """Decorator to register a check class in the global registry."""
    _CHECK_REGISTRY.append(cls)
    return cls

def get_registered_checks() -> list[Type[BaseCheck]]:
    """Retrieve all registered check classes."""
    return list(_CHECK_REGISTRY)
