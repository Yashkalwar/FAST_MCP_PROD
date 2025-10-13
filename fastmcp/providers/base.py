from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Dict


class ProviderAdapter(ABC):
    provider_id: str

    def __init__(self, provider_id: str):
        self.provider_id = provider_id

    @abstractmethod
    async def exchange(self, scopes: list[str], subject: str, tenant: str, purpose: str) -> dict:
        """Return provider token metadata."""

    @abstractmethod
    async def call(self, endpoint: str, payload: dict) -> dict:
        """Execute provider endpoint."""


_registry: Dict[str, ProviderAdapter] = {}


def register_adapter(adapter: ProviderAdapter) -> None:
    _registry[adapter.provider_id] = adapter


def get_adapter(provider_id: str) -> ProviderAdapter:
    adapter = _registry.get(provider_id)
    if not adapter:
        raise KeyError(f"provider {provider_id} not registered")
    return adapter


def list_adapters() -> list[str]:
    return list(_registry.keys())

