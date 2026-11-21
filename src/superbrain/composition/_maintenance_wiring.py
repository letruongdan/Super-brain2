"""Composition wiring registering ``StorageMaintenanceAdapter`` with ``application.maintenance``."""

from __future__ import annotations

from superbrain.application.maintenance import register_maintenance_backend
from superbrain.storage._maintenance_adapter import StorageMaintenanceAdapter

_BACKEND = StorageMaintenanceAdapter()


def ensure_maintenance_backend() -> StorageMaintenanceAdapter:
    """Register and return the concrete ``StorageMaintenanceAdapter``."""
    register_maintenance_backend(_BACKEND)
    return _BACKEND


ensure_maintenance_backend()
