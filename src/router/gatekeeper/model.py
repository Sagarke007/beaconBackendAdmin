"""
Data models for Gatekeeper Router.
"""

from typing import Dict
from pydantic import BaseModel


class HealthData(BaseModel):
    """Model for client and project health data."""
    client_name: str
    project_id: str
    payload: dict


class SchemaRequest(BaseModel):
    """Model for schema configuration requests."""
    schema_config: Dict[str, str]