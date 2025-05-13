from typing import Dict

from pydantic import BaseModel


class HealthData(BaseModel):
    client_name: str
    project_id: str
    payload: dict


class SchemaRequest(BaseModel):
    schema_config: Dict[str, str]