from pydantic import BaseModel


class HealthData(BaseModel):
    client_name: str
    project_id: str
    payload: dict