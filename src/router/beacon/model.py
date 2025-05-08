"""Project model for the Beacon project."""
from pydantic import BaseModel

class Project(BaseModel):
    """ Project model for the Beacon project."""
    name: str
    url: str
    description: str