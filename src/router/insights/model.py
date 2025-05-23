"""Project model for the Beacon project."""

from pydantic import BaseModel
from typing_extensions import Optional


class Project(BaseModel):
    """Project model for the Beacon project."""

    name: Optional[str] = None
    url: Optional[str] = None
    description: Optional[str] = None
