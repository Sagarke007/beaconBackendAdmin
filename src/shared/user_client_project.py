"""
user client_project
"""
import json
from pathlib import Path
from typing import Dict, List, Optional


class UserClientProjectManager:
    def __init__(self, json_file_path: str = "user_client_projects.json") -> None:
        self.json_file = Path(json_file_path)
        self._initialize_file()

    def _initialize_file(self) -> None:
        """Create the JSON file with empty structure if it doesn't exist"""
        if not self.json_file.exists():
            with open(self.json_file, 'w') as f:
                json.dump({"user_client_projects": []}, f, indent=2)

    def _load_data(self) -> Dict:
        """Load data from JSON file"""
        with open(self.json_file, 'r') as f:
            return json.load(f)

    def _save_data(self, data: Dict) -> None:
        """Save data to JSON file"""
        with open(self.json_file, 'w') as f:
            json.dump(data, f, indent=2)

    def add_user_client_project(self, user_id: str, client_id: str, project_ids: List[str]) -> None:
        """Add a new user-client-project relationship"""
        data = self._load_data()

        # Check if user already exists
        for entry in data["user_client_projects"]:
            if entry["user_id"] == user_id:
                return (f"User {user_id} already exists in the system")

        # Add new entry
        data["user_client_projects"].append({
            "user_id": user_id,
            "project_ids": project_ids
        })

        self._save_data(data)

    def get_projects_for_user(self, user_id: str) -> List[str]:
        """Get all project IDs for a user"""
        data = self._load_data()
        for entry in data["user_client_projects"]:
            if entry["user_id"] == user_id:
                return entry["project_ids"]
        return []

    def get_client_for_user(self, user_id: str) -> Optional[str]:
        """Get client ID for a user"""
        data = self._load_data()
        for entry in data["user_client_projects"]:
            if entry["user_id"] == user_id:
                return entry["client_name"]
        return None

    def add_project_to_user(self, user_id: str, project_id: str) -> None:
        """Add a project to an existing user"""
        data = self._load_data()
        for entry in data["user_client_projects"]:
            if entry["user_id"] == user_id:
                if project_id not in entry["project_ids"]:
                    entry["project_ids"].append(project_id)
                    self._save_data(data)
                    return
        return (f"User {user_id} not found")

    def remove_project_from_user(self, user_id: str, project_id: str) -> None:
        """Remove a project from a user"""
        data = self._load_data()
        for entry in data["user_client_projects"]:
            if entry["user_id"] == user_id:
                if project_id in entry["project_ids"]:
                    entry["project_ids"].remove(project_id)
                    self._save_data(data)
                    return
        return (f"Project {project_id} not found for user {user_id}")