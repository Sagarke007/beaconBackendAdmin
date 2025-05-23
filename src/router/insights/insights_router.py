"""
Beacon Router
"""
import json
from datetime import datetime, timedelta
from fastapi import Depends, APIRouter, HTTPException, Query
from uuid import uuid4
from shared.database import read_data, write_data
from shared.user_utils import UserLoginHandler
from router.insights.model import Project
from router.gatekeeper.gatekeeper_router import LOCAL_DIR
from shared.http_responses import HTTPResponse
from shared.utils import create_dsn
from shared.insight_utils import project_information


DATA_FILE = "projects.json"
USER_LOGIN = UserLoginHandler()
router = APIRouter()


@router.post("/create_project")
def create_project(
    request: Project, user_info: str = Depends(USER_LOGIN.authenticate_token)
):
    """
    Create a new project for a user.
    """
    try:
        _, user_info_data = user_info
        user_id = user_info_data["user_id"]
        data = read_data(DATA_FILE)

        if user_id not in data["users"]:
            data["users"][user_id] = {"projects": []}

        new_project = request.dict()
        new_project["project_id"] = str(uuid4())

        data["users"][user_id]["projects"].append(new_project)
        write_data(data, DATA_FILE)

        return HTTPResponse().success(
            response_message=f"Successfully created project {new_project['name']}"
        )
    except Exception as e:
        return HTTPResponse().failed(
            response_message=f"Failed to create project: {str(e)}"
        )


@router.get("/projects")
def get_projects(user_info: str = Depends(USER_LOGIN.authenticate_token)):
    """
    Get all projects for the authenticated user with API usage stats and date-wise summary.
    """
    try:
        _, user_info_data = user_info
        user_id = user_info_data["user_id"]
        client_name = "AgentMira"
        project_details = project_information(user_id)
        return HTTPResponse().success(
            response_data={"client_name": client_name, "project": project_details}
        )
    except Exception as e:
        return HTTPResponse().failed(
            response_message=f"Failed to fetch projects: {str(e)}"
        )


@router.put("/update_project/{project_id}")
def update_project(
    project_id: str,
    request: Project,
    user_info: str = Depends(USER_LOGIN.authenticate_token),
):
    """
    Update a specific project by ID for the authenticated user.
    """
    try:
        _, user_info_data = user_info
        user_id = user_info_data["user_id"]
        data = read_data(DATA_FILE)

        projects = data["users"].get(user_id, {}).get("projects", [])
        for project in projects:
            if project["project_id"] == project_id:
                project.update(request.dict(exclude_unset=True))
                write_data(data, DATA_FILE)
                return HTTPResponse().success(
                    response_message=f"Successfully updated project {project['name']}"
                )
        raise HTTPException(status_code=404, detail="Project not found")
    except Exception as e:
        return HTTPResponse().failed(
            response_message=f"Failed to update project: {str(e)}"
        )


@router.delete("/delete_project/{project_id}")
def delete_project(
    project_id: str, user_info: str = Depends(USER_LOGIN.authenticate_token)
):
    """
    Delete a project by ID for the authenticated user.
    """
    try:
        _, user_info_data = user_info
        user_id = user_info_data["user_id"]
        data = read_data(DATA_FILE)

        projects = data["users"].get(user_id, {}).get("projects", [])
        new_projects = [p for p in projects if p["project_id"] != project_id]

        if len(new_projects) == len(projects):
            return HTTPResponse().failed(response_message="Project not found")

        data["users"][user_id]["projects"] = new_projects
        write_data(data, DATA_FILE)

        return HTTPResponse().success(response_message="Successfully deleted project")
    except Exception as e:
        return HTTPResponse().failed(
            response_message=f"Failed to delete project: {str(e)}"
        )


@router.get("/logs/{project_id}")
def get_4xx_logs(
        project_id: str, user_info: str = Depends(USER_LOGIN.authenticate_token)
):
    """
    Returns all log entries with 4xx status codes for authenticated user.
    """
    try:
        _, user_info_data = user_info
        user_id = user_info_data["user_id"]

        file_path = LOCAL_DIR / "api_log" / user_id / f"{project_id}.json"
        if not file_path.exists():
            return HTTPResponse().failed(response_message="Log file not found.")

        with open(file_path, "r", encoding="utf-8") as f:
            try:
                log_entries = json.load(f)
            except json.JSONDecodeError:
                return HTTPResponse().failed(response_message="Invalid JSON format.")

        filtered_logs = [
            entry for entry in log_entries[::-1]
            if 400 <= int(entry.get("status_code", 0)) < 600
        ]

        return HTTPResponse().success(response_data=filtered_logs)

    except FileNotFoundError:
        return HTTPResponse().failed(response_message="Log file not found.")
    except json.JSONDecodeError:
        return HTTPResponse().failed(response_message="Invalid JSON format.")
    except Exception as e:
        return HTTPResponse().failed(response_message=f"Failed to retrieve logs: {str(e)}")


@router.get("/logs/{project_id}/poll")
def poll_latest_logs(
    project_id: str,
    since: str = Query(
        None,
        description="ISO timestamp to fetch new logs after (defaults to last 5 minutes)",
    ),
    user_info: str = Depends(USER_LOGIN.authenticate_token),
):
    """
    Polls for new 4xx/5xx logs since the provided timestamp.
    If `since` is not provided, defaults to logs from the last 5 minutes.
    """
    try:
        _, user_info_data = user_info
        user_id = user_info_data["user_id"]

        file_path = LOCAL_DIR / "api_log" / user_id / f"{project_id}.json"
        if not file_path.exists():
            return HTTPResponse().failed(response_message="Log file not found.")

        # Handle `since` fallback
        if since:
            try:
                since_dt = datetime.fromisoformat(since)
            except ValueError:
                return HTTPResponse().failed(
                    response_message="Invalid 'since' timestamp format. Use ISO 8601."
                )
        else:
            since_dt = datetime.utcnow() - timedelta(minutes=5)

        with open(file_path, "r") as f:
            try:
                log_entries = json.load(f)
            except json.JSONDecodeError:
                return HTTPResponse().failed(response_message="Invalid JSON format.")

        log_entries = log_entries[::-1]  # Newest first

        new_logs = []
        latest_ts = None
        for entry in log_entries:
            try:
                status_code = int(entry.get("status_code", 0))
                entry_time = datetime.fromisoformat(entry.get("timestamp"))
                if 200 <= status_code < 600 and entry_time > since_dt:
                    new_logs.append(entry)
                    if latest_ts is None or entry_time > latest_ts:
                        latest_ts = entry_time
            except Exception:
                continue

        return HTTPResponse().success(
            response_data={
                "logs": new_logs,
                "latest_timestamp": latest_ts.isoformat() if latest_ts else None,
            }
        )

    except Exception as e:
        return HTTPResponse().failed(response_message=f"Failed to poll logs: {str(e)}")


@router.get("/generate-dsn/{project_id}")
def generate_dsn(
    project_id: str, user_info: str = Depends(USER_LOGIN.authenticate_token)
):
    """
    Generate a DSN (Data Source Name) for the given project ID and user info.
    If DSN already exists, return it without generating a new one.
    """
    try:
        _, user_info_data = user_info
        user_id = user_info_data["user_id"]

        # Load the JSON file
        project_data = read_data("projects.json")

        if not project_data:
            return HTTPResponse().failed("projects file not found.")

        user_projects = (
            project_data.get("users", {}).get(user_id, {}).get("projects", [])
        )

        # Find the project
        for project in user_projects:
            if project.get("project_id") == project_id:
                # If DSN already exists, return it
                if "dsn" in project:
                    return HTTPResponse().success(
                        response_data=project["dsn"],
                        response_message="DSN already exists for this project.",
                    )

                # Otherwise, generate and assign a new DSN
                dsn = create_dsn(user_id, project_id)
                project["dsn"] = dsn

                # Save the updated JSON
                write_data(project_data, "projects.json")

                return HTTPResponse().success(
                    response_data=dsn, response_message="DSN successfully generated."
                )

        return HTTPResponse().failed(f"Project ID {project_id} not found for user.")

    except Exception as e:
        return HTTPResponse().failed(
            response_message=f"Failed to generate DSN: {str(e)}"
        )
