from fastapi import Depends, APIRouter, HTTPException
from uuid import uuid4
from shared.database import read_data, write_data
from shared.user_utils import UserLoginHandler
from router.beacon.model import Project
from router.gatekeeper.gatekeeper_router import LOCAL_DIR
from shared.http_responses import HTTPResponse
import json

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
    Get all projects for the authenticated user.
    """
    try:
        _, user_info_data = user_info
        user_id = user_info_data["user_id"]
        data = read_data(DATA_FILE)
        projects = data["users"].get(user_id, {}).get("projects", [])
        client_name = "AgentMira"

        project_details = []

        for project in projects:
            project_id = project.get("project_id")
            file_path = LOCAL_DIR / "api_endpoint" / user_id / f"{project_id}.json"

            framework = ""
            average_response_time = "0 seconds"
            api_count = 0

            if file_path.exists():
                try:
                    project_data = read_data(file_path)
                    apis = project_data.get("endpoints", [])
                    if apis:
                        total_response_time = sum(
                            api.get("response_time", 0) for api in apis
                        )
                        api_count = len(apis)
                        framework = apis[-1].get("framework", "FastApi")
                        average_response_time = (
                            f"{round(total_response_time / api_count, 4)} seconds"
                        )
                except Exception:
                    pass

            project_details.append(
                {
                    "projectName": project.get("name"),
                    "projectPath": project.get("url"),
                    "description": project.get("description"),
                    "projectID": project_id,
                    "framework": framework,
                    "averageResponseTime": average_response_time,
                    "apiCount": api_count,
                }
            )

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
                project.update(request.dict())
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


@router.get("/count/{project_id}")
def get_status_code_summary(
    project_id: str, user_info: str = Depends(USER_LOGIN.authenticate_token)
):
    """
    Returns counts and URLs of 2xx, 4xx, 5xx status codes for authenticated user.
    """
    try:
        _, user_info_data = user_info
        user_id = user_info_data["user_id"]

        summary = {
            "2xx": {"count": 0, "projectUrl": []},
            "4xx": {"count": 0, "projectUrl": []},
            "5xx": {"count": 0, "projectUrl": []},
        }

        file_path = LOCAL_DIR / "api_log" / user_id / f"{project_id}.json"
        if not file_path.exists():
            return HTTPResponse().failed(response_message="Log file not found.")

        with open(file_path, "r") as f:
            try:
                log_entries = json.load(f)
            except json.JSONDecodeError as e:
                return HTTPResponse().failed(response_message="Invalid JSON format.")

        for entry in log_entries:
            try:
                status_code = int(entry.get("status_code", 0))
                full_url = entry.get("full_url", "N/A")

                if 200 <= status_code < 300:
                    summary["2xx"]["count"] += 1
                    summary["2xx"]["projectUrl"].append(full_url)
                elif 400 <= status_code < 500:
                    summary["4xx"]["count"] += 1
                    summary["4xx"]["projectUrl"].append(full_url)
                elif 500 <= status_code < 600:
                    summary["5xx"]["count"] += 1
                    summary["5xx"]["projectUrl"].append(full_url)

            except Exception:
                continue  # Skip problematic entries

        return HTTPResponse().success(response_data=summary)

    except Exception as e:
        return HTTPResponse().failed(
            response_message=f"Failed to summarize logs: {str(e)}"
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

        with open(file_path, "r") as f:
            try:
                log_entries = json.load(f)
            except json.JSONDecodeError:
                return HTTPResponse().failed(response_message="Invalid JSON format.")

        filtered_logs = []
        for entry in log_entries:
            try:
                status_code = int(entry.get("status_code", 0))
                if 400 <= status_code < 600:
                    filtered_logs.append(entry)
            except Exception:
                continue  # Skip problematic entries

        return HTTPResponse().success(response_data=filtered_logs)

    except Exception as e:
        return HTTPResponse().failed(
            response_message=f"Failed to retrieve 4xx logs: {str(e)}"
        )
