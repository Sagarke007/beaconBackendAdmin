

from fastapi import APIRouter, Body, HTTPException, Depends
from pathlib import Path
import json

from shared.user_utils import UserLoginHandler

from shared.http_responses import HTTPResponse

from shared.user_client_project import UserClientProjectManager

router = APIRouter()

LOCAL_DIR = Path("../health_data")

LOCAL_DIR.mkdir(parents=True, exist_ok=True)  # Create the folder if it doesn't exist


import os
import json
from fastapi import APIRouter, Body, HTTPException

router = APIRouter()

USER_LOGIN = UserLoginHandler()
# Initialize manager
manager = UserClientProjectManager()

@router.post("/upload/send-api-health-data")
async def receive_health_data(payload: dict = Body(...),):
    """
    Receive health data from the API and save it into client_id folder as project_id.json
    """

    client_id = payload.get("client_id")
    project_id = payload.get("project_id")

    if not client_id or not project_id:
        return HTTPResponse().failed(response_message="client_id or project_id missing")

    client_dir = LOCAL_DIR / client_id

    client_dir.mkdir(parents=True, exist_ok=True)

    file_path = client_dir / f"{project_id}.json"

    try:
        with open(file_path, "w") as f:
            json.dump(payload, f, indent=2)

        return HTTPResponse().success(response_message=f"File saved to {file_path}")
    except Exception as e:
        return HTTPResponse().failed(response_message=f"Failed to save file: {str(e)}")


@router.get("/retrieve-file/{project_id}")
async def get_health_data(project_id: str,user_info: str = Depends(USER_LOGIN.authenticate_token),):
    """
    Retrieve health data stored inside client_id/project_id.json
    """
    try:
        _, user_info_data = user_info
        user_id = user_info_data["user_id"]
        file_path = LOCAL_DIR / user_id / f"{project_id}.json"
        if not file_path.exists():
            return HTTPResponse().failed(
                response_message={
                    "message": "Health data not found for the given project and client"
                }
            )

        with open(file_path, "r") as f:
            data = json.load(f)
        endpoints = data.get("endpoints", {})

        return HTTPResponse().success(response_data=endpoints)
    except Exception as e:
        return HTTPResponse().failed(response_message=f"Failed to retrieve health data: {str(e)}")

@router.get("/user-client-projects/")
async def get_user_client_projects(
        user_info: tuple = Depends(USER_LOGIN.authenticate_token)
):
    """
    Get the client and projects associated with the authenticated user

    Returns:
        dict: {
            "success": bool,
            "message": str,
            "data": {
                "client_id": str,
                "project_ids": List[str]
            }
        }
    """
    try:
        # Extract user_id from the authenticated token
        _, user_info = user_info

        user_id = user_info.get("user_id")
        if not user_id:
            return HTTPResponse.failed(response_message="User ID not found in token")

        # Get the client and projects for this user
        client_name = manager.get_client_for_user(user_id)
        project_ids = manager.get_projects_for_user(user_id)

        return HTTPResponse().success(response_data= {
                "client_name": client_name,
                "project_ids": project_ids
            }
        )

    except Exception as e:
        return HTTPResponse().failed(
            response_message=f"Failed to retrieve client and projects: {str(e)}"
        )