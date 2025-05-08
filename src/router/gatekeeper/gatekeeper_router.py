from fastapi import APIRouter, Body, HTTPException, Depends
from pathlib import Path
import json

from shared.user_utils import UserLoginHandler
from shared.http_responses import HTTPResponse

router = APIRouter()

LOCAL_DIR = Path("../health_data")
LOCAL_DIR.mkdir(parents=True, exist_ok=True)  # Create the folder if it doesn't exist

USER_LOGIN = UserLoginHandler()


@router.post("/upload/send-api-health-data")
async def receive_health_data(payload: dict = Body(...)):
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
async def get_health_data(
    project_id: str, user_info: str = Depends(USER_LOGIN.authenticate_token)
):
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